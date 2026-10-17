// Command syncboxd is the Syncbox server.
//
// It serves the API, and it is also the backup tool, because the two need the same
// understanding of the on-disk layout. Subcommands:
//
//	serve     run the API server
//	backup    ask a running server to take a snapshot now
//	restore   write a snapshot out into a directory, offline
//	version   print the version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/syncbox/server/internal/api"
	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/backup"
	"github.com/syncbox/server/internal/backup/target"
	"github.com/syncbox/server/internal/config"
	"github.com/syncbox/server/internal/store"
)

// version is stamped by the build.
const version = "0.1.0"

const usageText = `syncboxd - the Syncbox server

Usage:
  syncboxd serve     [-addr host:port]
  syncboxd backup    [-url URL] [-token TOKEN]
  syncboxd restore   -snapshot ID -target DIR|s3://BUCKET[/PREFIX] -to DIR
  syncboxd version

Configuration is read from the environment. Run "syncboxd serve -h" for the
flags, and see docs/backup.md for the snapshot layout.
`

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		log.Printf("syncboxd: %v", err)
		os.Exit(1)
	}
}

// run dispatches one subcommand and returns the error the process should report.
func run(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, usageText)
		return errors.New("no command given")
	}

	switch args[0] {
	case "serve":
		return serve(args[1:], stdout)
	case "backup":
		return backupCommand(args[1:], stdout)
	case "restore":
		return restoreCommand(args[1:], stdout)
	case "version":
		fmt.Fprintf(stdout, "syncboxd %s\n", version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return nil
	default:
		fmt.Fprint(stdout, usageText)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// serve runs the API until the process is asked to stop, then drains.
func serve(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("serve", flag.ContinueOnError)
	set.SetOutput(stdout)
	addr := set.String("addr", "", "address to listen on, overriding SYNCBOX_LISTEN_ADDR")
	if err := set.Parse(args); err != nil {
		return fmt.Errorf("parsing serve flags: %w", err)
	}

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	if *addr != "" {
		cfg.ListenAddr = *addr
	}
	for _, warning := range cfg.Warnings() {
		log.Printf("warning: %s", warning)
	}

	st, err := store.Open(cfg.DataDir, cfg.MaxChunkBytes)
	if err != nil {
		return err
	}
	defer st.Close()
	log.Printf("data directory %s", cfg.DataDir)

	var backups *backup.Manager
	if cfg.BackupTarget != "" {
		tgt, err := openBackupTarget(cfg.BackupTarget, cfg)
		if err != nil {
			return err
		}
		backups = backup.NewManager(tgt, st, version)
		log.Printf("snapshots go to %s", tgt.Location())
		if cfg.BackupPost != "" {
			backups.SetPostHook(backup.PostCommand(tgt, cfg.BackupPost, backupPostTimeout))
			log.Printf("after sealing, each snapshot runs: %s", cfg.BackupPost)
		}
	}

	issuer := auth.NewIssuer(cfg.TokenSecret, cfg.TokenTTL)
	srv := api.New(st, backups, issuer, cfg.Password)
	srv.SetVersion(version)
	if cfg.RatePerSecond > 0 {
		srv.SetRateLimit(cfg.RatePerSecond, cfg.RateBurst)
		log.Printf("throttling each address to %.1f requests/s (burst %d)", cfg.RatePerSecond, cfg.RateBurst)
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      2 * time.Minute,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if backups != nil && cfg.BackupSchedule > 0 {
		go snapshotEvery(ctx, backups, cfg.BackupSchedule)
		log.Printf("snapshotting every %s", cfg.BackupSchedule)
	}

	errs := make(chan error, 1)
	go func() {
		log.Printf("listening on http://%s", cfg.ListenAddr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("listening on %s: %w", cfg.ListenAddr, err)
		}
	}()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		log.Printf("shutting down")
	}

	// A fresh context: the signal context is already cancelled, so reusing it
	// would give in-flight requests no time at all.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown did not finish cleanly: %w", err)
	}
	return nil
}

// snapshotEvery takes a snapshot on a timer and retires the ones the retention
// policy has aged out.
//
// Errors are logged rather than returned: a backup that fails once should not take
// the server down with it, and the next tick tries again.
func snapshotEvery(ctx context.Context, manager *backup.Manager, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		policy := backup.DefaultPolicy()
		snapshot, err := manager.Create(ctx, policy)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("scheduled snapshot failed: %v", err)
			continue
		}
		log.Printf("snapshot %s taken with %d chunks", snapshot.ID, len(snapshot.Manifest.Chunks))

		kept, dropped, err := manager.Prune(ctx, policy)
		if err != nil {
			log.Printf("retiring old snapshots failed: %v", err)
			continue
		}
		if len(dropped) > 0 {
			log.Printf("retired %d snapshots, %d remain", len(dropped), len(kept))
		}
	}
}

// backupCommand asks a running server to take a snapshot now.
//
// It is a client rather than a direct call because the store being snapshotted is
// the one the server holds. Cron can run this against a localhost socket, which is
// how a scheduled backup works without the CLI needing to open the data files.
func backupCommand(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("backup", flag.ContinueOnError)
	set.SetOutput(stdout)
	url := set.String("url", "http://127.0.0.1:8080", "server base URL")
	token := set.String("token", "", "bearer token, or set SYNCBOX_TOKEN")
	if err := set.Parse(args); err != nil {
		return fmt.Errorf("parsing backup flags: %w", err)
	}
	if *token == "" {
		*token = os.Getenv("SYNCBOX_TOKEN")
	}
	if *token == "" {
		return errors.New("a token is required: pass -token or set SYNCBOX_TOKEN")
	}

	endpoint := trimTrailingSlash(*url) + "/admin/backups"
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+*token)

	client := &http.Client{Timeout: 2 * time.Minute}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("asking %s for a snapshot: %w", endpoint, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("reading the reply from %s: %w", endpoint, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("server refused the backup (%s): %s", response.Status, strings.TrimSpace(string(body)))
	}

	// Re-marshalling keeps the output readable even though the server's body is
	// already JSON, and proves the reply parsed.
	var pretty map[string]any
	if err := json.Unmarshal(body, &pretty); err != nil {
		fmt.Fprintf(stdout, "%s\n", strings.TrimSpace(string(body)))
		return nil
	}
	encoded, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		return fmt.Errorf("decoding the reply: %w", err)
	}
	fmt.Fprintf(stdout, "%s\n", encoded)
	return nil
}

// backupPostTimeout bounds one run of the SYNCBOX_BACKUP_POST command. Generous
// because it is sized for restic over a home uplink, not for a local copy.
const backupPostTimeout = 30 * time.Minute

// openBackupTarget builds the target the backup location names: an
// "s3://bucket[/prefix]" URL selects object storage — endpoint, region and
// credentials come from the environment like every other setting — and
// anything else is a local directory.
func openBackupTarget(location string, cfg config.Config) (target.Target, error) {
	if rest, ok := strings.CutPrefix(location, "s3://"); ok {
		bucket, prefix, _ := strings.Cut(rest, "/")
		return target.NewS3(target.S3Config{
			Bucket:    bucket,
			Prefix:    prefix,
			Region:    cfg.S3Region,
			Endpoint:  cfg.S3Endpoint,
			AccessKey: cfg.S3AccessKey,
			SecretKey: cfg.S3SecretKey,
			LockDays:  cfg.BackupLockDays,
		})
	}
	return target.NewLocal(location)
}

// restoreCommand writes a snapshot into a directory, without a running server.
func restoreCommand(args []string, stdout io.Writer) error {
	set := flag.NewFlagSet("restore", flag.ContinueOnError)
	set.SetOutput(stdout)
	snapshotID := set.String("snapshot", "", "snapshot id to restore")
	targetDir := set.String("target", "", "directory or s3://bucket[/prefix] the snapshots live in")
	dest := set.String("to", "", "directory to restore into")
	if err := set.Parse(args); err != nil {
		return fmt.Errorf("parsing restore flags: %w", err)
	}
	if *snapshotID == "" || *targetDir == "" || *dest == "" {
		fmt.Fprint(stdout, usageText)
		return errors.New("restore needs -snapshot, -target, and -to")
	}

	// An s3:// target takes its endpoint and credentials from the environment,
	// which is the only place they can come from without a running server.
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	tgt, err := openBackupTarget(*targetDir, cfg)
	if err != nil {
		return err
	}
	// Restore reads from the snapshot target only, so the source side of the
	// manager is nil. It writes the server's own data-dir layout (metadata.json +
	// chunks/) into -to; the next `serve` with SYNCBOX_DATA_DIR pointed there
	// imports it into SQLite on open. There is no separate load step to pretend at.
	manager := backup.NewManager(tgt, nil, version)

	manifest, err := manager.Restore(context.Background(), *snapshotID, *dest)
	if err != nil {
		return err
	}
	pinned := ""
	if manifest.Pinned() {
		pinned = ", read pinned to the sealed versions"
	}
	fmt.Fprintf(stdout, "restored %s (%d chunks, %d bytes%s) into %s\n",
		manifest.ID, len(manifest.Chunks), manifest.ChunkBytes, pinned, *dest)
	return nil
}

// trimTrailingSlash removes a trailing "/" so paths concatenate cleanly.
func trimTrailingSlash(raw string) string {
	for len(raw) > 1 && raw[len(raw)-1] == '/' {
		raw = raw[:len(raw)-1]
	}
	return raw
}
