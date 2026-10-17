// The post-backup hook: the one moment an operator gets to plug their own
// tool into the backup pipeline.
//
// The verdict behind the shape is documented in docs/backup.md: restic, rsync
// and borg are CONSUMERS of a sealed snapshot directory, not a storage engine
// we reimplement a Target over. A sealed snapshot is a finished, checksummed,
// immutable artifact; the useful integration is "carry this artifact
// elsewhere", and that is what runs a shell command with the snapshot named in
// the environment.
package backup

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/syncbox/server/internal/backup/target"
)

// hookOutputLimit bounds how much of a hook's output the log keeps: enough to
// explain a restic summary or an rsync failure, bounded so a chatty script
// cannot grow the server log forever.
const hookOutputLimit = 8 << 10

// PostCommand returns a Manager hook that runs command through the shell after
// each sealed snapshot. The command sees the snapshot named in
// SYNCBOX_SNAPSHOT_ID, SYNCBOX_SNAPSHOT_REL (its path inside the target),
// SYNCBOX_SNAPSHOT_CREATED_AT, and SYNCBOX_BACKUP_TARGET (the target's
// Location, directory or s3:// URL alike); on a local target it also gets
// SYNCBOX_SNAPSHOT_PATH, the absolute directory restic or rsync can read
// directly.
//
// The returned hook itself never blocks: the command runs in its own goroutine
// on a context detached from the caller's with the given timeout. Both halves
// matter — an admin-API client hanging up must not kill a mid-flight copy, and
// the scheduler must not queue behind one. The command's outcome is logged and
// deliberately never changes the backup's outcome: a snapshot that exists and
// sealed cleanly is not a failed backup because one copy step tripped, and
// reporting it as one would hide a good snapshot from the operator's eye.
func PostCommand(tgt target.Target, command string, timeout time.Duration) func(context.Context, Snapshot) {
	root, local := tgt.(*target.Local)
	return func(ctx context.Context, snapshot Snapshot) {
		env := append(os.Environ(),
			"SYNCBOX_SNAPSHOT_ID="+snapshot.ID,
			"SYNCBOX_SNAPSHOT_REL="+snapshotRel(snapshot.ID),
			"SYNCBOX_SNAPSHOT_CREATED_AT="+snapshot.CreatedAt.UTC().Format(time.RFC3339),
			"SYNCBOX_BACKUP_TARGET="+tgt.Location(),
		)
		if local {
			env = append(env, "SYNCBOX_SNAPSHOT_PATH="+filepath.Join(root.Location(), snapshotRel(snapshot.ID)))
		}
		go func() {
			runCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
			defer cancel()
			cmd := exec.CommandContext(runCtx, "/bin/sh", "-c", command)
			cmd.Env = env
			var out cappedWriter
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Run(); err != nil {
				log.Printf("post-backup hook for %s failed: %v: %s", snapshot.ID, err, out.String())
				return
			}
			log.Printf("post-backup hook for %s completed: %s", snapshot.ID, out.String())
		}()
	}
}

// cappedWriter keeps the first hookOutputLimit bytes written to it and
// swallows the rest without making the child process notice.
type cappedWriter struct {
	buf  bytes.Buffer
	trim bool
}

func (w *cappedWriter) Write(p []byte) (int, error) {
	if room := hookOutputLimit - w.buf.Len(); room > 0 {
		if len(p) > room {
			w.buf.Write(p[:room])
			w.trim = true
		} else {
			w.buf.Write(p)
		}
	} else {
		w.trim = true
	}
	return len(p), nil
}

func (w *cappedWriter) String() string {
	out := strings.TrimSpace(w.buf.String())
	if w.trim {
		out += " […]"
	}
	return out
}
