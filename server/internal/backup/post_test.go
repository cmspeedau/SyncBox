// The post-backup hook tested with real shells against real snapshots: the
// seam exists for restic and rsync, so pretending with a fake command would
// test everything except the part that matters.
package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitFor polls read until it succeeds or the budget runs out. The detached
// hook goroutine is the point, so Create returns before the hook lands — the
// test has to wait for the artifact instead.
func waitFor(t *testing.T, path string) string {
	t.Helper()
	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if body, err := os.ReadFile(path); err == nil {
			return string(body)
		}
	}
	t.Fatalf("hook never wrote %s", path)
	return ""
}

func TestPostCommandSeesTheSealedSnapshot(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()

	out := filepath.Join(t.TempDir(), "hook.txt")
	tgt := mustTarget(t, filepath.Join(f.root, "target"))
	f.manager.SetPostHook(PostCommand(tgt,
		`printf '%s\n%s\n%s\n%s\n' "$SYNCBOX_SNAPSHOT_ID" "$SYNCBOX_SNAPSHOT_REL" "$SYNCBOX_SNAPSHOT_PATH" "$SYNCBOX_BACKUP_TARGET" >"`+out+`"`,
		10*time.Second))

	snap, err := f.manager.Create(ctx, DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	lines := strings.Split(strings.TrimRight(waitFor(t, out), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("hook wrote %d lines:\n%s", len(lines), lines)
	}
	if lines[0] != snap.ID {
		t.Errorf("SYNCBOX_SNAPSHOT_ID = %q, want %q", lines[0], snap.ID)
	}
	if want := "snapshots/" + snap.ID; lines[1] != want {
		t.Errorf("SYNCBOX_SNAPSHOT_REL = %q, want %q", lines[1], want)
	}
	// The path a restic backup of the sealed bundle would point at must exist.
	if info, err := os.Stat(lines[2]); err != nil || !info.IsDir() {
		t.Errorf("SYNCBOX_SNAPSHOT_PATH = %q is not a directory: %v", lines[2], err)
	}
	if lines[3] != tgt.Location() {
		t.Errorf("SYNCBOX_BACKUP_TARGET = %q, want %q", lines[3], tgt.Location())
	}
}

func TestPostCommandFailureNeverFailsTheBackup(t *testing.T) {
	// The snapshot is committed when the seal lands. A tripping copy step is
	// the hook's news, not a reason to hide a good snapshot from the operator.
	f := newFixture(t)
	f.seed(t)

	f.manager.SetPostHook(PostCommand(mustTarget(t, filepath.Join(f.root, "target")), "exit 3", 10*time.Second))
	snap, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create with a failing hook: %v", err)
	}
	if snap.ID == "" {
		t.Error("snapshot lost behind its hook failure")
	}
}

func TestPostCommandDoesNotBlockCreate(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	f.manager.SetPostHook(PostCommand(mustTarget(t, filepath.Join(f.root, "target")), "sleep 5", 250*time.Millisecond))
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		if _, err := f.manager.Create(context.Background(), DefaultPolicy()); err != nil {
			t.Errorf("Create: %v", err)
		}
		done <- time.Since(start)
	}()
	select {
	case elapsed := <-done:
		if elapsed > 2*time.Second {
			t.Errorf("Create waited %s behind a hook that was told to run detached", elapsed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Create never returned")
	}
}

func TestCappedWriterBoundsAndMarks(t *testing.T) {
	var w cappedWriter
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 8; i++ { // 32 KiB into an 8 KiB cap
		if n, err := w.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write lied: %d %v", n, err)
		}
	}
	summary := w.String()
	if !strings.HasSuffix(summary, "[…]") {
		t.Error("a trimmed capture must say so")
	}
	if len(summary) > hookOutputLimit+len(" […]") {
		t.Errorf("captured %d bytes past the %d-byte cap", len(summary), hookOutputLimit)
	}
}
