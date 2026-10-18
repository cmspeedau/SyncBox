package credential

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoredPasswordSealsAndVerifies(t *testing.T) {
	encoded, err := hash("a-long-enough-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	// The sealed string must never contain the password it protects.
	if strings.Contains(encoded, "a-long-enough-secret") {
		t.Error("the hash leaks the password")
	}
	ok, err := verify(encoded, "a-long-enough-secret")
	if err != nil || !ok {
		t.Fatalf("verify(good) = %v, %v; want true, nil", ok, err)
	}
	ok, err = verify(encoded, "the wrong password")
	if err != nil || ok {
		t.Fatalf("verify(bad) = %v, %v; want false, nil", ok, err)
	}
}

func TestAnUninitializedAuthorityAdmitsNoOne(t *testing.T) {
	a, err := NewAuthority("", "")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	if a.Initialized() {
		t.Error("a bare authority reports itself initialized")
	}
	if a.Verify("anything") {
		t.Error("an uninitialized authority let a guess through")
	}
}

func TestSetupPersistsAndSurvivesAReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")

	a, err := NewAuthority(path, "")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	if a.Initialized() {
		t.Fatal("a fresh data directory reports itself initialized")
	}
	if err := a.Setup("first-run-secret"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !a.Initialized() {
		t.Fatal("after setup the authority is still uninitialized")
	}

	// The credential is on disk, owner-only, and never in the clear.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("the password file is missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("password file mode = %o, want 600", perm)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "first-run-secret") {
		t.Error("the password file stores the password in the clear")
	}

	// A brand-new authority over the same directory verifies against what the
	// first one wrote — that is what surviving a restart means.
	reloaded, err := NewAuthority(path, "")
	if err != nil {
		t.Fatalf("NewAuthority after restart: %v", err)
	}
	if !reloaded.Initialized() {
		t.Fatal("a stored password did not survive the reload")
	}
	if !reloaded.Verify("first-run-secret") {
		t.Error("the reloaded authority refused the real password")
	}
	if reloaded.Verify("nope") {
		t.Error("the reloaded authority admitted a wrong password")
	}
}

func TestSetupIsWeakOrOnce(t *testing.T) {
	a, _ := NewAuthority("", "")

	if err := a.Setup("short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("Setup(short) = %v, want ErrWeakPassword", err)
	}
	if err := a.Setup("long-enough-now"); err != nil {
		t.Fatalf("Setup(good): %v", err)
	}
	if err := a.Setup("another-secret"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("second Setup = %v, want ErrAlreadyInitialized", err)
	}
}

func TestEnvironmentPasswordWinsAndRefusesSetup(t *testing.T) {
	// An env password outranks any stored file, and there is nothing to set up.
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("garbage\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	a, err := NewAuthority(path, "the-env-password")
	if err != nil {
		t.Fatalf("NewAuthority with an env password should ignore a bad file, got: %v", err)
	}
	if !a.Verify("the-env-password") {
		t.Error("the env password did not sign in")
	}
	if a.Verify("anything") {
		t.Error("a wrong guess signed in against the env password")
	}
	if err := a.Setup("ignored"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Errorf("Setup under an env password = %v, want ErrAlreadyInitialized", err)
	}
}

func TestACorruptStoredPasswordRefusesToBoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	if err := os.WriteFile(path, []byte("not-an-argon2-hash\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := NewAuthority(path, ""); err == nil {
		t.Fatal("a corrupt password file was accepted; it must be a hard error")
	}
}

func TestChangeRotatesAStoredPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	a, err := NewAuthority(path, "")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	if err := a.Setup("first-secret"); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	// A wrong current password is refused and leaves the old one working.
	if err := a.Change("nope", "brand-new-secret"); !errors.Is(err, ErrWrongPassword) {
		t.Fatalf("Change(wrong current) = %v, want ErrWrongPassword", err)
	}
	if !a.Verify("first-secret") {
		t.Fatal("a refused change altered the password")
	}

	// A too-short new password is refused, again leaving the old one in place.
	if err := a.Change("first-secret", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("Change(short new) = %v, want ErrWeakPassword", err)
	}
	if !a.Verify("first-secret") {
		t.Fatal("a refused change altered the password")
	}

	// The real rotation: the old stops working, the new works, across a reload.
	if err := a.Change("first-secret", "brand-new-secret"); err != nil {
		t.Fatalf("Change: %v", err)
	}
	if a.Verify("first-secret") {
		t.Error("the old password still signs in after a change")
	}
	if !a.Verify("brand-new-secret") {
		t.Error("the new password does not sign in")
	}

	reloaded, err := NewAuthority(path, "")
	if err != nil {
		t.Fatalf("NewAuthority after change: %v", err)
	}
	if reloaded.Verify("first-secret") {
		t.Error("the old password survived a restart")
	}
	if !reloaded.Verify("brand-new-secret") {
		t.Error("the new password did not survive a restart")
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "brand-new-secret") {
		t.Error("the password file leaked the new password in the clear")
	}
}

func TestSourceNamesTheAuthority(t *testing.T) {
	none, _ := NewAuthority("", "")
	if got := none.Source(); got != "unset" {
		t.Errorf("uninitialized Source = %q, want unset", got)
	}

	env, _ := NewAuthority("", "the-env-password")
	if got := env.Source(); got != "environment" {
		t.Errorf("env Source = %q, want environment", got)
	}

	dir := t.TempDir()
	stored, _ := NewAuthority(filepath.Join(dir, "password"), "")
	if got := stored.Source(); got != "unset" {
		t.Errorf("fresh-dir Source = %q, want unset before setup", got)
	}
	if err := stored.Setup("a-long-enough-secret"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if got := stored.Source(); got != "stored" {
		t.Errorf("after setup Source = %q, want stored", got)
	}
}

func TestChangeRefusesEnvAndUninitialized(t *testing.T) {
	env, _ := NewAuthority("", "the-env-password")
	if err := env.Change("the-env-password", "something-else-12"); !errors.Is(err, ErrEnvPassword) {
		t.Errorf("Change under an env password = %v, want ErrEnvPassword", err)
	}
	none, _ := NewAuthority("", "")
	if err := none.Change("whatever", "something-else-12"); !errors.Is(err, ErrNotInitialized) {
		t.Errorf("Change uninitialized = %v, want ErrNotInitialized", err)
	}
}

func TestChangedAtReflectsTheStoredFileMtime(t *testing.T) {
	none, _ := NewAuthority("", "")
	if !none.ChangedAt().IsZero() {
		t.Error("an uninitialized authority reports a change time")
	}

	// An environment password owns no timestamp, even with a stored file on disk:
	// the server did not write it and cannot date it.
	dir := t.TempDir()
	path := filepath.Join(dir, "password")
	env, _ := NewAuthority(path, "the-env-password")
	if !env.ChangedAt().IsZero() {
		t.Error("an env authority reports a change time")
	}

	// An in-memory stored credential never wrote a file, so it has nothing to date.
	inMem, _ := NewAuthority("", "")
	if err := inMem.Setup("a-long-enough-secret"); err != nil {
		t.Fatalf("in-memory Setup: %v", err)
	}
	if !inMem.ChangedAt().IsZero() {
		t.Error("an in-memory stored authority reports a change time it cannot have")
	}

	// A real stored credential reports the password file's own mtime: fresh setup
	// reads as "moments ago"...
	stored, _ := NewAuthority(path, "")
	if err := stored.Setup("a-long-enough-secret"); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	changed := stored.ChangedAt()
	if changed.IsZero() {
		t.Fatal("a stored credential reports no change time")
	}
	if delta := time.Since(changed); delta < -time.Minute || delta > time.Minute {
		t.Errorf("just-set ChangedAt is %v from now, want within a minute", delta)
	}

	// ...and the value is genuinely the one on disk: plant an instant, reload, and
	// it comes back — the durable counterpart to Source's "stored".
	pinned := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	if err := os.Chtimes(path, pinned, pinned); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	reloaded, err := NewAuthority(path, "")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := reloaded.ChangedAt(); got.Unix() != pinned.Unix() {
		t.Errorf("reloaded ChangedAt = %v (unix %d), want unix %d", got, got.Unix(), pinned.Unix())
	}
}
