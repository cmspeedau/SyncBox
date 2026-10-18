// Package credential owns the single server password: how it is stored, how a
// guess is checked, and the one-time first-run setup that gives a fresh server
// its first credential.
//
// There are three authorities, and exactly one is in force at a time:
//
//   - env: the operator set SYNCBOX_PASSWORD. It is compared as typed, as it
//     always has been — a long random secret with TLS as the real boundary — and
//     first-run setup is refused, because there is nothing to set up.
//   - stored: no env password, but a previous first run left an Argon2id hash in
//     the data directory. A guess is verified against that hash, so the chosen
//     password — which is often a human phrase, not a random secret — never sits
//     on disk in the clear.
//   - uninitialized: neither, so nothing can sign in yet. The server stays
//     unusable until someone calls Setup exactly once.
//
// Setup is the only way out of uninitialized. It is deliberately reachable with
// no credential — that is the whole point of a first run — but it is good once and
// then refuses forever after, and a deployment that reaches for the network
// before finishing it should have set SYNCBOX_PASSWORD instead (see server README).
package credential

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// The password is verified once per login, not once per request, so the cost is
// paid by whoever is signing in — and the login route is IP rate-limited like
// every other route. These are the RFC 9106 recommendations for Argon2id, the
// first (memory-hard) set: 64 MiB, three passes, four lanes, a 32-byte key.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // KiB
	argonThreads = 4
	keyLen       = 32
	saltLen      = 16

	// MinPasswordLength is the server-side floor for a first-run password. The
	// console checks it too, but the server does not trust the client to.
	MinPasswordLength = 8
)

// Sentinel errors the API maps onto distinct codes, so a client can tell "this
// server already has a password" from "that password is too short" from a real
// failure.
var (
	ErrAlreadyInitialized = errors.New("the server already has a password")
	ErrWeakPassword       = fmt.Errorf("a first-run password must be at least %d characters", MinPasswordLength)
)

// mode is which authority is in force.
type mode int

const (
	modeUninitialized mode = iota
	modeEnv
	modeStored
)

// Authority answers "may this password sign in" and performs the one-time setup.
// It is safe for concurrent use: Setup takes the lock, re-checks the mode, writes
// durable before it flips to stored, so exactly one racing caller ever wins.
type Authority struct {
	mu   sync.Mutex
	path string // file in the data dir holding the stored hash; "" means in-memory only
	mode mode
	env  string // the env password, when mode == modeEnv
	key  string // the PHC-encoded Argon2id hash, when mode == modeStored
}

// NewAuthority decides the mode and, for a stored credential, loads it from path.
// envPassword non-empty always wins. An empty env password falls back to the file
// at path (when there is one), and to uninitialized otherwise. A path of "" makes
// a store that can still be set up once but keeps nothing across a restart — used
// by tests that only want to drive the state machine. A file that exists but will
// not parse is a hard error: a corrupt credential must not silently unlock the
// door for whoever boots the server next.
func NewAuthority(path, envPassword string) (*Authority, error) {
	if envPassword != "" {
		return &Authority{path: path, mode: modeEnv, env: envPassword}, nil
	}
	if path == "" {
		return &Authority{mode: modeUninitialized}, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Authority{path: path, mode: modeUninitialized}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading the stored password: %w", err)
	}
	encoded := strings.TrimSpace(string(raw))
	if encoded == "" {
		return nil, fmt.Errorf("the stored password at %s is empty", path)
	}
	if _, err := parse(encoded); err != nil {
		return nil, fmt.Errorf("the stored password at %s: %w", path, err)
	}
	return &Authority{path: path, mode: modeStored, key: encoded}, nil
}

// Initialized reports whether anything can sign in yet.
func (a *Authority) Initialized() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.mode != modeUninitialized
}

// Verify checks a guess against whichever credential is in force. An
// uninitialized authority can never say yes: there is no password to match.
func (a *Authority) Verify(guess string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch a.mode {
	case modeEnv:
		// Constant-time even for the env case: the secret is long and random, but
		// there is no reason to hand a timing signal away for free.
		return subtle.ConstantTimeCompare([]byte(guess), []byte(a.env)) == 1
	case modeStored:
		ok, err := verify(a.key, guess)
		return err == nil && ok
	default:
		return false
	}
}

// Setup gives an uninitialized server its first password: it is hashed with
// Argon2id, written durable, and only then does the authority flip to stored. It
// refuses when a credential already exists (env or stored) and refuses a password
// too short to be worth sealing.
func (a *Authority) Setup(password string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.mode != modeUninitialized {
		return ErrAlreadyInitialized
	}
	if len(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	encoded, err := hash(password)
	if err != nil {
		return err
	}
	if a.path != "" {
		if err := writeSecret(a.path, encoded); err != nil {
			return err
		}
	}
	a.key = encoded
	a.mode = modeStored
	return nil
}

// hash seals password with a fresh random salt and returns the self-describing
// PHC string, so Verify needs nothing but the string to re-derive the key.
func hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating a password salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// verify recomputes the key from the PHC string's own parameters and compares it
// to the stored one without leaking its length or contents on a mismatch.
func verify(encoded, password string) (bool, error) {
	p, err := parse(encoded)
	if err != nil {
		return false, err
	}
	key := argon2.IDKey([]byte(password), p.salt, p.time, p.memory, p.threads, uint32(len(p.key)))
	return subtle.ConstantTimeCompare(key, p.key) == 1, nil
}

// phc is a parsed Argon2id hash.
type phc struct {
	time    uint32
	memory  uint32
	threads uint8
	salt    []byte
	key     []byte
}

// parse reads the PHC string back. It is strict about the shape but takes the
// parameters from the string itself, so a hash written under older (or newer)
// parameters still verifies without a re-hash.
func parse(encoded string) (*phc, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=,t=,p=", "<salt>", "<key>" — six fields with a
	// leading empty piece from the initial "$".
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return nil, errors.New("not an argon2id hash")
	}
	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return nil, fmt.Errorf("unsupported argon2 version %q", parts[2])
	}
	p := &phc{}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return nil, fmt.Errorf("bad argon2 parameters %q: %w", parts[3], err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("bad salt: %w", err)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("bad key: %w", err)
	}
	if len(salt) == 0 || len(key) == 0 {
		return nil, errors.New("empty salt or key")
	}
	p.salt, p.key = salt, key
	return p, nil
}

// writeSecret writes body to path atomically and owner-read-write only. The
// password file is written into the same data directory the server already guards,
// and a half-written credential is worse than none, so it is staged and renamed.
func writeSecret(path, body string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".password-*")
	if err != nil {
		return fmt.Errorf("staging the password file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds
	if _, err := tmp.WriteString(body + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the password file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("setting the password file mode: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing the password file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("installing the password file: %w", err)
	}
	return nil
}
