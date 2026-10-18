package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/credential"
	"github.com/syncbox/server/internal/store"
)

// Change-password is the door for every password after the first, so these
// exercise it as a lock the owner controls: you must hold a token AND know the
// current password, a rejected attempt must not disturb your session, and a
// successful one must take effect immediately and durably.

// newStoredClient is a server whose password lives in a temp data dir and starts
// uninitialized — the state a first run leaves behind — so a rotation has
// something real to rotate and can survive a reload.
func newStoredClient(t *testing.T) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	creds, err := credential.NewAuthority(filepath.Join(t.TempDir(), "password"), "")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}
	server := httptest.NewServer(NewWithAuthority(stored, nil, issuer, creds).Routes())
	t.Cleanup(server.Close)
	return &client{t: t, server: server}
}

// change POSTs a rotation with an explicit bearer token and returns the status
// and error code.
func (c *client) change(current, next, token string) (int, string) {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"current": current, "password": next})
	response := c.raw(http.MethodPost, "/api/v1/auth/password", body, token)
	code := response.StatusCode
	if code >= http.StatusBadRequest {
		errCode, _ := c.errorBodyOf(response)
		return code, errCode
	}
	response.Body.Close()
	return code, ""
}

// tokenStatus is a bare token exchange that reports rather than fataling, so a
// test can assert an old password is now refused.
func (c *client) tokenStatus(password string) int {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	response := c.raw(http.MethodPost, "/api/v1/auth/token", body, "")
	defer response.Body.Close()
	return response.StatusCode
}

func TestChangePasswordRotatesAStoredCredential(t *testing.T) {
	c := newStoredClient(t)

	// The route is authenticated: no token, no change.
	if code, _ := c.change("x", "long-enough-now", ""); code != http.StatusUnauthorized {
		t.Fatalf("change without a token = %d, want 401", code)
	}

	// First run, then sign in so we hold a token.
	if code, _ := c.setup("original-secret"); code != http.StatusCreated {
		t.Fatalf("setup = %d, want 201", code)
	}
	c.token = c.loginWith("original-secret")

	// The right token but the wrong current password is refused — and the
	// session is left alone, so a fumble never logs the owner out.
	if code, errCode := c.change("not-the-password", "brand-new-secret", c.token); code != http.StatusForbidden || errCode != "password_mismatch" {
		t.Fatalf("wrong current = %d %q, want 403 password_mismatch", code, errCode)
	}
	if probe := c.raw(http.MethodGet, "/admin/vaults", nil, c.token); probe.StatusCode != http.StatusOK {
		probe.Body.Close()
		t.Fatal("a rejected change should not have ended the session")
	} else {
		probe.Body.Close()
	}

	// A too-short new password is refused before anything is written.
	if code, errCode := c.change("original-secret", "short", c.token); code != http.StatusBadRequest || errCode != "weak_password" {
		t.Fatalf("short new = %d %q, want 400 weak_password", code, errCode)
	}

	// The real rotation takes effect at once: the old password stops working and
	// the new one signs in.
	if code, _ := c.change("original-secret", "brand-new-secret", c.token); code != http.StatusOK {
		t.Fatalf("good change = %d, want 200", code)
	}
	if got := c.tokenStatus("original-secret"); got != http.StatusUnauthorized {
		t.Errorf("the old password still yields a token (%d), want 401", got)
	}
	if c.loginWith("brand-new-secret") == "" {
		t.Fatal("the new password does not sign in")
	}
}

func TestEnvPasswordCannotBeRotatedOverTheAPI(t *testing.T) {
	c := newClient(t, false) // env: testPassword, already signed in

	// SYNCBOX_PASSWORD is the source of truth; changing it here would vanish on
	// restart, so the honest answer is a refusal that says where to change it.
	if code, errCode := c.change(testPassword, "another-secret-here", c.token); code != http.StatusForbidden || errCode != "env_password" {
		t.Errorf("change under an env password = %d %q, want 403 env_password", code, errCode)
	}
}
