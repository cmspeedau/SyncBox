package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/credential"
	"github.com/syncbox/server/internal/store"
)

// The first-run surfaces are tested end to end because what they promise is a
// contract about a credential that does not exist yet: the door is closed, exactly
// one caller may open it, and after that ordinary sign-in owns the door.

// newBareClient is a server whose credential authority is uninitialized and kept
// in memory (no data directory): it has no password and cannot persist a first
// run, which is all the HTTP surface needs to be exercised. Unlike newClient it
// returns an unauthenticated client, because there is nothing to log in with yet.
func newBareClient(t *testing.T) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	creds, err := credential.NewAuthority("", "")
	if err != nil {
		t.Fatalf("NewAuthority: %v", err)
	}

	server := httptest.NewServer(NewWithAuthority(stored, nil, issuer, creds).Routes())
	t.Cleanup(server.Close)
	return &client{t: t, server: server}
}

// status reads GET /api/v1/auth/status.
func (c *client) status() bool {
	c.t.Helper()
	response := c.raw(http.MethodGet, "/api/v1/auth/status", nil, "")
	var body struct {
		Initialized bool `json:"initialized"`
	}
	c.mustDecode(response, &body)
	return body.Initialized
}

// setup posts a first-run password and returns the status code and error code.
func (c *client) setup(password string) (int, string) {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	response := c.raw(http.MethodPost, "/api/v1/auth/setup", body, "")
	code := response.StatusCode
	if code >= http.StatusBadRequest {
		errCode, _ := c.errorBodyOf(response)
		return code, errCode
	}
	response.Body.Close()
	return code, ""
}

func TestFirstRunSetsThePasswordExactlyOnce(t *testing.T) {
	c := newBareClient(t)

	if c.status() {
		t.Fatal("a fresh server reports itself initialized")
	}

	// Nothing signs in before a password exists, and it says why.
	uninit := c.raw(http.MethodPost, "/api/v1/auth/token",
		[]byte(`{"password":"anything"}`), "")
	if uninit.StatusCode != http.StatusUnauthorized {
		t.Errorf("token before setup = %s, want 401", uninit.Status)
	}
	if code, _ := c.errorBodyOf(uninit); code != "uninitialized" {
		t.Errorf("token before setup code = %q, want uninitialized", code)
	}

	// A password below the floor is refused, and leaves the door closed.
	if code, errCode := c.setup("short"); code != http.StatusBadRequest || errCode != "weak_password" {
		t.Fatalf("weak setup = %d %q, want 400 weak_password", code, errCode)
	}
	if c.status() {
		t.Fatal("a refused setup left the server initialized")
	}

	const password = "a-long-enough-secret"
	if code, errCode := c.setup(password); code != http.StatusCreated || errCode != "" {
		t.Fatalf("setup = %d %q, want 201", code, errCode)
	}
	if !c.status() {
		t.Fatal("after setup the server still reports itself uninitialized")
	}

	// The password just set now signs in, and a wrong one does not.
	c.token = c.loginWith(password)
	wrong := c.raw(http.MethodPost, "/api/v1/auth/token",
		[]byte(`{"password":"the wrong one"}`), "")
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("token with a wrong password = %s, want 401", wrong.Status)
	}

	// A second first run is refused, and could not change the password anyway.
	if code, errCode := c.setup("some-other-secret"); code != http.StatusConflict || errCode != "already_initialized" {
		t.Fatalf("second setup = %d %q, want 409 already_initialized", code, errCode)
	}
	if c.loginWith(password) == "" {
		t.Fatal("the first password stopped working after a refused second setup")
	}
}

// An environment password is already a credential: the fresh server reports itself
// initialized and refuses a first run, so a container that set SYNCBOX_PASSWORD is
// never left waiting for a console.
func TestAnEnvironmentPasswordNeedsNoFirstRun(t *testing.T) {
	c := newClient(t, false) // env: testPassword

	if !c.status() {
		t.Error("a server with an environment password reports itself uninitialized")
	}
	if code, errCode := c.setup("another-secret"); code != http.StatusConflict || errCode != "already_initialized" {
		t.Errorf("setup with an env password = %d %q, want 409 already_initialized", code, errCode)
	}
}

// loginWith is login with a password other than the test constant.
func (c *client) loginWith(password string) string {
	c.t.Helper()
	body, _ := json.Marshal(map[string]string{"password": password})
	response := c.raw(http.MethodPost, "/api/v1/auth/token", body, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		c.t.Fatalf("login with the given password returned %s", response.Status)
	}
	var decoded struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		c.t.Fatalf("decoding token reply: %v", err)
	}
	if decoded.Token == "" {
		c.t.Fatal("server issued an empty token")
	}
	return decoded.Token
}
