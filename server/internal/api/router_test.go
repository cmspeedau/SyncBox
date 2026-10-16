package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/backup"
	"github.com/syncbox/server/internal/backup/target"
	"github.com/syncbox/server/internal/store"
)

const testPassword = "correct horse battery staple"

// client is a test server plus a token, which is what every authenticated case
// needs before it can ask for anything.
type client struct {
	t      *testing.T
	server *httptest.Server
	token  string
}

func newClient(t *testing.T, withBackups bool) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)

	var backups *backup.Manager
	if withBackups {
		dir := t.TempDir()
		tgt, err := target.NewLocal(dir)
		if err != nil {
			t.Fatalf("target.NewLocal: %v", err)
		}
		backups = backup.NewManager(tgt, stored, "test")
		// A snapshot is sealed at mode 0550, which would leave t.TempDir unable to
		// clean it up. Clearing the modes is what a real maintenance pass does.
		t.Cleanup(func() { unsealTree(t, dir) })
	}

	server := httptest.NewServer(New(stored, backups, issuer, testPassword).Routes())
	t.Cleanup(server.Close)

	testClient := &client{t: t, server: server}
	testClient.token = testClient.login()
	return testClient
}

// login exchanges the configured password for a token, failing the test if the
// server refuses its own credentials.
func (c *client) login() string {
	c.t.Helper()

	body, _ := json.Marshal(map[string]string{"password": testPassword})
	response := c.raw(http.MethodPost, "/api/v1/auth/token", body, "")
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		c.t.Fatalf("login returned %s", response.Status)
	}
	var decoded struct {
		Token       string `json:"token"`
		ExpiresUnix int64  `json:"expires_unix"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		c.t.Fatalf("decoding token reply: %v", err)
	}
	if decoded.Token == "" {
		c.t.Fatal("server issued an empty token")
	}
	if decoded.ExpiresUnix <= time.Now().Unix() {
		c.t.Errorf("token expiry %d is already past", decoded.ExpiresUnix)
	}
	return decoded.Token
}

// raw sends a request without a token, for the unauthenticated cases.
func (c *client) raw(method, path string, body []byte, token string) *http.Response {
	c.t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, c.server.URL+path, reader)
	if err != nil {
		c.t.Fatalf("building %s %s: %v", method, path, err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	return response
}

// do sends an authenticated request.
func (c *client) do(method, path string, body []byte) *http.Response {
	c.t.Helper()
	return c.raw(method, path, body, c.token)
}

// mustDecode reads a JSON reply into dst.
func (c *client) mustDecode(response *http.Response, dst any) {
	c.t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(dst); err != nil {
		c.t.Fatalf("decoding reply: %v", err)
	}
}

// errorBodyOf reads the standard error reply.
func (c *client) errorBodyOf(response *http.Response) (string, string) {
	c.t.Helper()
	var decoded struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	c.mustDecode(response, &decoded)
	return decoded.Code, decoded.Reason
}

// silenceLogs keeps the middleware's request lines out of test output.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	os.Exit(m.Run())
}

// unsealTree clears the read-only bits a sealed snapshot sets, so a temporary
// directory can be removed at the end of a test.
func unsealTree(t *testing.T, root string) {
	t.Helper()

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			os.Chmod(path, 0o755)
			return nil
		}
		os.Chmod(path, 0o644)
		return nil
	})
	if err != nil {
		t.Logf("unsealing %s: %v", root, err)
	}
}

func TestHealthNeedsNoToken(t *testing.T) {
	c := newClient(t, false)

	response := c.raw(http.MethodGet, "/healthz", nil, "")
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("health returned %s", response.Status)
	}
	var decoded struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatalf("decoding health: %v", err)
	}
	if decoded.Status != "ok" {
		t.Errorf("status = %q, want ok", decoded.Status)
	}
}

func TestWrongPasswordIsRejected(t *testing.T) {
	c := newClient(t, false)

	body, _ := json.Marshal(map[string]string{"password": "wrong password"})
	response := c.raw(http.MethodPost, "/api/v1/auth/token", body, "")
	defer response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong password returned %s, want 401", response.Status)
	}
	if code, _ := c.errorBodyOf(response); code != "unauthorized" {
		t.Errorf("code = %q, want unauthorized", code)
	}
}

func TestUnknownTokenIsRejected(t *testing.T) {
	c := newClient(t, false)

	response := c.raw(http.MethodGet, "/api/v1/vaults/vault/revisions?since=0", nil, "not-a-real-token")
	response.Body.Close()

	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("forged token returned %s, want 401", response.Status)
	}
}

func TestMissingTokenIsRejected(t *testing.T) {
	c := newClient(t, false)

	// The handler tree distinguishes "no credentials" from "bad credentials", and
	// the client reacts differently to each: one asks for a password, the other
	// refreshes.
	response := c.raw(http.MethodGet, "/api/v1/vaults/vault/revisions", nil, "")
	code, _ := c.errorBodyOf(response)
	if response.StatusCode != http.StatusUnauthorized || code != "unauthorized" {
		t.Errorf("missing token gave %s code %q", response.Status, code)
	}
}

func TestChunkLifecycle(t *testing.T) {
	c := newClient(t, false)
	const chunkID = "ABCDEFGH12345678"
	const path = "/api/v1/vaults/vault/chunks/" + chunkID

	// Before the upload, the server must report the chunk as missing.
	body, _ := json.Marshal(map[string][]string{"ids": {chunkID}})
	response := c.do(http.MethodPost, "/api/v1/vaults/vault/chunks/exists", body)
	var check struct {
		Missing []string `json:"missing"`
	}
	c.mustDecode(response, &check)
	if len(check.Missing) != 1 {
		t.Fatalf("missing = %v, want the chunk listed", check.Missing)
	}

	response = c.raw(http.MethodHead, path, nil, c.token)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("HEAD before upload = %s, want 404", response.Status)
	}
	response.Body.Close()

	payload := []byte("encrypted bytes")
	response = c.do(http.MethodPut, path, payload)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("PUT = %s, want 201", response.Status)
	}
	response.Body.Close()

	response = c.raw(http.MethodHead, path, nil, c.token)
	if response.StatusCode != http.StatusOK {
		t.Errorf("HEAD after upload = %s, want 200", response.Status)
	}
	if got := response.ContentLength; got != int64(len(payload)) {
		t.Errorf("HEAD reported %d bytes, want %d", got, len(payload))
	}
	response.Body.Close()

	response = c.do(http.MethodGet, path, nil)
	got, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatalf("reading chunk: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("chunk came back as %q", got)
	}

	// And now the existence check must say there is nothing to send, which is what
	// makes a re-sync cheap.
	response = c.do(http.MethodPost, "/api/v1/vaults/vault/chunks/exists", body)
	c.mustDecode(response, &check)
	if len(check.Missing) != 0 {
		t.Errorf("missing = %v after upload, want none", check.Missing)
	}
}

func TestTraversalStyleChunkIDIsRefused(t *testing.T) {
	c := newClient(t, false)

	response := c.do(http.MethodPut, "/api/v1/vaults/vault/chunks/../../etc/passwd", []byte("x"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusNotFound {
		t.Errorf("traversal id returned %s, want a refusal", response.Status)
	}
	if response.StatusCode == http.StatusCreated {
		t.Error("traversal id was stored")
	}
}

func TestCommitAssignsAndPagesRevisions(t *testing.T) {
	c := newClient(t, false)

	commit := func(parent uint64, name string) uint64 {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"parent": parent,
			"revision": map[string]any{
				"parent":        parent,
				"dir_id":        "DIRID",
				"cipher_name":   name,
				"manifest":      "ZW5jcnlwdGVk",
				"size":          12,
				"modified_unix": 1_700_000_000,
				"deleted":       false,
			},
		})
		if err != nil {
			t.Fatalf("marshalling commit: %v", err)
		}
		response := c.do(http.MethodPost, "/api/v1/vaults/vault/revisions", body)
		defer response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(response.Body)
			t.Fatalf("commit %s = %s: %s", name, response.Status, body)
		}
		var decoded struct {
			Revision uint64 `json:"revision"`
		}
		c.mustDecode(response, &decoded)
		return decoded.Revision
	}

	first := commit(0, "AAAA")
	if first != 1 {
		t.Errorf("first revision = %d, want 1", first)
	}
	second := commit(1, "BBBB")
	if second != 2 {
		t.Errorf("second revision = %d, want 2", second)
	}

	response := c.do(http.MethodGet, "/api/v1/vaults/vault/revisions?since=0", nil)
	var page struct {
		Revisions []struct {
			Revision   uint64 `json:"revision"`
			CipherName string `json:"cipher_name"`
		} `json:"revisions"`
		Upto uint64 `json:"upto"`
	}
	c.mustDecode(response, &page)
	if page.Upto != 2 {
		t.Errorf("upto = %d, want 2", page.Upto)
	}
	if len(page.Revisions) != 2 || page.Revisions[0].CipherName != "AAAA" {
		t.Errorf("page = %+v, want both revisions oldest first", page.Revisions)
	}

	// The client polls with the head it last saw; a settled vault answers empty.
	response = c.do(http.MethodGet, "/api/v1/vaults/vault/revisions?since=2", nil)
	c.mustDecode(response, &page)
	if len(page.Revisions) != 0 {
		t.Errorf("since the head returned %d revisions, want none", len(page.Revisions))
	}
}

func TestCommitAgainstAStaleParentConflicts(t *testing.T) {
	c := newClient(t, false)

	body, _ := json.Marshal(map[string]any{
		"parent": 0,
		"revision": map[string]any{
			"parent":      0,
			"dir_id":      "DIRID",
			"cipher_name": "AAAA",
			// A manifest is base64 on the wire, so this has to be valid base64 or
			// the decode fails before the conflict is ever reached.
			"manifest": "QUFB",
			"size":     1,
		},
	})
	response := c.do(http.MethodPost, "/api/v1/vaults/vault/revisions", body)
	response.Body.Close()

	// A second commit naming the same parent is the two-clients-one-file case. The
	// 409 is what tells the client to keep both copies instead of overwriting.
	response = c.do(http.MethodPost, "/api/v1/vaults/vault/revisions", body)
	defer response.Body.Close()

	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale commit = %s, want 409", response.Status)
	}
	if code, _ := c.errorBodyOf(response); code != "conflict" {
		t.Errorf("code = %q, want conflict", code)
	}
}

func TestCommitCannotWriteIntoAnotherVault(t *testing.T) {
	c := newClient(t, false)

	// The path decides the vault, so a body that names a different one is refused
	// rather than trusted.
	body, _ := json.Marshal(map[string]any{
		"parent": 0,
		"revision": map[string]any{
			"parent":      0,
			"vault_id":    "someone-elses-vault",
			"dir_id":      "DIRID",
			"cipher_name": "AAAA",
			"manifest":    "QUFB",
			"size":        1,
		},
	})
	response := c.do(http.MethodPost, "/api/v1/vaults/vault/revisions", body)
	response.Body.Close()

	if response.StatusCode == http.StatusCreated {
		// Overwriting is only acceptable because the server ignores the field, so
		// confirm the revision really landed under the path's vault.
		list := c.do(http.MethodGet, "/api/v1/vaults/someone-elses-vault/revisions?since=0", nil)
		var page struct {
			Revisions []json.RawMessage `json:"revisions"`
		}
		c.mustDecode(list, &page)
		if len(page.Revisions) != 0 {
			t.Error("a commit through one vault path wrote into another vault")
		}
	}
}

func TestUnknownFieldsAreRefused(t *testing.T) {
	c := newClient(t, false)

	body, _ := json.Marshal(map[string]any{
		"password":     testPassword,
		"admin_please": true,
	})
	response := c.raw(http.MethodPost, "/api/v1/auth/token", body, "")
	defer response.Body.Close()

	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown field returned %s, want 400", response.Status)
	}
}

func TestBackupsRunThroughTheAdminEndpoint(t *testing.T) {
	c := newClient(t, true)

	response := c.do(http.MethodPost, "/admin/backups", []byte("{}"))
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("backup = %s: %s", response.Status, body)
	}

	response = c.do(http.MethodGet, "/admin/backups", nil)
	var snapshots []struct {
		ID       string `json:"ID"`
		Manifest struct {
			Chunks []json.RawMessage `json:"chunks"`
		} `json:"Manifest"`
	}
	c.mustDecode(response, &snapshots)
	if len(snapshots) != 1 {
		t.Fatalf("listed %d snapshots, want 1", len(snapshots))
	}
	if snapshots[0].ID == "" {
		t.Error("snapshot has no id")
	}
}

func TestBackupsReportWhenNotConfigured(t *testing.T) {
	c := newClient(t, false)

	response := c.do(http.MethodPost, "/admin/backups", []byte("{}"))
	defer response.Body.Close()

	if response.StatusCode != http.StatusNotImplemented {
		t.Errorf("unconfigured backup = %s, want 501", response.Status)
	}
	if code, _ := c.errorBodyOf(response); code != "not_configured" {
		t.Errorf("code = %q, want not_configured", code)
	}
}
