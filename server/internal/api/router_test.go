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
	"strings"
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

// newEnforcingClient is newClient with vault enforcement on: the server refuses
// a commit to a vault its registry does not know (S5).
func newEnforcingClient(t *testing.T) *client {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	server := New(stored, nil, issuer, testPassword)
	server.SetRequireRegisteredVaults(true)
	httpServer := httptest.NewServer(server.Routes())
	t.Cleanup(httpServer.Close)

	testClient := &client{t: t, server: httpServer}
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

func TestBackupVerifyProvesAndRestoreDelivers(t *testing.T) {
	c := newClient(t, true)

	// One chunk of real content, so verify has something to re-hash.
	upload := c.do(http.MethodPut, "/api/v1/vaults/vault/chunks/ABCDEFGHIJKLMNOP", []byte("payload for the backup test"))
	defer upload.Body.Close()
	if upload.StatusCode != http.StatusCreated && upload.StatusCode != http.StatusOK {
		t.Fatalf("chunk upload = %s", upload.Status)
	}

	response := c.do(http.MethodPost, "/admin/backups", []byte("{}"))
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create backup = %s", response.Status)
	}
	var snapshot struct {
		ID string `json:"ID"`
	}
	c.mustDecode(response, &snapshot)

	// Verify answers with the numbers it just re-checked against the target.
	response = c.do(http.MethodPost, "/admin/backups/"+snapshot.ID+"/verify", nil)
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("verify = %s: %s", response.Status, body)
	}
	var verified struct {
		ID     string `json:"id"`
		Chunks int    `json:"chunks"`
	}
	c.mustDecode(response, &verified)
	if verified.ID != snapshot.ID || verified.Chunks < 1 {
		t.Errorf("verify body = %+v, want the snapshot's id and chunks", verified)
	}

	// Restore writes a usable data directory into an empty destination.
	dest := t.TempDir()
	dest = filepath.Join(dest, "restored") // may not exist yet: restore creates it
	body, _ := json.Marshal(map[string]string{"dest_dir": dest})
	response = c.do(http.MethodPost, "/admin/backups/"+snapshot.ID+"/restore", body)
	if response.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(response.Body)
		t.Fatalf("restore = %s: %s", response.Status, raw)
	}
	if _, err := os.Stat(filepath.Join(dest, "metadata.json")); err != nil {
		t.Errorf("restored directory has no metadata.json: %v", err)
	}

	// A second restore over the now-occupied target is a conflict, not a wipe.
	response = c.do(http.MethodPost, "/admin/backups/"+snapshot.ID+"/restore", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Errorf("restore over an occupied target = %s, want 409", response.Status)
	}

	// A snapshot that was never taken is a clean 404, on both endpoints.
	response = c.do(http.MethodPost, "/admin/backups/NEVER/verify", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("verify unknown = %s, want 404", response.Status)
	}
}

func TestRateLimitThrottlesAndSaysWhenToReturn(t *testing.T) {
	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	srv := New(stored, nil, issuer, testPassword)
	// Burst of three with effectively no refill, so the whole test spends the
	// burst and lands on the refusal without sleeping.
	srv.SetRateLimit(0.001, 3)

	server := httptest.NewServer(srv.Routes())
	t.Cleanup(server.Close)

	c := &client{t: t, server: server}
	c.token = c.login() // first token of the burst.

	// Two more fit; login plus these two is the burst of three.
	for range 2 {
		response := c.do(http.MethodGet, "/healthz", nil)
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("in-burst request = %s, want 200", response.Status)
		}
	}

	response := c.do(http.MethodGet, "/api/v1/vaults/vault/revisions", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("post-burst request = %s, want 429", response.Status)
	}
	if after := response.Header.Get("Retry-After"); after == "" {
		t.Error("a 429 must say when to come back")
	}
	var refused struct {
		Code   string `json:"code"`
		Reason string `json:"reason"`
	}
	c.mustDecode(response, &refused)
	if refused.Code != "rate_limited" {
		t.Errorf("refusal code = %q, want rate_limited — the code clients retry on", refused.Code)
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

func TestRootAnswersWithNameCard(t *testing.T) {
	c := newClient(t, false)

	// No token: the root answers whoever asks, human or script. The 404 it
	// replaces was the server's whole first impression.
	response := c.raw(http.MethodGet, "/", nil, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %s, want 200", response.Status)
	}

	var card struct {
		Name    string            `json:"name"`
		Version string            `json:"version"`
		Docs    string            `json:"docs"`
		API     map[string]string `json:"api"`
	}
	c.mustDecode(response, &card)
	if card.Name != "syncbox" {
		t.Errorf("name = %q, want syncbox", card.Name)
	}
	if card.Version == "" {
		t.Error("name-card omits its version")
	}
	if card.Docs == "" {
		t.Error("name-card omits the docs link")
	}
	for _, key := range []string{"token", "revisions", "chunks", "vault_registry", "backups"} {
		if card.API[key] == "" {
			t.Errorf("name-card api map missing %q", key)
		}
	}

	// The card answers "/" alone: a mistyped path stays a 404 rather than
	// confidently showing everyone the wrong page.
	response = c.raw(http.MethodGet, "/definitely-not-a-page", nil, "")
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("GET /definitely-not-a-page = %s, want 404", response.Status)
	}
}

func TestVaultRegistryNeedsAToken(t *testing.T) {
	c := newClient(t, false)

	for _, request := range []struct{ method, path string }{
		{http.MethodGet, "/admin/vaults"},
		{http.MethodPost, "/admin/vaults"},
		{http.MethodPatch, "/admin/vaults/ABCDEFGH"},
		{http.MethodPost, "/admin/vaults/ABCDEFGH/archive"},
	} {
		response := c.raw(request.method, request.path, nil, "")
		code, _ := c.errorBodyOf(response)
		response.Body.Close()
		if code != "unauthorized" {
			t.Errorf("%s %s without a token = %q, want unauthorized",
				request.method, request.path, code)
		}
	}
}

func TestVaultRegistryLifecycle(t *testing.T) {
	c := newClient(t, false)

	// Create: the server mints the id, and the fresh vault answers in its own
	// full shape so a console can render it without a second round trip.
	body, _ := json.Marshal(map[string]string{"name": "Photos"})
	response := c.do(http.MethodPost, "/admin/vaults", body)
	if response.StatusCode != http.StatusCreated {
		defer response.Body.Close()
		t.Fatalf("create = %s", response.Status)
	}
	var created store.VaultInfo
	c.mustDecode(response, &created)
	if len(created.ID) != 8 || created.Name != "Photos" || created.CreatedAt == 0 {
		t.Fatalf("created = %+v, want a minted 8-char id, name Photos, real timestamp", created)
	}
	if created.Location != "Photos" {
		t.Errorf("a vault with no location given should default to its name, got %q", created.Location)
	}

	// A name that would render as a blank row is refused on the way in.
	for _, bad := range []string{`{"name":"  "}`, `{"name":""}`} {
		response := c.do(http.MethodPost, "/admin/vaults", []byte(bad))
		code, _ := c.errorBodyOf(response)
		response.Body.Close()
		if code != "invalid_name" {
			t.Errorf("create with %s = %q, want invalid_name", bad, code)
		}
	}

	// A client that commits into a vault nobody registered still works —
	// enforcement is a later milestone — and the vault appears in the
	// registry nameless, which is the migration story made visible.
	commitBody, _ := json.Marshal(map[string]any{
		"parent": 0,
		"revision": map[string]any{
			"parent": 0, "dir_id": "DIRID", "cipher_name": "AAAA",
			"manifest": "ZW5jcnlwdGVk", "size": 12, "modified_unix": 1_700_000_000,
		},
	})
	response = c.do(http.MethodPost, "/api/v1/vaults/GRANDMA1/revisions", commitBody)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("commit into unregistered vault = %s, want 201 while registration is optional", response.Status)
	}

	list := func() []store.VaultInfo {
		t.Helper()
		response := c.do(http.MethodGet, "/admin/vaults", nil)
		defer response.Body.Close()
		var decoded struct {
			Vaults []store.VaultInfo `json:"vaults"`
		}
		c.mustDecode(response, &decoded)
		return decoded.Vaults
	}

	// Rename, with a 404 for ids that were never minted or committed.
	body, _ = json.Marshal(map[string]string{"name": "Family Photos"})
	response = c.do(http.MethodPatch, "/admin/vaults/"+created.ID, body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("rename = %s, want 200", response.Status)
	}
	body, _ = json.Marshal(map[string]string{"name": "Nothing"})
	response = c.do(http.MethodPatch, "/admin/vaults/NOSUCHVA", body)
	code, _ := c.errorBodyOf(response)
	response.Body.Close()
	if code != "not_found" {
		t.Errorf("rename unknown id = %q, want not_found", code)
	}

	// Location: set on the vault's card, refused when another live vault
	// already claims the folder, and clearable (empty means "clients choose").
	body, _ = json.Marshal(map[string]string{"location": "Syncbox/Family Photos"})
	response = c.do(http.MethodPatch, "/admin/vaults/"+created.ID, body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("set location = %s, want 200", response.Status)
	}
	secondBody, _ := json.Marshal(map[string]string{"name": "Work"})
	response = c.do(http.MethodPost, "/admin/vaults", secondBody)
	var second store.VaultInfo
	c.mustDecode(response, &second)
	body, _ = json.Marshal(map[string]string{"location": "Syncbox/Family Photos"})
	response = c.do(http.MethodPatch, "/admin/vaults/"+second.ID, body)
	code, _ = c.errorBodyOf(response)
	response.Body.Close()
	if code != "location_taken" {
		t.Errorf("claiming a live vault's folder = %q, want location_taken", code)
	}
	body, _ = json.Marshal(map[string]string{"location": "  "})
	response = c.do(http.MethodPatch, "/admin/vaults/"+second.ID, body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Errorf("clearing a location = %s, want 200", response.Status)
	}
	body, _ = json.Marshal(map[string]string{})
	response = c.do(http.MethodPatch, "/admin/vaults/"+second.ID, body)
	code, _ = c.errorBodyOf(response)
	response.Body.Close()
	if code != "invalid_request" {
		t.Errorf("patch with neither name nor location = %q, want invalid_request", code)
	}

	// Archive, and its 404.
	body, _ = json.Marshal(map[string]bool{"archived": true})
	response = c.do(http.MethodPost, "/admin/vaults/GRANDMA1/archive", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("archive = %s, want 200", response.Status)
	}
	response = c.do(http.MethodPost, "/admin/vaults/NOSUCHVA/archive", body)
	code, _ = c.errorBodyOf(response)
	response.Body.Close()
	if code != "not_found" {
		t.Errorf("archive unknown id = %q, want not_found", code)
	}

	vaults := list()
	byID := map[string]store.VaultInfo{}
	for _, info := range vaults {
		byID[info.ID] = info
	}
	if len(byID) != 3 {
		t.Fatalf("registry lists %+v, want three vaults", vaults)
	}
	if renamed := byID[created.ID]; renamed.Name != "Family Photos" ||
		renamed.Location != "Syncbox/Family Photos" || renamed.Revisions != 0 {
		t.Errorf("renamed vault reads %+v", renamed)
	}
	if work := byID[second.ID]; work.Name != "Work" || work.Location != "" {
		t.Errorf("vault %s reads %+v, want name Work and a cleared location", second.ID, work)
	}
	grandma, ok := byID["GRANDMA1"]
	if !ok {
		t.Fatal("committed vault never entered the registry")
	}
	if grandma.Name != "" || !grandma.Archived || grandma.Revisions != 1 ||
		grandma.LiveFiles != 1 || grandma.Bytes != 12 {
		t.Errorf("commit-born vault reads %+v, want nameless, archived, 1 revision of 12 live bytes", grandma)
	}
}

// TestClientsSeeVaultsWithoutBookkeeping pins the client-facing read: names
// and retirement for resolution, and none of the operator's numbers.
func TestClientsSeeVaultsWithoutBookkeeping(t *testing.T) {
	c := newClient(t, false)

	response := c.raw(http.MethodGet, "/vaults", nil, "")
	code, _ := c.errorBodyOf(response)
	response.Body.Close()
	if code != "unauthorized" {
		t.Fatalf("GET /vaults unauthenticated = %q, want unauthorized", code)
	}

	body, _ := json.Marshal(map[string]string{"name": "Photos"})
	response = c.do(http.MethodPost, "/admin/vaults", body)
	var created store.VaultInfo
	c.mustDecode(response, &created)

	retireBody, _ := json.Marshal(map[string]string{"name": "Old Jobs"})
	response = c.do(http.MethodPost, "/admin/vaults", retireBody)
	var retiring store.VaultInfo
	c.mustDecode(response, &retiring)
	archiveBody, _ := json.Marshal(map[string]bool{"archived": true})
	c.do(http.MethodPost, "/admin/vaults/"+retiring.ID+"/archive", archiveBody).Body.Close()

	list := c.do(http.MethodGet, "/vaults", nil)
	var decoded struct {
		Vaults []map[string]any `json:"vaults"`
	}
	c.mustDecode(list, &decoded)

	byID := map[string]map[string]any{}
	for _, vault := range decoded.Vaults {
		byID[vault["id"].(string)] = vault
	}
	if len(byID) != 2 {
		t.Fatalf("client list = %+v, want the two registered vaults", decoded.Vaults)
	}
	if photos := byID[created.ID]; photos["name"] != "Photos" || photos["archived"] != false ||
		photos["location"] != "Photos" {
		t.Errorf("Photos reads %+v, want name Photos at its defaulted location", photos)
	}
	if retired := byID[retiring.ID]; retired["archived"] != true {
		t.Errorf("retired vault reads %+v, want archived true", retired)
	}
	// The fields a client must not receive: the operator's bookkeeping.
	for _, vault := range decoded.Vaults {
		for _, forbidden := range []string{"revisions", "live_files", "bytes", "created_at", "last_write_at"} {
			if _, present := vault[forbidden]; present {
				t.Errorf("client vault list leaked %q: %+v", forbidden, vault)
			}
		}
	}
}

// TestEnforcementRefusesUnknownVaults covers S5: with the toggle on, a commit
// to a vault the registry does not know is refused with a stable code instead
// of silently birthing a namespace — while a vault created the normal way
// commits exactly as before. That contrast is what makes the toggle safe to
// turn on late: it closes a door without changing the room.
func TestEnforcementRefusesUnknownVaults(t *testing.T) {
	c := newEnforcingClient(t)

	commit := func(vaultID string) *http.Response {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"parent": 0,
			"revision": map[string]any{
				"parent":        0,
				"dir_id":        "DIRID",
				"cipher_name":   "AAAA",
				"manifest":      "ZW5jcnlwdGVk",
				"size":          12,
				"modified_unix": 1_700_000_000,
				"deleted":       false,
			},
		})
		if err != nil {
			t.Fatalf("marshalling commit: %v", err)
		}
		return c.do(http.MethodPost, "/api/v1/vaults/"+vaultID+"/revisions", body)
	}

	refused := commit("STRANGER")
	if refused.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(refused.Body)
		t.Fatalf("commit to an unregistered vault = %s, want 403: %s", refused.Status, body)
	}
	if code, _ := c.errorBodyOf(refused); code != "unknown_vault" {
		t.Errorf("refusal code = %q, want unknown_vault", code)
	}

	// A vault created the way the console creates one is registered, so the
	// very same commit lands — enforcement gates entry, not the vault itself.
	created := c.do(http.MethodPost, "/admin/vaults", []byte(`{"name":"Photos"}`))
	if created.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("creating a vault = %s: %s", created.Status, body)
	}
	var vault store.VaultInfo
	c.mustDecode(created, &vault)

	accepted := commit(vault.ID)
	defer accepted.Body.Close()
	if accepted.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(accepted.Body)
		t.Fatalf("commit to a registered vault = %s, want 201: %s", accepted.Status, body)
	}
}

func TestConsoleServedToBrowsers(t *testing.T) {
	c := newClient(t, false)

	request, err := http.NewRequest(http.MethodGet, c.server.URL+"/", nil)
	if err != nil {
		t.Fatalf("building request: %v", err)
	}
	request.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET / as a browser: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET / as a browser = %s, want 200", response.Status)
	}
	if ctype := response.Header.Get("Content-Type"); !strings.HasPrefix(ctype, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ctype)
	}
	if csp := response.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("Content-Security-Policy = %q, want default-src 'self'", csp)
	}
	if cache := response.Header.Get("Cache-Control"); cache != "no-store" {
		t.Errorf("Cache-Control on the page = %q, want no-store", cache)
	}

	page, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading page: %v", err)
	}
	body := string(page)
	for _, want := range []string{"<!DOCTYPE html>", "src=\"/app.js\"", "href=\"/style.css\"", "cannot read your files", "id=\"snapshots\"", "Take snapshot", "id=\"theme\""} {
		if !strings.Contains(body, want) {
			t.Errorf("page is missing %q", want)
		}
	}
	// The CSP's promise, checked against the page itself: no inline script or
	// style, which is what script-src 'self' exists to make unnecessary.
	for _, forbidden := range []string{"<script>", "<style", "onclick=", "onload="} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Errorf("page smuggles inline behaviour: %q", forbidden)
		}
	}
}

func TestConsoleAssetsAreRoutedNotMounted(t *testing.T) {
	c := newClient(t, false)

	// The assets need no token — the shell is public; every byte of data it
	// will fetch behind that shell does.
	for path, wantType := range map[string]string{"/app.js": "text/javascript", "/style.css": "text/css"} {
		response := c.raw(http.MethodGet, path, nil, "")
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if response.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %s, want 200", path, response.Status)
		}
		if ctype := response.Header.Get("Content-Type"); !strings.HasPrefix(ctype, wantType) {
			t.Errorf("%s Content-Type = %q, want %s", path, ctype, wantType)
		}
		if len(body) == 0 {
			t.Errorf("%s served empty; go:embed lost the file", path)
		}
	}

	// Nothing is reachable but the embedded set: there is no directory to walk.
	response := c.raw(http.MethodGet, "/../server/internal/config/config.go", nil, "")
	defer response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("path walked outside the embedded assets")
	}
}
