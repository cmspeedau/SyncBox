package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/syncbox/server/internal/auth"
	"github.com/syncbox/server/internal/store"
)

// The sync-space surfaces are tested through the HTTP surface rather than
// against the store directly, because what they promise is a contract: what a
// client may read of a space it registered as cleartext, and what it must be
// refused on one it registered as a vault.

// syncProbe is a test server whose clock the test owns. Owning the clock is what
// lets a share link expire and a recycle window close inside a test rather than
// in a sleep, and lets a mint be checked against a fixed "now".
type syncProbe struct {
	*client
	api    *Server
	offset atomic.Int64
}

// probeClock is the moment every probe starts from, so a test that advances the
// clock by days knows exactly what the server thinks "today" is.
var probeClock = time.Date(2026, time.October, 18, 12, 0, 0, 0, time.UTC)

func newSyncProbe(t *testing.T) *syncProbe {
	t.Helper()

	stored := store.NewMemory(MaxChunkBytes)
	issuer := auth.NewIssuer("test-secret", time.Hour)
	api := New(stored, nil, issuer, testPassword)

	// The clock reads the probe's offset, so it is live for every handler and
	// every goroutine without any of them sharing a variable the test writes.
	probe := &syncProbe{api: api}
	api.now = func() time.Time {
		return probeClock.Add(time.Duration(probe.offset.Load()))
	}

	server := httptest.NewServer(api.Routes())
	t.Cleanup(server.Close)
	probe.client = &client{t: t, server: server}
	probe.token = probe.login()
	return probe
}

// advance moves the server's clock forward, which is how a test expires a share
// link or closes a recycle window without waiting for either.
func (p *syncProbe) advance(by time.Duration) {
	p.offset.Add(int64(by))
}

// createSpace registers a space in the given mode and returns its id.
func (p *syncProbe) createSpace(name, mode string) string {
	p.t.Helper()

	body, _ := json.Marshal(map[string]string{"name": name, "mode": mode})
	response := p.do(http.MethodPost, "/admin/vaults", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		p.t.Fatalf("creating a %s space %q: %s", mode, name, response.Status)
	}
	var created struct {
		ID   string `json:"id"`
		Mode string `json:"mode"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		p.t.Fatalf("decoding the created space: %v", err)
	}
	if created.ID == "" {
		p.t.Fatal("the registry minted an empty id")
	}
	return created.ID
}

// commitBody is the wire shape of POST .../revisions. Field names are the
// protocol's, and the server refuses a body holding anything they do not name.
type commitBody struct {
	Parent   uint64      `json:"parent"`
	Revision commitEntry `json:"revision"`
}

type commitEntry struct {
	Revision   uint64 `json:"revision"`
	Parent     uint64 `json:"parent"`
	DirID      string `json:"dir_id"`
	CipherName string `json:"cipher_name"`
	Manifest   string `json:"manifest"`
	Size       int64  `json:"size"`
	ModifiedAt int64  `json:"modified_unix"`
	Deleted    bool   `json:"deleted"`
}

// head reads the space's current revision, the parent every commit must name.
func (p *syncProbe) head(vaultID string) uint64 {
	p.t.Helper()

	response := p.do(http.MethodGet, "/api/v1/vaults/"+vaultID+"/revisions?since=0", nil)
	var page struct {
		Upto uint64 `json:"upto"`
	}
	p.mustDecode(response, &page)
	return page.Upto
}

// push uploads one cleartext file's chunk and commits it with a manifest that
// names that chunk — the bytes a real sync client sends in sync mode.
func (p *syncProbe) push(vaultID, relDir, name, body string) uint64 {
	p.t.Helper()

	id := chunkIDFor([]byte(body))
	response := p.do(http.MethodPut,
		"/api/v1/vaults/"+vaultID+"/chunks/"+id, []byte(body))
	response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		p.t.Fatalf("storing chunk %s: %s", id, response.Status)
	}

	parent := p.head(vaultID)
	payload, err := json.Marshal(commitBody{
		Parent: parent,
		Revision: commitEntry{
			Parent:     parent,
			DirID:      syncDirID(relDir),
			CipherName: name,
			Manifest:   buildSyncManifest(p.t, uint64(len(body)), chunkOf(body)),
			Size:       int64(len(body)),
			ModifiedAt: probeClock.Unix(),
		},
	})
	if err != nil {
		p.t.Fatalf("encoding the commit: %v", err)
	}

	response = p.do(http.MethodPost, "/api/v1/vaults/"+vaultID+"/revisions", payload)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		p.t.Fatalf("committing %s/%s: %s", relDir, name, response.Status)
	}
	var created struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		p.t.Fatalf("decoding the commit reply: %v", err)
	}
	return created.Revision
}

// remove commits a tombstone for one file, the way the sync engine does: no
// manifest, no size, and deleted set.
func (p *syncProbe) remove(vaultID, relDir, name string) uint64 {
	p.t.Helper()

	parent := p.head(vaultID)
	payload, err := json.Marshal(commitBody{
		Parent: parent,
		Revision: commitEntry{
			Parent:     parent,
			DirID:      syncDirID(relDir),
			CipherName: name,
			Manifest:   "",
			Deleted:    true,
		},
	})
	if err != nil {
		p.t.Fatalf("encoding the tombstone: %v", err)
	}

	response := p.do(http.MethodPost, "/api/v1/vaults/"+vaultID+"/revisions", payload)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		p.t.Fatalf("committing the tombstone for %s/%s: %s", relDir, name, response.Status)
	}
	var created struct {
		Revision uint64 `json:"revision"`
	}
	if err := json.NewDecoder(response.Body).Decode(&created); err != nil {
		p.t.Fatalf("decoding the tombstone reply: %v", err)
	}
	return created.Revision
}

// browseBody is what GET .../files answers.
type browseBody struct {
	VaultID string     `json:"vault_id"`
	Files   []fileView `json:"files"`
}

func (p *syncProbe) browse(vaultID string) *http.Response {
	p.t.Helper()
	return p.do(http.MethodGet, "/api/v1/vaults/"+vaultID+"/files", nil)
}

// binBody is what GET .../recycle answers.
type binBody struct {
	VaultID       string        `json:"vault_id"`
	Deleted       []recycleView `json:"deleted"`
	RetentionDays int           `json:"retention_days"`
}

func (p *syncProbe) bin(vaultID string) *http.Response {
	p.t.Helper()
	return p.do(http.MethodGet, "/api/v1/vaults/"+vaultID+"/recycle", nil)
}

// mint shares one file and returns the link.
func (p *syncProbe) mint(vaultID, relDir, name string, expiresInSeconds int64) (*http.Response, shareView) {
	p.t.Helper()

	payload, err := json.Marshal(shareCreateBody{
		DirID:            syncDirID(relDir),
		CipherName:       name,
		ExpiresInSeconds: expiresInSeconds,
	})
	if err != nil {
		p.t.Fatalf("encoding the share request: %v", err)
	}
	response := p.do(http.MethodPost, "/api/v1/vaults/"+vaultID+"/shares", payload)
	var view shareView
	if response.StatusCode == http.StatusCreated {
		if err := json.NewDecoder(response.Body).Decode(&view); err != nil {
			p.t.Fatalf("decoding the share reply: %v", err)
		}
		response.Body.Close()
	}
	return response, view
}

// fetch opens a share link with no credential at all, which is the point of one.
func (p *syncProbe) fetch(path string) *http.Response {
	p.t.Helper()
	return p.raw(http.MethodGet, path, nil, "")
}

func TestBrowseShowsACleartextTreeOfASyncSpace(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")
	p.push(space, "docs/2026", "plan.md", "# Plan")

	response := p.browse(space)
	var body browseBody
	p.mustDecode(response, &body)
	if body.VaultID != space {
		t.Errorf("vault_id = %q, want %q", body.VaultID, space)
	}

	paths := map[string]fileView{}
	for _, file := range body.Files {
		paths[file.Path] = file
	}
	if len(paths) != 2 {
		t.Fatalf("files = %+v, want two", body.Files)
	}
	notes, ok := paths["notes.txt"]
	if !ok {
		t.Fatalf("the root file is missing from %+v", body.Files)
	}
	if notes.Size != int64(len("hello in the clear")) {
		t.Errorf("notes.txt size = %d, want %d", notes.Size, len("hello in the clear"))
	}
	if notes.Revision == 0 {
		t.Error("a browsed file reported no revision")
	}
	if _, ok := paths["docs/2026/plan.md"]; !ok {
		t.Errorf("a nested file lost its decoded path: %+v", body.Files)
	}
	// The opaque key is still handed back, because that is what addresses the
	// file for a commit or a share.
	for _, file := range body.Files {
		if file.DirID == "" || file.CipherName == "" {
			t.Errorf("%q came back without its key: %+v", file.Path, file)
		}
	}
}

func TestBrowseFollowsEditsAndDeletions(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "first")
	p.push(space, "", "notes.txt", "second, longer")
	p.push(space, "", "keep.txt", "untouched")

	var body browseBody
	p.mustDecode(p.browse(space), &body)
	if len(body.Files) != 2 {
		t.Fatalf("files = %+v, want two live files", body.Files)
	}
	for _, file := range body.Files {
		if file.Path == "notes.txt" && file.Size != int64(len("second, longer")) {
			t.Errorf("browse showed notes.txt at %d bytes, want the newest revision", file.Size)
		}
	}

	p.remove(space, "", "notes.txt")
	body = browseBody{}
	p.mustDecode(p.browse(space), &body)
	if len(body.Files) != 1 || body.Files[0].Path != "keep.txt" {
		t.Errorf("after a delete files = %+v, want only keep.txt", body.Files)
	}
}

// The three surfaces are a sync space's. A vault answers 403 with a code, so a
// client can branch on the reason instead of reading a sentence, and nothing it
// cannot read is ever listed.
func TestAVaultRefusesAllThreeSurfacesWithACode(t *testing.T) {
	p := newSyncProbe(t)
	secret := p.createSpace("Grandma", "vault")
	const unknown = "NOSUCHVAULT"

	cases := []struct {
		method, path, code string
	}{
		{http.MethodGet, "/api/v1/vaults/" + secret + "/files", "not_browsable"},
		{http.MethodGet, "/api/v1/vaults/" + secret + "/recycle", "not_recyclable"},
		{http.MethodPost, "/api/v1/vaults/" + secret + "/recycle/restore", "not_recyclable"},
		{http.MethodPost, "/api/v1/vaults/" + secret + "/shares", "not_shareable"},
	}
	for _, want := range cases {
		response := p.do(want.method, want.path, []byte(`{"dir_id":"00","cipher_name":"x.txt"}`))
		if response.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s = %s, want 403", want.method, want.path, response.Status)
		}
		if code, _ := p.errorBodyOf(response); code != want.code {
			t.Errorf("%s %s code = %q, want %q", want.method, want.path, code, want.code)
		}
	}

	// An unknown space is a different answer: there is nothing to refuse.
	response := p.browse(unknown)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("browsing an unknown space = %s, want 404", response.Status)
	}
	response.Body.Close()

	// And a space that was never registered — a commit birthed it — stays a
	// vault, so the server keeps claiming it cannot read what nothing handed it
	// in the clear.
	const born = "COMMITBE"
	parent := p.head(born)
	payload, _ := json.Marshal(commitBody{Parent: parent, Revision: commitEntry{
		Parent: parent, DirID: "00", CipherName: "legacy.txt", Manifest: "eHl6", Size: 3,
	}})
	birth := p.do(http.MethodPost, "/api/v1/vaults/"+born+"/revisions", payload)
	birth.Body.Close()
	if code, _ := p.errorBodyOf(p.browse(born)); code != "not_browsable" {
		t.Errorf("a commit-born space was browsable: code %q", code)
	}
}

func TestShareStreamsOneFileToWhoeverHoldsTheLink(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "photos", "cat.txt", "an orange cat")

	response, share := p.mint(space, "photos", "cat.txt", 0)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("minting a share: %s", response.Status)
	}
	if share.Token == "" || share.URL == "" {
		t.Fatalf("share reply is missing its link: %+v", share)
	}
	if share.Path != "photos/cat.txt" {
		t.Errorf("share path = %q, want photos/cat.txt", share.Path)
	}
	if share.ExpiresUnix <= probeClock.Unix() {
		t.Errorf("share expires at %d, want after the clock's %d", share.ExpiresUnix, probeClock.Unix())
	}

	// The link is the credential: no bearer token is sent, and it still works.
	download := p.fetch(share.URL)
	defer download.Body.Close()
	if download.StatusCode != http.StatusOK {
		t.Fatalf("fetching a share: %s", download.Status)
	}
	body, err := io.ReadAll(download.Body)
	if err != nil {
		t.Fatalf("reading the shared bytes: %v", err)
	}
	if string(body) != "an orange cat" {
		t.Errorf("shared bytes = %q, want the file's own bytes", body)
	}
	if got := download.Header.Get("Content-Length"); got != "13" {
		t.Errorf("Content-Length = %q, want 13", got)
	}
	if got := download.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "attachment") {
		t.Errorf("Content-Disposition = %q, want an attachment", got)
	}
	// A share is content the server did not author, and it is served from the
	// same origin as the console: it must never be rendered or sniffed.
	if got := download.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if kind := download.Header.Get("Content-Type"); !strings.HasPrefix(kind, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain for a .txt file", kind)
	}
}

func TestShareLinksExpireAndAreCapped(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")

	// A mint may ask for less than the server's ceiling, never more.
	p.api.SetShareTTL(24 * time.Hour)
	_, long := p.mint(space, "", "notes.txt", 10*365*24*60*60)
	if asked := long.ExpiresUnix - probeClock.Unix(); asked != int64((24 * time.Hour).Seconds()) {
		t.Errorf("a ten-year ask expires in %ds, want the server's 24h ceiling", asked)
	}
	_, short := p.mint(space, "", "notes.txt", 60)
	if asked := short.ExpiresUnix - probeClock.Unix(); asked != 60 {
		t.Errorf("a 60s ask expires in %ds, want 60", asked)
	}

	p.advance(90 * time.Second)
	expired := p.fetch(short.URL)
	if expired.StatusCode != http.StatusUnauthorized {
		t.Errorf("an expired link = %s, want 401", expired.Status)
	}
	expired.Body.Close()

	// Inside its window the same link still reads.
	young := p.fetch(long.URL)
	if young.StatusCode != http.StatusOK {
		t.Errorf("a young link = %s, want 200", young.Status)
	}
	young.Body.Close()
}

// A share link must not be a skeleton key: it names one file, and neither kind
// of token works in the other's place.
func TestAShareLinkIsNotACredentialForAnythingElse(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	other := p.createSpace("Others", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")
	p.push(other, "", "elsewhere.txt", "not yours")

	_, share := p.mint(space, "", "notes.txt", 0)

	// As a bearer token: the claim sets are signed over different messages, so
	// this is a signature mismatch rather than a token with odd fields.
	response := p.raw(http.MethodGet, "/api/v1/vaults/"+other+"/files", nil, share.Token)
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("a share link as a bearer token = %s, want 401", response.Status)
	}
	response.Body.Close()

	// And a bearer token is not a share link.
	response = p.fetch("/api/v1/shares/" + p.token)
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("a bearer token as a share link = %s, want 401", response.Status)
	}
	response.Body.Close()

	// A forged link, whatever it claims, is refused.
	response = p.fetch("/api/v1/shares/" + share.Token + "x")
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("a forged share link = %s, want 401", response.Status)
	}
	response.Body.Close()

	// One link serves the one file it names, and never a listing.
	download := p.fetch(share.URL)
	body, err := io.ReadAll(download.Body)
	download.Body.Close()
	if err != nil {
		t.Fatalf("reading the shared bytes: %v", err)
	}
	if string(body) != "hello in the clear" {
		t.Errorf("the link served %q", body)
	}
}

func TestShareMintsOnlyForFilesTheSpaceHolds(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")
	p.remove(space, "", "notes.txt")

	response, _ := p.mint(space, "", "notes.txt", 0)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("sharing a deleted file = %s, want 404", response.Status)
	}
	response.Body.Close()

	response, _ = p.mint(space, "", "never.txt", 0)
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("sharing a file that never existed = %s, want 404", response.Status)
	}
	response.Body.Close()

	// A request must name a file; a body that leaves it out is a mistake.
	bad := p.do(http.MethodPost, "/api/v1/vaults/"+space+"/shares", []byte(`{"dir_id":"00"}`))
	if code, _ := p.errorBodyOf(bad); code != "invalid_request" {
		t.Errorf("sharing without a name = code %q, want invalid_request", code)
	}
}

// A file whose record the server cannot read is not shareable, and the mint is
// where that is caught: a link is something you hand to a stranger, and a link
// that fails on the first try is worse than a refusal.
func TestShareRefusesAFileTheServerCannotRead(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")

	// A vault-shaped manifest committed into a sync space: legal bytes as far as
	// the commit route is concerned, and useless to a download.
	parent := p.head(space)
	payload, _ := json.Marshal(commitBody{Parent: parent, Revision: commitEntry{
		Parent:     parent,
		DirID:      syncDirID(""),
		CipherName: "opaque.bin",
		Manifest:   base64.StdEncoding.EncodeToString([]byte("SBXVAULT not a sync record")),
		Size:       4,
	}})
	committed := p.do(http.MethodPost, "/api/v1/vaults/"+space+"/revisions", payload)
	if committed.StatusCode != http.StatusCreated {
		t.Fatalf("the commit route refused its own shape: %s", committed.Status)
	}
	committed.Body.Close()

	// It browses fine — the listing needs no manifest — and cannot be shared.
	var browsed browseBody
	p.mustDecode(p.browse(space), &browsed)
	if len(browsed.Files) != 1 {
		t.Fatalf("files = %+v, want the file listed", browsed.Files)
	}
	response, _ := p.mint(space, "", "opaque.bin", 0)
	if code, _ := p.errorBodyOf(response); code != "unreadable_manifest" {
		t.Errorf("sharing an unreadable record = code %q, want unreadable_manifest", code)
	}
}

// A link that was minted while the file was live stops resolving the moment the
// file is deleted, rather than serving a stale revision.
func TestADeletedFileStopsAnsweringItsOwnLink(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")
	_, share := p.mint(space, "", "notes.txt", 0)

	p.remove(space, "", "notes.txt")
	response := p.fetch(share.URL)
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Errorf("a deleted file's link = %s, want 404", response.Status)
	}
}

func TestTheRecycleBinListsDeletionsAndRestoreIsACommit(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "photos", "cat.txt", "an orange cat")
	p.push(space, "photos", "dog.txt", "a sleepy dog")
	p.push(space, "", "keep.txt", "untouched")

	p.remove(space, "photos", "cat.txt")

	var bin binBody
	p.mustDecode(p.bin(space), &bin)
	if len(bin.Deleted) != 1 {
		t.Fatalf("bin = %+v, want one deleted file", bin.Deleted)
	}
	entry := bin.Deleted[0]
	if entry.Path != "photos/cat.txt" {
		t.Errorf("bin path = %q, want photos/cat.txt", entry.Path)
	}
	if entry.Size != int64(len("an orange cat")) {
		t.Errorf("bin size = %d, want the size the file had", entry.Size)
	}
	// The deletion time is the store's own stamp on the tombstone, which is what
	// the retention window ages against.
	if entry.DeletedAt <= 0 || entry.DeletedAt > time.Now().Unix() {
		t.Errorf("deleted_unix = %d, want the moment the tombstone was stored", entry.DeletedAt)
	}

	// Restore is a commit at the head, so a peer's newer revision does not make
	// it land on top of nothing.
	peer := p.push(space, "", "peer.txt", "a peer wrote this")
	payload, _ := json.Marshal(map[string]string{
		"dir_id": syncDirID("photos"), "cipher_name": "cat.txt",
	})
	response := p.do(http.MethodPost, "/api/v1/vaults/"+space+"/recycle/restore", payload)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("restoring: %s", response.Status)
	}
	var restored fileView
	if err := json.NewDecoder(response.Body).Decode(&restored); err != nil {
		t.Fatalf("decoding the restore: %v", err)
	}
	response.Body.Close()
	if restored.Revision != peer+1 {
		t.Errorf("restored at revision %d, want the head after %d", restored.Revision, peer)
	}
	if restored.Path != "photos/cat.txt" || restored.Size != int64(len("an orange cat")) {
		t.Errorf("restored = %+v, want photos/cat.txt at its old size", restored)
	}

	bin = binBody{}
	p.mustDecode(p.bin(space), &bin)
	if len(bin.Deleted) != 0 {
		t.Errorf("bin after a restore = %+v, want empty", bin.Deleted)
	}
	var browsed browseBody
	p.mustDecode(p.browse(space), &browsed)
	// keep.txt, dog.txt, the peer's new file, and the restored one.
	if len(browsed.Files) != 4 {
		t.Errorf("files after a restore = %+v, want four", browsed.Files)
	}

	// Restoring something that is not in the bin is a 404, not a silent no-op.
	again := p.do(http.MethodPost, "/api/v1/vaults/"+space+"/recycle/restore", payload)
	if code, _ := p.errorBodyOf(again); code != "not_found" {
		t.Errorf("restoring a live file = code %q, want not_found", code)
	}
}

// The bin is a window, not a promise of forever: once the retention pass has
// swept a deletion, it is no longer offered, and the sweep is what the window
// means.
func TestTheRecycleWindowExpiresOldDeletions(t *testing.T) {
	p := newSyncProbe(t)
	p.api.SetRecycleDays(30)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")
	p.remove(space, "", "notes.txt")

	var bin binBody
	p.mustDecode(p.bin(space), &bin)
	if len(bin.Deleted) != 1 || bin.RetentionDays != 30 {
		t.Fatalf("bin = %+v, want one entry inside a 30-day window", bin)
	}

	p.advance(45 * 24 * time.Hour)
	bin = binBody{}
	p.mustDecode(p.bin(space), &bin)
	if len(bin.Deleted) != 0 {
		t.Errorf("bin after the window = %+v, want nothing on offer", bin.Deleted)
	}
	// The tombstone itself still stands: the file is not browsable again.
	var browsed browseBody
	p.mustDecode(p.browse(space), &browsed)
	if len(browsed.Files) != 0 {
		t.Errorf("an expired deletion came back to life: %+v", browsed.Files)
	}
}

func TestTheSyncSurfacesNeedTheirToken(t *testing.T) {
	p := newSyncProbe(t)
	space := p.createSpace("Docs", "sync")
	p.push(space, "", "notes.txt", "hello in the clear")

	for _, path := range []string{
		"/api/v1/vaults/" + space + "/files",
		"/api/v1/vaults/" + space + "/recycle",
	} {
		response := p.raw(http.MethodGet, path, nil, "")
		if response.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without a token = %s, want 401", path, response.Status)
		}
		response.Body.Close()
	}
}

// chunkIDFor is the sync space's content address: SHA-256 of the plaintext, in
// the same Crockford base32 the client uses.
func chunkIDFor(body []byte) string {
	sum := sha256.Sum256(body)
	return crockfordEncode(sum[:])
}

// testChunk is one manifest entry: a chunk's address and the bytes it stores.
type testChunk struct {
	id        string
	storedLen int
}

func chunkOf(body string) testChunk {
	return testChunk{id: chunkIDFor([]byte(body)), storedLen: len(body)}
}

// buildSyncManifest writes the cleartext record a sync client commits, and
// returns it base64-encoded as the wire carries it.
func buildSyncManifest(t *testing.T, size uint64, chunks ...testChunk) string {
	t.Helper()

	var out bytes.Buffer
	out.WriteString(syncManifestMagic)
	var eight [8]byte
	binary.LittleEndian.PutUint64(eight[:], size)
	out.Write(eight[:])
	var four [4]byte
	binary.LittleEndian.PutUint32(four[:], uint32(len(chunks)))
	out.Write(four[:])
	for _, chunk := range chunks {
		binary.LittleEndian.PutUint32(four[:], uint32(chunk.storedLen))
		out.Write(four[:])
		var two [2]byte
		binary.LittleEndian.PutUint16(two[:], uint16(len(chunk.id)))
		out.Write(two[:])
		out.WriteString(chunk.id)
	}
	return base64.StdEncoding.EncodeToString(out.Bytes())
}

// decodeManifestBytes undoes the wire's base64 for the codec's own tests.
func decodeManifestBytes(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the test's own manifest is not base64: %v", err)
	}
	return raw
}
