// The S3 target tested against a stand-in that keeps the wire honest: paths
// are path-style like MinIO's, ListObjectsV2 paginates and honors the
// delimiter, every request's x-amz-content-sha256 is checked against the body
// actually received, and objects are version stacks like a real versioned
// bucket: a PUT always lands as a new version (even over a COMPLIANCE-locked
// one — the drill watched mc cp do exactly that), retention lands on named
// versions, sealed versions refuse deletion, and a pinned GET answers from the
// version it names. So a signing/payload mismatch, a lost version identity or
// a seal that misses a version fails here instead of at a bucket.
package target

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fversion is one stored version of an object, as a versioned bucket stores
// them: a stack per key where a PUT pushes and only deletes pop.
type fversion struct {
	id     string
	body   []byte
	retain time.Time // zero = never sealed
}

type fakeS3 struct {
	mu          sync.Mutex
	objects     map[string][]fversion // key -> versions, oldest first
	deleteMarks map[string]bool       // key -> a delete marker stands where the object was
	lockable    bool
	now         func() time.Time
	// versionlessSealCalls counts retention PUTs that named no version —
	// kind of the live service to honor, unforgivable on stricter ones, so
	// the client must never make one.
	versionlessSealCalls int
	versionSeq           map[string]int
}

func newFake(lockable bool) *fakeS3 {
	return &fakeS3{
		objects:     map[string][]fversion{},
		deleteMarks: map[string]bool{},
		lockable:    lockable,
		now:         time.Now,
		versionSeq:  map[string]int{},
	}
}

// current returns the version an unpinned read sees: the top of the stack,
// gone if a delete marker stands over it.
func (f *fakeS3) current(key string) (fversion, bool) {
	versions := f.objects[key]
	if len(versions) == 0 || f.deleteMarks[key] {
		return fversion{}, false
	}
	return versions[len(versions)-1], true
}

func (f *fakeS3) version(key, id string) (fversion, bool) {
	for _, v := range f.objects[key] {
		if v.id == id {
			return v, true
		}
	}
	return fversion{}, false
}

func (f *fakeS3) retained(v fversion) bool {
	return !v.retain.IsZero() && f.now().Before(v.retain)
}

// sealedCount reports how many stored versions currently live under retention.
func (f *fakeS3) sealedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, versions := range f.objects {
		for _, v := range versions {
			if f.retained(v) {
				n++
			}
		}
	}
	return n
}

func writeS3Error(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, "<Error><Code>%s</Code><Message>fake</Message></Error>", code)
}

func (f *fakeS3) serve(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		// Every request must arrive signed with the suite-style credential,
		// and carry a payload hash matching the bytes actually received.
		if authz := r.Header.Get("Authorization"); !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 Credential=AKIDTEST/") {
			t.Errorf("missing or wrong Authorization header: %q", authz)
			writeS3Error(w, http.StatusForbidden, "AccessDenied")
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}
		sum := sha256.Sum256(body)
		if got := r.Header.Get("x-amz-content-sha256"); got != hex.EncodeToString(sum[:]) {
			t.Errorf("payload hash mismatch: header %s, body %x", got, sum[:])
			writeS3Error(w, http.StatusBadRequest, "XAmzContentSHA256Mismatch")
			return
		}

		const bucketPrefix = "/snapshots-bucket/"
		if !strings.HasPrefix(r.URL.Path, bucketPrefix) {
			writeS3Error(w, http.StatusNotFound, "NoSuchBucket")
			return
		}
		key := strings.TrimPrefix(r.URL.Path, bucketPrefix)

		f.mu.Lock()
		defer f.mu.Unlock()

		switch {
		case r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" && key == "":
			f.list(w, r)
		case r.Method == http.MethodGet && r.URL.Query().Has("versions") && key == "":
			f.listVersions(t, w, r)
		case r.Method == http.MethodPut && r.URL.Query().Has("retention"):
			if !f.lockable {
				writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
				return
			}
			// The real service requires a Content-MD5 on PutObjectRetention,
			// so the stand-in does too: a seal that stops sending it fails
			// here before it fails at a bucket.
			sum := md5.Sum(body)
			if got := r.Header.Get("Content-MD5"); got != base64.StdEncoding.EncodeToString(sum[:]) {
				writeS3Error(w, http.StatusBadRequest, "MissingContentMD5")
				return
			}
			// Retention lands on the named version. MinIO applies a
			// versionless call to the current version; the counter below
			// exists because not every service is that kind, and a seal
			// that stopped naming versions would be silently refused
			// somewhere else.
			requested := r.URL.Query().Get("versionId")
			if requested == "" {
				f.versionlessSealCalls++
				latest, ok := f.current(key)
				if !ok {
					writeS3Error(w, http.StatusNotFound, "NoSuchKey")
					return
				}
				requested = latest.id
			}
			stored, ok := f.version(key, requested)
			if !ok {
				writeS3Error(w, http.StatusNotFound, "NoSuchVersion")
				return
			}
			if f.retained(stored) {
				writeS3Error(w, http.StatusForbidden, "AccessDenied") // COMPLIANCE is not re-pointable
				return
			}
			var doc struct {
				XMLName         xml.Name `xml:"Retention"`
				Mode            string   `xml:"Mode"`
				RetainUntilDate string   `xml:"RetainUntilDate"`
			}
			if err := xml.Unmarshal(body, &doc); err != nil {
				t.Fatalf("decoding retention document: %v", err)
			}
			// Strict about the real object schema: Mode + RetainUntilDate.
			// The rule/Days shape the client once sent used to sail through
			// here exactly as it sailed through MinIO.
			if doc.Mode != "COMPLIANCE" && doc.Mode != "GOVERNANCE" {
				t.Errorf("retention body must name Mode, got %q", doc.Mode)
				writeS3Error(w, http.StatusBadRequest, "MalformedXML")
				return
			}
			until, parseErr := time.Parse("2006-01-02T15:04:05Z", doc.RetainUntilDate)
			if parseErr != nil {
				t.Errorf("retention body must carry a RetainUntilDate, got %q", doc.RetainUntilDate)
				writeS3Error(w, http.StatusBadRequest, "MalformedXML")
				return
			}
			f.setRetention(key, requested, until)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			// A versioned bucket takes every PUT: even a COMPLIANCE-locked
			// current version cannot stop a NEW version from standing up in
			// front of it (the drill proved it with mc cp). What the lock
			// protects is the sealed version's bytes, not the key's name.
			f.versionSeq[key]++
			id := fmt.Sprintf("v%03d", f.versionSeq[key])
			f.objects[key] = append(f.objects[key], fversion{id: id, body: body})
			delete(f.deleteMarks, key) // a new version stands as current
			w.Header().Set("x-amz-version-id", id)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet:
			if requested := r.URL.Query().Get("versionId"); requested != "" {
				stored, ok := f.version(key, requested)
				if !ok {
					writeS3Error(w, http.StatusNotFound, "NoSuchVersion")
					return
				}
				w.Header().Set("x-amz-version-id", stored.id)
				w.Header().Set("Content-Length", strconv.Itoa(len(stored.body)))
				_, _ = w.Write(stored.body)
				return
			}
			object, ok := f.current(key)
			if !ok {
				writeS3Error(w, http.StatusNotFound, "NoSuchKey")
				return
			}
			w.Header().Set("x-amz-version-id", object.id)
			w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
			_, _ = w.Write(object.body)
		case r.Method == http.MethodHead:
			object, ok := f.current(key)
			if !ok {
				writeS3Error(w, http.StatusNotFound, "NoSuchKey")
				return
			}
			w.Header().Set("x-amz-version-id", object.id)
			w.Header().Set("Content-Length", strconv.Itoa(len(object.body)))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodDelete:
			requested := r.URL.Query().Get("versionId")
			if requested == "" {
				// Unversioned delete on a versioned bucket only stands up a
				// delete marker: the bytes stay billed, visible to
				// ListObjectVersions, unreachable to Read.
				if _, ok := f.objects[key]; ok {
					f.deleteMarks[key] = true
				}
				w.WriteHeader(http.StatusNoContent) // real S3: even for absent keys
				return
			}
			if requested == deleteMarkerID {
				delete(f.deleteMarks, key) // retiring the marker itself
				w.WriteHeader(http.StatusNoContent)
				return
			}
			stored, ok := f.version(key, requested)
			if !ok {
				writeS3Error(w, http.StatusNotFound, "NoSuchVersion")
				return
			}
			if f.retained(stored) {
				writeS3Error(w, http.StatusForbidden, "AccessDenied")
				return
			}
			versions := f.objects[key]
			for i, v := range versions {
				if v.id == requested {
					f.objects[key] = append(versions[:i], versions[i+1:]...)
					break
				}
			}
			if len(f.objects[key]) == 0 {
				delete(f.objects, key)
				delete(f.versionSeq, key)
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			writeS3Error(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		}
	}
}

// deleteMarkerID names the one delete marker a key can wear, as
// ListObjectVersions reports it.
const deleteMarkerID = "delete-marker-1"

func (f *fakeS3) setRetention(key, versionID string, until time.Time) {
	versions := f.objects[key]
	for i, v := range versions {
		if v.id == versionID {
			versions[i].retain = until
			return
		}
	}
}

// list answers ListObjectsV2 honoring the delimiter, returning at most two
// entries per page with an opaque continuation token — so the client's paging
// loop runs on every listing, and the token never leaks into the client's
// semantics (it must survive it being anything).
func (f *fakeS3) list(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	delimiter := query.Get("delimiter")
	start := 0
	if token := query.Get("continuation-token"); token != "" {
		start, _ = strconv.Atoi(token)
	}

	var keys []string
	for key := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if _, ok := f.current(key); !ok {
			continue // covered by a delete marker: invisible to a listing
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// Merge into the page's entry list: with a delimiter, keys under a
	// sub-directory collapse to their CommonPrefix.
	type entry struct {
		key, commonPrefix string
	}
	var entries []entry
	seenDir := map[string]bool{}
	for _, key := range keys {
		rest := strings.TrimPrefix(key, prefix)
		if delimiter != "" && strings.Contains(rest, delimiter) {
			dir := prefix + strings.SplitN(rest, delimiter, 2)[0] + delimiter
			if !seenDir[dir] {
				seenDir[dir] = true
				entries = append(entries, entry{key: dir, commonPrefix: dir})
			}
			continue
		}
		entries = append(entries, entry{key: key})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	page := entries
	truncated := false
	if len(page[start:]) > 2 {
		page, truncated = entries[start:start+2], true
	} else {
		page = entries[start:]
	}
	nextToken := ""
	if truncated {
		nextToken = strconv.Itoa(start + 2)
	}

	w.Header().Set("Content-Type", "application/xml")
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	fmt.Fprintf(&out, `<Name>snapshots-bucket</Name><Prefix>%s</Prefix><IsTruncated>%v</IsTruncated>`, prefix, truncated)
	if truncated {
		fmt.Fprintf(&out, `<NextContinuationToken>%s</NextContinuationToken>`, nextToken)
	}
	for _, e := range page {
		if e.commonPrefix != "" {
			fmt.Fprintf(&out, `<CommonPrefixes><Prefix>%s</Prefix></CommonPrefixes>`, e.commonPrefix)
		} else {
			fmt.Fprintf(&out, `<Contents><Key>%s</Key><Size>1</Size></Contents>`, e.key)
		}
	}
	out.WriteString(`</ListBucketResult>`)
	_, _ = io.WriteString(w, out.String())
}

// listVersions answers ListObjectVersions: every stored version of every key
// (oldest first, like the service's per-key ordering), plus any delete
// markers, two entries per page with key-marker/version-id-marker
// continuation — so the client's version paging runs on every listing and
// cannot quietly skip a version that shares a key with a returned one.
func (f *fakeS3) listVersions(t *testing.T, w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	prefix := query.Get("prefix")
	keyMarker, versionMarker := query.Get("key-marker"), query.Get("version-id-marker")

	type entry struct {
		key, versionID string
		marker         bool
	}
	var entries []entry
	for key := range f.objects {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		for _, v := range f.objects[key] {
			entries = append(entries, entry{key: key, versionID: v.id})
		}
	}
	for key := range f.deleteMarks {
		if strings.HasPrefix(key, prefix) {
			entries = append(entries, entry{key: key, versionID: deleteMarkerID, marker: true})
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].key != entries[j].key {
			return entries[i].key < entries[j].key
		}
		return entries[i].versionID < entries[j].versionID
	})
	if keyMarker != "" {
		// Continuation resumes strictly after the named (key, version)
		// pair. Exact-match resume, like the service's own marker walk.
		var kept []entry
		past := false
		for _, e := range entries {
			if past {
				kept = append(kept, e)
			} else if e.key == keyMarker && e.versionID == versionMarker {
				past = true
			}
		}
		if !past {
			t.Errorf("continuation marker (%s, %s) names no entry", keyMarker, versionMarker)
		}
		entries = kept
	}
	truncated := false
	if len(entries) > 2 {
		truncated = true
		entries = entries[:2]
	}
	lastKey, lastVersion := "", ""
	if truncated {
		lastKey, lastVersion = entries[1].key, entries[1].versionID
	}

	w.Header().Set("Content-Type", "application/xml")
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	fmt.Fprintf(&out, `<Name>snapshots-bucket</Name><Prefix>%s</Prefix><IsTruncated>%v</IsTruncated>`, prefix, truncated)
	if truncated {
		fmt.Fprintf(&out, `<NextKeyMarker>%s</NextKeyMarker><NextVersionIdMarker>%s</NextVersionIdMarker>`, lastKey, lastVersion)
	}
	for _, e := range entries {
		isLatest := "false"
		if cur, ok := f.current(e.key); ok {
			if !e.marker && cur.id == e.versionID {
				isLatest = "true" // the version an unpinned read lands on
			}
		} else if e.marker {
			isLatest = "true" // a marker with nothing above it is current
		}
		if e.marker {
			fmt.Fprintf(&out, `<DeleteMarker><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%s</IsLatest></DeleteMarker>`, e.key, e.versionID, isLatest)
		} else {
			fmt.Fprintf(&out, `<Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>%s</IsLatest></Version>`, e.key, e.versionID, isLatest)
		}
	}
	out.WriteString(`</ListVersionsResult>`)
	_, _ = io.WriteString(w, out.String())
}

func newTestS3(t *testing.T, fake *fakeS3) (*S3, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(fake.serve(t))
	s3, err := NewS3(S3Config{
		Bucket:    "snapshots-bucket",
		Prefix:    "bundles",
		Region:    "us-east-1",
		Endpoint:  server.URL,
		AccessKey: "AKIDTEST",
		SecretKey: "secret",
		LockDays:  40,
	})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	return s3, server
}

func mustWrite(t *testing.T, s3 *S3, rel, body string) string {
	t.Helper()
	_, version, err := s3.Write(context.Background(), rel, strings.NewReader(body))
	if err != nil {
		t.Fatalf("Write(%s): %v", rel, err)
	}
	return version
}

func TestS3TargetRoundTrip(t *testing.T) {
	s3, server := newTestS3(t, newFake(true))
	defer server.Close()
	ctx := context.Background()

	if v := mustWrite(t, s3, "snapshots/a/metadata.json", `{"id":"a"}`); v == "" {
		t.Error("a versioned bucket must hand back the identity of the version it made")
	}
	mustWrite(t, s3, "snapshots/a/manifest.bin", "manifest bytes")
	mustWrite(t, s3, "snapshots/b/metadata.json", `{"id":"b"}`)
	mustWrite(t, s3, "loose.bin", "no directory")

	children, err := s3.Entries(ctx, "snapshots")
	if err != nil {
		t.Fatalf("Entries(snapshots): %v", err)
	}
	if strings.Join(children, ",") != "a,b" {
		t.Errorf("Entries(snapshots) = %v, want [a b]", children)
	}
	files, err := s3.Entries(ctx, "snapshots/a")
	if err != nil {
		t.Fatalf("Entries(snapshots/a): %v", err)
	}
	if strings.Join(files, ",") != "manifest.bin,metadata.json" {
		t.Errorf("Entries(snapshots/a) = %v", files)
	}
	root, err := s3.Entries(ctx, "")
	if err != nil {
		t.Fatalf("Entries(root): %v", err)
	}
	if strings.Join(root, ",") != "loose.bin,snapshots" {
		t.Errorf("Entries(root) = %v", root)
	}

	if ok, err := s3.Exists(ctx, "snapshots/a/manifest.bin"); err != nil || !ok {
		t.Errorf("Exists present: %v %v", ok, err)
	}
	if ok, err := s3.Exists(ctx, "nope.bin"); err != nil || ok {
		t.Errorf("Exists absent: %v %v", ok, err)
	}
	if size, err := s3.Size(ctx, "snapshots/a/manifest.bin"); err != nil || size != int64(len("manifest bytes")) {
		t.Errorf("Size: %d %v", size, err)
	}
	reader, err := s3.Read(ctx, "snapshots/a/metadata.json")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	body, _ := io.ReadAll(reader)
	reader.Close()
	if string(body) != `{"id":"a"}` {
		t.Errorf("Read body = %s", body)
	}
	if _, err := s3.Read(ctx, "missing/thing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing Read = %v, want ErrNotFound", err)
	}

	if err := s3.RemoveAll(ctx, "snapshots/b"); err != nil {
		t.Fatalf("RemoveAll unsealed: %v", err)
	}
	if ok, _ := s3.Exists(ctx, "snapshots/b/metadata.json"); ok {
		t.Error("RemoveAll left an object behind")
	}
}

func TestS3SealProtectsVersionsNotKeys(t *testing.T) {
	// What object lock actually promises, as the MinIO drill observed: a
	// tamperer can always PUT a newer version in front of a sealed object,
	// but the sealed version's bytes survive — readable only by pinning it,
	// and undeletable until retention expires.
	fake := newFake(true)
	s3, server := newTestS3(t, fake)
	defer server.Close()
	ctx := context.Background()

	sealedID := mustWrite(t, s3, "snapshots/a/chunk", "chunk bytes")
	mustWrite(t, s3, "snapshots/a/metadata.json", "first")

	if err := s3.ReadOnly(ctx, "snapshots/a"); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if fake.sealedCount() != 2 {
		t.Fatalf("sealed %d versions, want 2", fake.sealedCount())
	}

	// The tamper succeeds — standing a new version up is allowed, and is
	// exactly why Verify and Restore must read by pinned version.
	if _, _, err := s3.Write(ctx, "snapshots/a/chunk", strings.NewReader("forged")); err != nil {
		t.Fatalf("writing a new version over a sealed key: %v", err)
	}
	reader, err := s3.Read(ctx, "snapshots/a/chunk")
	if err != nil {
		t.Fatalf("Read current: %v", err)
	}
	current, _ := io.ReadAll(reader)
	reader.Close()
	if string(current) != "forged" {
		t.Errorf("unpinned Read = %q, want the tamperer's bytes", current)
	}

	pinned, err := s3.ReadVersion(ctx, "snapshots/a/chunk", sealedID)
	if err != nil {
		t.Fatalf("ReadVersion: %v", err)
	}
	body, _ := io.ReadAll(pinned)
	pinned.Close()
	if string(body) != "chunk bytes" {
		t.Errorf("pinned ReadVersion = %q, want the sealed bytes", body)
	}

	// Retirement is refused while the sealed version is protected...
	if err := s3.RemoveAll(ctx, "snapshots/a"); !errors.Is(err, ErrRetained) {
		t.Fatalf("RemoveAll retained = %v, want ErrRetained", err)
	}
	// ...and succeeds once retention has passed, taking every version.
	fake.now = func() time.Time { return time.Now().AddDate(0, 0, 41) }
	if err := s3.RemoveAll(ctx, "snapshots/a"); err != nil {
		t.Fatalf("RemoveAll after retention expired: %v", err)
	}
	if ok, _ := s3.Exists(ctx, "snapshots/a/chunk"); ok {
		t.Error("expired retention must allow retirement")
	}
	if _, err := s3.ReadVersion(ctx, "snapshots/a/chunk", sealedID); !errors.Is(err, ErrNotFound) {
		t.Errorf("retired version ReadVersion = %v, want ErrNotFound", err)
	}
}

func TestS3SealNamesEveryVersion(t *testing.T) {
	// Retention belongs to a version, not a name: a key with a stack of
	// them must have each one sealed, or the older bytes sit unlocked in
	// plain sight. MinIO would honor a versionless call against the current
	// version, but the AWS contract is version-targeted and stricter
	// services refuse or misplace a bare one — the seal names every
	// version, and the counter here is the tripwire if it stops.
	fake := newFake(true)
	s3, server := newTestS3(t, fake)
	defer server.Close()

	mustWrite(t, s3, "snapshots/a/metadata.json", "first")
	mustWrite(t, s3, "snapshots/a/metadata.json", "second") // stacks, as a re-push would
	mustWrite(t, s3, "snapshots/a/manifest.bin", "y")
	if err := s3.ReadOnly(context.Background(), "snapshots/a"); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if fake.versionlessSealCalls != 0 {
		t.Errorf("seal made %d versionless retention calls, which lock nothing", fake.versionlessSealCalls)
	}
	if got := fake.sealedCount(); got != 3 {
		t.Errorf("retention landed on %d versions, want all 3", got)
	}
}

func TestS3SealOnLocklessBucketRefusesLoudly(t *testing.T) {
	s3, server := newTestS3(t, newFake(false))
	defer server.Close()

	mustWrite(t, s3, "snapshots/a/metadata.json", "x")
	err := s3.ReadOnly(context.Background(), "snapshots/a")
	if err == nil {
		t.Fatal("a bucket without object lock must not appear to seal")
	}
	if !strings.Contains(err.Error(), "MethodNotAllowed") {
		t.Errorf("seal error should name the service refusal, got %v", err)
	}
}

func TestS3PagesThroughLongListings(t *testing.T) {
	fake := newFake(true)
	s3, server := newTestS3(t, fake)
	defer server.Close()
	ctx := context.Background()

	for i := 0; i < 7; i++ {
		mustWrite(t, s3, fmt.Sprintf("many/obj-%d", i), "x")
	}
	if err := s3.ReadOnly(ctx, "many"); err != nil {
		t.Fatalf("ReadOnly across pages: %v", err)
	}
	if got := fake.sealedCount(); got != 7 {
		t.Errorf("paging sealed %d versions, want 7", got)
	}
}

func TestS3PrefixAnchorsEveryKey(t *testing.T) {
	fake := newFake(true)
	s3, server := newTestS3(t, fake)
	defer server.Close()

	mustWrite(t, s3, "snapshots/a/metadata.json", "x")
	mustWrite(t, s3, "../outside.bin", "escape attempt")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for key := range fake.objects {
		if !strings.HasPrefix(key, "bundles/") {
			t.Errorf("key %q escaped the prefix", key)
		}
	}
}

func TestS3Location(t *testing.T) {
	withPrefix := &S3{cfg: S3Config{Bucket: "b", Prefix: "p/q"}}
	if got := withPrefix.Location(); got != "s3://b/p/q" {
		t.Errorf("Location = %s", got)
	}
	bare := &S3{cfg: S3Config{Bucket: "b"}}
	if got := bare.Location(); got != "s3://b" {
		t.Errorf("Location = %s", got)
	}
}

func TestS3AWSEndpointIsVirtualHosted(t *testing.T) {
	s3, err := NewS3(S3Config{Bucket: "sync-box", Region: "eu-west-2", AccessKey: "a", SecretKey: "s"})
	if err != nil {
		t.Fatalf("NewS3: %v", err)
	}
	got, err := s3.urlFor("snapshots/a chunk/manifest.bin", nil)
	if err != nil {
		t.Fatalf("urlFor: %v", err)
	}
	want := "https://sync-box.s3.eu-west-2.amazonaws.com/snapshots/a%20chunk/manifest.bin"
	if got != want {
		t.Errorf("urlFor:\n got %s\nwant %s", got, want)
	}
}
