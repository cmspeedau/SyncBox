// S3 is the snapshot target for object storage, and it is where ReadOnly
// becomes real: sealing a snapshot sets COMPLIANCE-mode object-lock retention
// on every object, which no caller — not this server, not root, not the bucket
// owner — can undo before the retention date. The local target's chmod seal
// only ever promised that much against an unprivileged accident; this one
// promises it against a compromised server.
//
// The client is the S3 REST surface this package actually needs — PUT, GET,
// HEAD, DELETE, ListObjectsV2 with a delimiter, PutObjectRetention — signed
// with the hand-rolled SigV4 in this package. No multipart: what the backup
// engine writes is a metadata file, a manifest, and FastCDC-sized chunks, all
// comfortably under the single-PUT ceiling.
package target

import (
	"bytes"
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
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// S3Config locates and credentials an object-storage target. Endpoint is the
// AWS S3 endpoint when empty; set it for MinIO and friends (requests go
// path-style then, which is what those servers expect).
type S3Config struct {
	Bucket    string
	Prefix    string // optional folder inside the bucket, no slashes required
	Region    string
	Endpoint  string // e.g. http://127.0.0.1:9000 for MinIO; empty for AWS
	AccessKey string
	SecretKey string
	// LockDays is the COMPLIANCE retention applied at sealing; the bucket must
	// be versioned and have object lock enabled, or ReadOnly errors.
	LockDays int
}

// S3 stores snapshot bundles as objects in a bucket.
type S3 struct {
	cfg    S3Config
	client *http.Client
	now    func() time.Time // clock seam for tests
}

// compile-time checks.
var (
	_ Target    = (*S3)(nil)
	_ Versioned = (*S3)(nil)
)

// NewS3 validates the configuration. It performs no network I/O: a server
// starting up learns about an unreachable endpoint from the first backup, not
// by being refused boot.
func NewS3(cfg S3Config) (*S3, error) {
	cfg.Bucket = strings.TrimSpace(cfg.Bucket)
	cfg.Prefix = strings.Trim(strings.TrimSpace(cfg.Prefix), "/")
	cfg.Region = strings.TrimSpace(cfg.Region)
	cfg.Endpoint = strings.TrimSuffix(strings.TrimSpace(cfg.Endpoint), "/")
	if cfg.Bucket == "" {
		return nil, fmt.Errorf("s3 target: empty bucket")
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("s3 target: empty region")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("s3 target: missing credentials")
	}
	if cfg.Endpoint != "" {
		if _, err := url.Parse(cfg.Endpoint); err != nil {
			return nil, fmt.Errorf("s3 target endpoint %q: %w", cfg.Endpoint, err)
		}
	}
	if cfg.LockDays <= 0 {
		cfg.LockDays = 400 // past the yearly rung of the default GFS ladder
	}
	return &S3{cfg: cfg, client: &http.Client{Timeout: 5 * time.Minute}, now: time.Now}, nil
}

// Location names the bucket (and prefix) for logs and command output.
func (s *S3) Location() string {
	if s.cfg.Prefix != "" {
		return "s3://" + s.cfg.Bucket + "/" + s.cfg.Prefix
	}
	return "s3://" + s.cfg.Bucket
}

// key maps a target-relative path to an object key, refusing escapes exactly
// as the local target refuses directory escapes.
func (s *S3) key(rel string) (string, error) {
	cleaned := path.Clean("/" + strings.TrimSpace(rel))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" {
		if s.cfg.Prefix == "" {
			return "", fmt.Errorf("s3 target: empty key")
		}
		return s.cfg.Prefix, nil
	}
	if s.cfg.Prefix != "" {
		return s.cfg.Prefix + "/" + cleaned, nil
	}
	return cleaned, nil
}

// urlFor builds the request URL: virtual-host style on AWS, path-style against
// an explicit endpoint (MinIO's default expectation).
func (s *S3) urlFor(key string, query url.Values) (string, error) {
	escaped := canonicalPath("/" + key)[1:] // escape segments, keep separators
	if s.cfg.Endpoint == "" {
		base := "https://" + s.cfg.Bucket + ".s3." + s.cfg.Region + ".amazonaws.com/" + escaped
		return withQuery(base, query), nil
	}
	base := s.cfg.Endpoint + "/" + s.cfg.Bucket + "/" + escaped
	return withQuery(base, query), nil
}

// withQuery renders the query with the SAME escaping the signature commits to
// (awsURIEscape: space is %20) — url.Values.Encode would send + for spaces and
// the wire would disagree with the canonical request, 403 on real S3.
func withQuery(base string, query url.Values) string {
	if len(query) == 0 {
		return base
	}
	return base + "?" + canonicalQuery(query)
}

// do issues one signed request. Reading the response body is the caller's job
// (and its closing); non-2xx responses come back as an s3Error.
func (s *S3) do(ctx context.Context, method, key string, query url.Values, body []byte, headers map[string]string) (*http.Response, error) {
	targetURL, err := s.urlFor(key, query)
	if err != nil {
		return nil, err
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, targetURL, reader)
	if err != nil {
		return nil, err
	}
	payloadHash := emptyPayloadSHA256
	if body != nil {
		sum := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(sum[:])
	}
	req.Header.Set("x-amz-content-sha256", payloadHash)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	signV4(req, payloadHash, s.cfg.Region, "s3", s.cfg.AccessKey, s.cfg.SecretKey, s.now())
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return nil, newS3Error(resp)
	}
	return resp, nil
}

// objectVersion is one entry of ListObjectVersions: a data version or a
// delete marker. A bucket with object lock always has versioning enabled, so
// every path that must name bytes exactly — sealing them, retiring them —
// speaks in versions, not keys. Retention and permanent deletion belong to a
// version; an unversioned delete on a versioned bucket merely stands up a
// marker and leaves the bytes billed and unaccounted.
type objectVersion struct {
	key          string
	versionID    string
	isDeleteMark bool
}

// listObjectVersions pages through ListObjectVersions for a prefix. It is
// deliberately NOT the delimiter-aware Entries listing: seals and retires
// need every version of every key, including the non-current ones a bucket
// keeps after replacements and delete markers.
func (s *S3) listObjectVersions(ctx context.Context, prefix string) ([]objectVersion, error) {
	var out []objectVersion
	keyMarker, versionMarker := "", ""
	for {
		query := url.Values{"versions": []string{}, "prefix": []string{prefix}}
		if keyMarker != "" {
			query.Set("key-marker", keyMarker)
			query.Set("version-id-marker", versionMarker)
		}
		resp, err := s.do(ctx, http.MethodGet, "", query, nil, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			IsTruncated         bool `xml:"IsTruncated"`
			NextKeyMarker       string
			NextVersionIdMarker string             `xml:"NextVersionIdMarker"`
			Versions            []objectVersionXML `xml:"Version"`
			DeleteMarkers       []objectVersionXML `xml:"DeleteMarker"`
		}
		decodeErr := xml.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, fmt.Errorf("decoding s3 versions response: %w", decodeErr)
		}
		for _, v := range result.Versions {
			out = append(out, objectVersion{key: v.Key, versionID: v.VersionID})
		}
		for _, v := range result.DeleteMarkers {
			out = append(out, objectVersion{key: v.Key, versionID: v.VersionID, isDeleteMark: true})
		}
		if !result.IsTruncated || result.NextKeyMarker == "" {
			return out, nil
		}
		keyMarker, versionMarker = result.NextKeyMarker, result.NextVersionIdMarker
	}
}

type objectVersionXML struct {
	Key       string `xml:"Key"`
	VersionID string `xml:"VersionId"`
}

// Write stores r at rel, replacing any previous object. On a versioned bucket
// the object's identity is the version the service created — recorded by the
// engine so Verify and Restore can read exactly these bytes again even after
// someone PUTs a newer version in front of them.
func (s *S3) Write(ctx context.Context, rel string, r io.Reader) (int64, string, error) {
	key, err := s.key(rel)
	if err != nil {
		return 0, "", err
	}
	body, err := io.ReadAll(r)
	if err != nil {
		return 0, "", err
	}
	resp, err := s.do(ctx, http.MethodPut, key, nil, body, nil)
	if err != nil {
		return 0, "", err
	}
	// The version header answers the PUT; the (empty) body must still be
	// closed or the connection is never reused.
	version := resp.Header.Get("x-amz-version-id")
	resp.Body.Close()
	return int64(len(body)), version, nil
}

// Read opens rel; the caller closes the returned reader.
func (s *S3) Read(ctx context.Context, rel string) (io.ReadCloser, error) {
	key, err := s.key(rel)
	if err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, key, nil, nil, nil)
	if err != nil {
		if errorIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("s3 target: %s: %w", rel, ErrNotFound)
		}
		return nil, err
	}
	return resp.Body, nil
}

// ReadVersion opens one pinned version. This is the seam that turns the
// object-lock promise inside out for readers: even with a newer version
// standing in front of the object, the bytes the snapshot sealed are the
// bytes restore gets.
func (s *S3) ReadVersion(ctx context.Context, rel, versionID string) (io.ReadCloser, error) {
	key, err := s.key(rel)
	if err != nil {
		return nil, err
	}
	resp, err := s.do(ctx, http.MethodGet, key, url.Values{"versionId": []string{versionID}}, nil, nil)
	if err != nil {
		if errorIs(err, http.StatusNotFound) {
			return nil, fmt.Errorf("s3 target: %s (version %s): %w", rel, versionID, ErrNotFound)
		}
		return nil, err
	}
	return resp.Body, nil
}

// Exists reports whether rel is present; a 404 is absence, anything else is
// the error's to explain.
func (s *S3) Exists(ctx context.Context, rel string) (bool, error) {
	_, err := s.Size(ctx, rel)
	switch {
	case err == nil:
		return true, nil
	case errorIs(err, http.StatusNotFound):
		return false, nil
	default:
		return false, err
	}
}

// Size returns the object's length.
func (s *S3) Size(ctx context.Context, rel string) (int64, error) {
	key, err := s.key(rel)
	if err != nil {
		return 0, err
	}
	resp, err := s.do(ctx, http.MethodHead, key, nil, nil, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.ContentLength, nil
}

// Entries lists the immediate children of a directory, sorted — implemented
// with the delimiter so deep trees never round-trip their whole key space.
func (s *S3) Entries(ctx context.Context, rel string) ([]string, error) {
	prefixKey, err := s.key(rel)
	if err != nil {
		return nil, err
	}
	directory := prefixKey + "/"
	seen := map[string]bool{}
	keys, prefixes, err := s.list(ctx, directory, "/")
	if err != nil {
		return nil, err
	}
	for _, p := range prefixes {
		child := strings.TrimSuffix(strings.TrimPrefix(p, directory), "/")
		if child != "" {
			seen[child] = true
		}
	}
	for _, k := range keys {
		child := strings.TrimPrefix(k, directory)
		if i := strings.Index(child, "/"); i >= 0 {
			child = child[:i] // a deeper key still means this directory child
		}
		if child != "" {
			seen[child] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

// ReadOnly seals every version of every object under rel with COMPLIANCE
// retention, naming each version id so the lock lands on the exact bytes the
// snapshot promised (version-targeted calls are also the only portable way
// across services). On a bucket without object lock enabled the storage
// service refuses, and this errors — a seal that did not seal is worse than
// no seal at all.
func (s *S3) ReadOnly(ctx context.Context, rel string) error {
	prefixKey, err := s.key(rel)
	if err != nil {
		return err
	}
	versions, err := s.listObjectVersions(ctx, prefixKey+"/")
	if err != nil {
		return err
	}
	// The object-retention document schema — Mode plus an absolute
	// RetainUntilDate, NOT the bucket rule's Days/Years shape. MinIO answers
	// a wrong-schema body with 200 and applies nothing (caught live on the
	// drill); strict parsing here is what turns that silent lie into noise.
	retainUntil := s.now().UTC().AddDate(0, 0, s.cfg.LockDays).Format("2006-01-02T15:04:05Z")
	retention := []byte(fmt.Sprintf(
		"<Retention xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Mode>COMPLIANCE</Mode>"+
			"<RetainUntilDate>%s</RetainUntilDate></Retention>", retainUntil))
	// PutObjectRetention demands a Content-MD5 of the body — a real-service
	// rule the seal must satisfy.
	sum := md5.Sum(retention)
	headers := map[string]string{
		"Content-Type": "application/xml",
		"Content-MD5":  base64.StdEncoding.EncodeToString(sum[:]),
	}
	sealed := 0
	for _, version := range versions {
		if version.isDeleteMark {
			continue // nothing behind a marker to protect
		}
		resp, err := s.do(ctx, http.MethodPut, version.key,
			url.Values{"retention": []string{}, "versionId": []string{version.versionID}},
			retention, headers)
		if err != nil {
			return fmt.Errorf("sealing s3://%s/%s (version %s): %w", s.cfg.Bucket, version.key, version.versionID, err)
		}
		resp.Body.Close() // the 2xx answer must be drained to reuse the connection
		sealed++
	}
	if sealed == 0 {
		return fmt.Errorf("s3 target: nothing to seal under %s/%s: %w", s.cfg.Bucket, prefixKey, ErrNotFound)
	}
	return nil
}

// RemoveAll is the maintenance path: it permanently deletes every version of
// every object under rel, which is the only way to actually retire a snapshot
// — an unversioned delete would merely stand up a delete marker and leave the
// billed bytes haunting the bucket. While any version's retention is live the
// refusal is the system working, so it surfaces as ErrRetained — which Prune
// treats as "not yet", not as failure.
func (s *S3) RemoveAll(ctx context.Context, rel string) error {
	prefixKey, err := s.key(rel)
	if err != nil {
		return err
	}
	versions, err := s.listObjectVersions(ctx, prefixKey+"/")
	if err != nil {
		return err
	}
	for _, version := range versions {
		resp, err := s.do(ctx, http.MethodDelete, version.key,
			url.Values{"versionId": []string{version.versionID}}, nil, nil)
		if err != nil {
			if errorIs(err, http.StatusForbidden) {
				return fmt.Errorf("s3://%s/%s (version %s): %w: %v", s.cfg.Bucket, version.key, version.versionID, ErrRetained, err)
			}
			if errorIs(err, http.StatusNotFound) {
				continue // someone already retired it; the goal stands
			}
			return err
		}
		resp.Body.Close()
	}
	return nil
}

// list pages through ListObjectsV2 for a prefix, with an optional delimiter;
// it returns object keys and, delimiter-set, common prefixes.
func (s *S3) list(ctx context.Context, prefix, delimiter string) (keys, prefixes []string, err error) {
	token := ""
	for {
		query := url.Values{"list-type": []string{"2"}, "prefix": []string{prefix}}
		if delimiter != "" {
			query.Set("delimiter", delimiter)
		}
		if token != "" {
			query.Set("continuation-token", token)
		}
		resp, err := s.do(ctx, http.MethodGet, "", query, nil, nil)
		if err != nil {
			// Listing the bucket root: the key must be empty, which s.key
			// would refuse — do() on "" is deliberate and safe here.
			return nil, nil, err
		}
		var result struct {
			IsTruncated           bool   `xml:"IsTruncated"`
			NextContinuationToken string `xml:"NextContinuationToken"`
			Contents              []struct {
				Key string `xml:"Key"`
			} `xml:"Contents"`
			CommonPrefixes []struct {
				Prefix string `xml:"Prefix"`
			} `xml:"CommonPrefixes"`
		}
		decodeErr := xml.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		if decodeErr != nil {
			return nil, nil, fmt.Errorf("decoding s3 list response: %w", decodeErr)
		}
		for _, object := range result.Contents {
			keys = append(keys, object.Key)
		}
		for _, p := range result.CommonPrefixes {
			prefixes = append(prefixes, p.Prefix)
		}
		if !result.IsTruncated || result.NextContinuationToken == "" {
			return keys, prefixes, nil
		}
		token = result.NextContinuationToken
	}
}

// s3Error is a refused request with the service's error code and message
// attached, so callers can match on status without string-matching messages —
// and operators see the reason the service actually gave (the object-lock
// refusal reads "Bucket has no object lock specified..." only in the body).
type s3Error struct {
	status  int
	code    string
	message string
}

func (e *s3Error) Error() string {
	switch {
	case e.code != "" && e.message != "":
		return fmt.Sprintf("s3: %d %s: %s", e.status, e.code, e.message)
	case e.code != "":
		return fmt.Sprintf("s3: %d %s", e.status, e.code)
	default:
		return fmt.Sprintf("s3: HTTP %d", e.status)
	}
}

func newS3Error(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	err := &s3Error{status: resp.StatusCode}
	var parsed struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(body, &parsed) == nil {
		err.code, err.message = parsed.Code, parsed.Message
	}
	return err
}

// errorIs matches an s3Error by HTTP status — the kind the wire actually
// carries. (Go's errors.Is against oserror codes would miss it: S3 speaks
// statuses, not errno.)
func errorIs(err error, status int) bool {
	var e *s3Error
	if !errors.As(err, &e) {
		return false
	}
	return e.status == status
}
