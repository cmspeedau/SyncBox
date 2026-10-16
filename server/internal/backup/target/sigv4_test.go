// SigV4 against the official AWS test suite.
//
// Every expected signature below is copied verbatim from the .authz file of
// rhymu8354/aws-sig-v4-test-suite (the suite AWS uses to test its own SDKs):
// get-vanilla, normalize-path/get-space, and get-header-value-trim. The suite's
// fixed clock (20150830T123600Z), credentials (AKIDEXAMPLE), region and service
// ("us-east-1", "service") are used unchanged, so any disagreement between our
// canonicalization and AWS's fails a test rather than a bucket.
package target

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"testing"
	"time"
)

var (
	suiteNow    = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	suiteCreds  = [2]string{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	suiteTarget = [2]string{"us-east-1", "service"}
)

func signSuiteRequest(t *testing.T, method, rawPath string, headers [][2]string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://example.amazonaws.com", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.URL.Path = rawPath
	for _, h := range headers {
		req.Header.Set(h[0], h[1])
	}
	payload := sha256.Sum256(nil)
	signV4(req, hex.EncodeToString(payload[:]), suiteTarget[0], suiteTarget[1], suiteCreds[0], suiteCreds[1], suiteNow)
	return req
}

func assertSuiteSignature(t *testing.T, req *http.Request, wantSignature, wantSignedHeaders string) {
	t.Helper()
	authz := req.Header.Get("Authorization")
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=" +
		wantSignedHeaders + ", Signature=" + wantSignature
	if authz != want {
		t.Errorf("Authorization mismatch\n got %s\nwant %s", authz, want)
	}
}

func TestSigV4Vanilla(t *testing.T) {
	req := signSuiteRequest(t, "GET", "/", nil)
	// get-vanilla/.authz
	assertSuiteSignature(t, req,
		"5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		"host;x-amz-date")
}

func TestSigV4PathSpace(t *testing.T) {
	// normalize-path/get-space: "/example space/" must canonicalize to
	// "/example%20space/" — the exact rule a snapshot key containing a space
	// lives by.
	req := signSuiteRequest(t, "GET", "/example space/", nil)
	// get-space/.authz
	assertSuiteSignature(t, req,
		"652487583200325589f1fba4c7e578f72c47cb61beeca81406b39ddec1366741",
		"host;x-amz-date")
}

func TestSigV4HeaderValueTrim(t *testing.T) {
	// get-header-value-trim: values arrive padded and internally ragged; the
	// canonical form is trimmed with inner runs collapsed, and quoted content
	// is left alone.
	req := signSuiteRequest(t, "GET", "/", [][2]string{
		{"my-header1", "  value1  "},
		{"my-header2", " \"a   b\t\tc\" "},
	})
	// get-header-value-trim/.authz
	assertSuiteSignature(t, req,
		"acc3ed3afb60bb290fc8d2dd0098b9911fcaa05412b367055dee359757a9c736",
		"host;my-header1;my-header2;x-amz-date")
}

func TestCanonicalQuery(t *testing.T) {
	// Sorted by encoded key; space is %20 (never +); "/" inside a value is
	// %2F — the two ways a hand-built query silently mismatches S3.
	values := url.Values{
		"prefix":      {"snapshots/2026 one"},
		"list-type":   {"2"},
		"delimiter":   {"/"},
		"marker-less": {""},
	}
	want := "delimiter=%2F&list-type=2&marker-less=&prefix=snapshots%2F2026%20one"
	if got := canonicalQuery(values); got != want {
		t.Errorf("canonicalQuery:\n got %s\nwant %s", got, want)
	}
}

func TestCanonicalPathKeepsSeparators(t *testing.T) {
	if got := canonicalPath("/a b/c~d/e+f/g%h/"); got != "/a%20b/c~d/e%2Bf/g%25h/" {
		t.Errorf("canonicalPath got %s", got)
	}
	if got := canonicalPath(""); got != "/" {
		t.Errorf("empty path must canonicalize to /, got %s", got)
	}
}
