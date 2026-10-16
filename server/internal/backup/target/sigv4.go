// AWS Signature Version 4, the authentication every S3-compatible endpoint
// speaks.
//
// This is deliberately hand-rolled rather than a dependency: the server's go.mod
// is a deliberate fact ("modernc sqlite is the largest thing here"), and SigV4
// is a small, fully-specified algorithm whose official test vectors are
// reproduced in `sigv4_test.go` — the same vector-pinned discipline the crypto
// crate uses, applied to a wire protocol. Only what the backup target needs is
// implemented: header-signed requests (as opposed to presigned query URLs),
// static credentials, and the exact path/query canonicalization S3 requires.

package target

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	sigV4Algorithm = "AWS4-HMAC-SHA256"
	// emptyPayloadSHA256 is the hex SHA-256 of zero bytes, which GET/HEAD/DELETE
	// requests sign as their payload.
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// signV4 signs req in place for service (always "s3" here) in region with
// static credentials, at time now. Every header present on req when it is
// called participates in the signature, so callers must set all of them
// (host and x-amz-* included) before signing.
func signV4(req *http.Request, payloadHash, region, service, accessKey, secretKey string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := amzDate[:8]
	req.Header.Set("x-amz-date", amzDate)

	var signed []string
	for name := range req.Header {
		if !strings.EqualFold(name, "authorization") {
			signed = append(signed, strings.ToLower(name))
		}
	}
	signed = append(signed, "host")
	sort.Strings(signed)
	// "host" is not in Header on a fresh request, but it is always first in
	// sorted order ahead of any x-* name we set; deduplicate in case a caller
	// set it explicitly.
	signed = dedupe(signed)

	var canon strings.Builder
	for _, name := range signed {
		value := req.Host
		if name != "host" {
			value = req.Header.Get(name)
		}
		canon.WriteString(name)
		canon.WriteByte(':')
		canon.WriteString(canonicalHeaderValue(value))
		canon.WriteByte('\n')
	}
	signedHeaders := strings.Join(signed, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalPath(req.URL.Path),
		canonicalQuery(req.URL.Query()),
		canon.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	hashedRequest := sha256.Sum256([]byte(canonicalRequest))
	stringToSign := strings.Join([]string{
		sigV4Algorithm,
		amzDate,
		scope,
		hex.EncodeToString(hashedRequest[:]),
	}, "\n")

	key := hmacSHA256([]byte("AWS4"+secretKey), dateStamp)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, stringToSign))

	req.Header.Set("Authorization", sigV4Algorithm+
		" Credential="+accessKey+"/"+scope+
		", SignedHeaders="+signedHeaders+
		", Signature="+signature)
}

// canonicalPath URI-escapes each path segment per the AWS rules (everything
// outside the unreserved set A-Za-z0-9-_.~ becomes %XX; the segment separators
// survive) — the step that turns "/example space/" into "/example%20space/".
func canonicalPath(p string) string {
	if p == "" {
		return "/"
	}
	segments := strings.Split(p, "/")
	for i, segment := range segments {
		segments[i] = awsURIEscape(segment, false)
	}
	return strings.Join(segments, "/")
}

// canonicalQuery renders query parameters sorted by encoded key (then value),
// each key and value escaped per the AWS rules — note that unlike
// application/x-www-form-urlencoded, a space is %20, never +, and a value-less
// parameter keeps its "key=".
func canonicalQuery(values url.Values) string {
	var pairs []string
	for key, list := range values {
		encodedKey := awsURIEscape(key, true)
		if len(list) == 0 {
			pairs = append(pairs, encodedKey+"=")
		}
		for _, value := range list {
			pairs = append(pairs, encodedKey+"="+awsURIEscape(value, true))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaderValue trims outer whitespace and collapses inner whitespace
// runs to one space, per the canonical-headers rule.
func canonicalHeaderValue(value string) string {
	fields := strings.Fields(value)
	return strings.Join(fields, " ")
}

// awsURIEscape percent-escapes everything the unreserved set excludes. With
// encodeSlash, "/" is escaped too (query parameters); path segments keep it.
func awsURIEscape(s string, encodeSlash bool) string {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			out.WriteByte(c)
		case c == '/' && !encodeSlash:
			out.WriteByte(c)
		default:
			const hexDigits = "0123456789ABCDEF"
			out.WriteByte('%')
			out.WriteByte(hexDigits[c>>4])
			out.WriteByte(hexDigits[c&0x0f])
		}
	}
	return out.String()
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func dedupe(sorted []string) []string {
	out := sorted[:0]
	for i, value := range sorted {
		if i == 0 || value != sorted[i-1] {
			out = append(out, value)
		}
	}
	return out
}
