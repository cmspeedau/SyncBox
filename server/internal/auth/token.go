// Package auth issues and checks the bearer tokens the API accepts.
//
// Tokens are self-contained: a JSON claim set, base64url encoded, followed by an
// HMAC-SHA256 over that encoding, keyed by a server secret. There is no session
// table to lose, and a restarted server keeps accepting tokens it issued before
// the restart as long as the secret is stable — which is why the secret comes
// from configuration rather than being generated at boot.
//
// This is deliberately not a general-purpose JWT implementation. It signs one
// claim set the server both mints and consumes, so it carries no algorithm
// negotiation and therefore none of the "alg: none" class of bug.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidToken means the token is malformed, not signed by this server, or
// expired. Callers must not distinguish those cases in a response, because doing
// so hands an attacker a probe.
var ErrInvalidToken = errors.New("token is not valid")

// Claims is what a token asserts.
type Claims struct {
	// Subject is the account the token belongs to. Single-user v1 always uses
	// "owner", but naming it now keeps the wire format stable for later.
	Subject string `json:"sub"`
	// IssuedAt is seconds since the Unix epoch.
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is seconds since the Unix epoch, after which Verify rejects.
	ExpiresAt int64 `json:"exp"`
}

// Issuer mints and checks tokens with one secret.
type Issuer struct {
	secret []byte
	ttl    time.Duration
}

// NewIssuer returns an issuer for the given secret and lifetime.
//
// An empty secret is replaced with 32 random bytes, which makes tokens useless
// across a restart rather than trivially forgeable. That is the safer failure,
// but it is still a failure, so config warns about it on the way in.
func NewIssuer(secret string, ttl time.Duration) *Issuer {
	key := []byte(secret)
	if len(key) == 0 {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			// rand.Read on Linux reads from the getrandom syscall and does not
			// fail in practice; if it ever did, panicking is better than
			// handing out a key we could not generate.
			panic(fmt.Sprintf("auth: cannot read random secret: %v", err))
		}
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Issuer{secret: key, ttl: ttl}
}

// TTL is how long a token issued by this issuer stays valid.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// Issue returns a token for subject, valid for the issuer's lifetime from now.
func (i *Issuer) Issue(subject string, now time.Time) (string, error) {
	claims := Claims{
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(i.ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding token claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + i.signature(encoded), nil
}

// Verify returns the claims a valid token carries.
//
// It reports ErrInvalidToken, wrapped for context, for every way a token can
// fail.
func (i *Issuer) Verify(token string, now time.Time) (*Claims, error) {
	encoded, signature, found := strings.Cut(token, ".")
	if !found || encoded == "" || signature == "" {
		return nil, fmt.Errorf("%w: wrong shape", ErrInvalidToken)
	}
	if !hmac.Equal([]byte(signature), []byte(i.signature(encoded))) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrInvalidToken, err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed claims: %v", ErrInvalidToken, err)
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("%w: no subject", ErrInvalidToken)
	}
	if now.Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	return &claims, nil
}

// ShareClaims is what a share link asserts: one file in one space, until a
// time. It is a second claim set, not a bearer token with extra fields — a link
// is held by whoever was handed it, often outside the account, so it must not
// be usable as (or forged from) one.
type ShareClaims struct {
	// VaultID is the space the shared file lives in.
	VaultID string `json:"vault"`
	// DirID and CipherName locate the file in that space, exactly as a revision
	// names it. In a sync space they are the cleartext path parts.
	DirID      string `json:"dir"`
	CipherName string `json:"name"`
	// IssuedAt and ExpiresAt are seconds since the Unix epoch.
	IssuedAt  int64 `json:"iat"`
	ExpiresAt int64 `json:"exp"`
}

// shareTag domain-separates a share link's signature from a bearer token's, so
// neither can be replayed as the other even though one secret signs both: the
// message actually signed is the tag plus the encoded payload.
const shareTag = "syncbox-share-v1\n"

// IssueShare mints a signed link to one file in one space, valid for ttl from
// now. It is deliberately narrow: the link names one item and one expiry, and
// carries nothing that would let its holder ask the server for anything else.
func (i *Issuer) IssueShare(vaultID, dirID, cipherName string, ttl time.Duration, now time.Time) (string, error) {
	if ttl <= 0 {
		return "", errors.New("a share needs a positive lifetime")
	}
	// A link that names no file could only mean "everything in the space", which
	// is not what a share is — and VerifyShare would refuse it anyway, so
	// minting one would hand out a credential that cannot be used.
	if vaultID == "" || dirID == "" || cipherName == "" {
		return "", errors.New("a share must name one file in one space")
	}
	claims := ShareClaims{
		VaultID:    vaultID,
		DirID:      dirID,
		CipherName: cipherName,
		IssuedAt:   now.Unix(),
		ExpiresAt:  now.Add(ttl).Unix(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding share claims: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return encoded + "." + i.signature(shareTag+encoded), nil
}

// VerifyShare returns the claims a valid share link carries.
//
// It reports ErrInvalidToken for every way the link can fail — malformed,
// unsigned by this server, or expired — so a holder cannot tell "wrong secret"
// from "too late", which would only help someone probing.
func (i *Issuer) VerifyShare(token string, now time.Time) (*ShareClaims, error) {
	encoded, signature, found := strings.Cut(token, ".")
	if !found || encoded == "" || signature == "" {
		return nil, fmt.Errorf("%w: wrong shape", ErrInvalidToken)
	}
	if !hmac.Equal([]byte(signature), []byte(i.signature(shareTag+encoded))) {
		return nil, fmt.Errorf("%w: signature mismatch", ErrInvalidToken)
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrInvalidToken, err)
	}
	var claims ShareClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: malformed claims: %v", ErrInvalidToken, err)
	}
	if claims.VaultID == "" || claims.DirID == "" || claims.CipherName == "" {
		return nil, fmt.Errorf("%w: a share must name a file", ErrInvalidToken)
	}
	if now.Unix() >= claims.ExpiresAt {
		return nil, fmt.Errorf("%w: expired", ErrInvalidToken)
	}
	return &claims, nil
}

// signature is the base64url HMAC-SHA256 of the encoded payload.
func (i *Issuer) signature(encoded string) string {
	mac := hmac.New(sha256.New, i.secret)
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
