package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIssueAndVerifyRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-test-secret", time.Hour)

	token, err := issuer.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	claims, err := issuer.Verify(token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "owner" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "owner")
	}
	if claims.ExpiresAt != now.Add(time.Hour).Unix() {
		t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt, now.Add(time.Hour).Unix())
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-test-secret", time.Hour)

	good, err := issuer.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	tampered := good[:len(good)-2] + "ab"
	longer := good + "." + good

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "no separator", token: "just-a-blob"},
		{name: "empty signature", token: "payload."},
		{name: "flipped signature", token: tampered},
		{name: "extra segment", token: longer},
		{name: "payload only", token: strings.Split(good, ".")[0]},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := issuer.Verify(test.token, now); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("Verify(%q) = %v, want ErrInvalidToken", test.token, err)
			}
		})
	}
}

func TestVerifyRejectsAfterExpiry(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-test-secret", time.Hour)

	token, err := issuer.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Still valid one second before the deadline, rejected once it passes. The
	// boundary matters: a client that refreshes at exactly the expiry must not be
	// refused for a request it started in time, and an expired token must not be
	// accepted for one extra second.
	if _, err := issuer.Verify(token, now.Add(time.Hour-time.Second)); err != nil {
		t.Errorf("Verify just before expiry: %v", err)
	}
	if _, err := issuer.Verify(token, now.Add(time.Hour)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("Verify at expiry = %v, want ErrInvalidToken", err)
	}
}

func TestTokensFromDifferentSecretsDoNotInteroperate(t *testing.T) {
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	first := NewIssuer("secret-one", time.Hour)
	second := NewIssuer("secret-two", time.Hour)

	token, err := first.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := second.Verify(token, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a token from another secret verified: %v", err)
	}
}

func TestClaimsFromAnotherServerAreNotTrusted(t *testing.T) {
	// A client can build its own payload with a far-future expiry; without the
	// secret it still cannot sign it, which is the whole point of the HMAC.
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-test-secret", time.Hour)

	forged := `eyJzdWIiOiJvd25lciIsImlhdCI6MCwiZXhwIjo5OTk5OTk5OTk5OX0.` +
		`AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`
	if _, err := issuer.Verify(forged, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("forged claim set verified: %v", err)
	}
}

func TestEmptySecretStillProducesVerifiableTokens(t *testing.T) {
	// An unset secret generates a random key. Tokens must be usable within the
	// process and unusable after a restart, which is the safe failure.
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("", time.Hour)

	token, err := issuer.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := issuer.Verify(token, now); err != nil {
		t.Fatalf("Verify with generated secret: %v", err)
	}

	restarted := NewIssuer("", time.Hour)
	if _, err := restarted.Verify(token, now); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("token survived a restart with a new secret: %v", err)
	}
}

// A share link is a second kind of credential, and the security property that
// matters is that the two kinds cannot be confused: a link held by a stranger
// must not open anything but the one file it names, and a token must not be
// mintable from a link (or the reverse) by anyone who can see either.
func TestShareRoundTrip(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-share-secret", time.Hour)

	token, err := issuer.IssueShare("ABCDEFGH", "00", "notes.txt", 24*time.Hour, now)
	if err != nil {
		t.Fatalf("IssueShare: %v", err)
	}
	claims, err := issuer.VerifyShare(token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("VerifyShare: %v", err)
	}
	if claims.VaultID != "ABCDEFGH" || claims.DirID != "00" || claims.CipherName != "notes.txt" {
		t.Errorf("claims = %+v, want the file the link was minted for", claims)
	}
	if claims.ExpiresAt != now.Add(24*time.Hour).Unix() {
		t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt, now.Add(24*time.Hour).Unix())
	}
}

func TestShareLinksExpire(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-share-secret", time.Hour)

	token, err := issuer.IssueShare("ABCDEFGH", "00", "notes.txt", time.Minute, now)
	if err != nil {
		t.Fatalf("IssueShare: %v", err)
	}
	if _, err := issuer.VerifyShare(token, now.Add(90*time.Second)); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("an expired link = %v, want ErrInvalidToken", err)
	}
}

func TestShareLinksFromDifferentSecretsDoNotInteroperate(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minted, err := NewIssuer("secret-one", time.Hour).IssueShare("V", "00", "n.txt", time.Hour, now)
	if err != nil {
		t.Fatalf("IssueShare: %v", err)
	}
	if _, err := NewIssuer("secret-two", time.Hour).VerifyShare(minted, now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("another server's link = %v, want ErrInvalidToken", err)
	}
}

// The domain-separation test: neither kind of credential passes for the other,
// even on the same server with the same secret.
func TestAShareLinkIsNotABearerTokenAndBack(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("one-secret-for-both", time.Hour)

	share, err := issuer.IssueShare("ABCDEFGH", "00", "notes.txt", time.Hour, now)
	if err != nil {
		t.Fatalf("IssueShare: %v", err)
	}
	bearer, err := issuer.Issue("owner", now)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if _, err := issuer.Verify(share, now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a share link as a bearer token = %v, want ErrInvalidToken", err)
	}
	if _, err := issuer.VerifyShare(bearer, now); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("a bearer token as a share link = %v, want ErrInvalidToken", err)
	}
}

func TestShareLinksAreRejectedForShapeAndEmptiness(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	issuer := NewIssuer("a-share-secret", time.Hour)

	token, err := issuer.IssueShare("ABCDEFGH", "00", "notes.txt", time.Hour, now)
	if err != nil {
		t.Fatalf("IssueShare: %v", err)
	}
	for _, broken := range []string{
		"",
		"no-separator",
		"payload.",
		token + "." + token,
		token[:len(token)-2] + "zz",
	} {
		if _, err := issuer.VerifyShare(broken, now); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("VerifyShare(%q) = %v, want ErrInvalidToken", broken, err)
		}
	}

	// A link that names no file is not a link: it could only mean "everything".
	if _, err := issuer.IssueShare("ABCDEFGH", "", "", time.Hour, now); err == nil {
		t.Error("IssueShare accepted an empty file name")
	}
	// And a lifetime of zero or less would be a link that never worked, or one
	// that never ends; both are refused at the mint.
	for _, ttl := range []time.Duration{0, -time.Minute} {
		if _, err := issuer.IssueShare("ABCDEFGH", "00", "n.txt", ttl, now); err == nil {
			t.Errorf("IssueShare accepted a lifetime of %s", ttl)
		}
	}
}
