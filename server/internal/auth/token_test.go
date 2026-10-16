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
