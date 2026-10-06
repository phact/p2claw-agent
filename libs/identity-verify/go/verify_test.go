// SPDX-License-Identifier: MIT
package identityverify

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Vector-driven test suite. Loads the shared cross-language fixture
// at libs/identity-verify/test-vectors.json and asserts:
//
//   - expect == "ok" cases  → Verify returns the expected claims
//   - expect == "err:<Variant>" cases → Verify returns *VerifyError
//     with .Kind == "<Variant>"
//
// The same JSON drives the Rust / TypeScript / Python reference libs.

type vectorCase struct {
	Name           string                 `json:"name"`
	Token          string                 `json:"token"`
	VerifyAt       int64                  `json:"verify_at"`
	Expect         string                 `json:"expect"`
	ExpectedClaims map[string]interface{} `json:"expected_claims,omitempty"`
}

type vectorFile struct {
	SpecVersion   string       `json:"spec_version"`
	TrustedPeerID string       `json:"trusted_peer_id"`
	Cases         []vectorCase `json:"cases"`
}

func loadFixture(t *testing.T) vectorFile {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// Canonical fixture is owned by native-dev's Rust gen-vectors binary.
	// Falls back to the TS placeholder if canonical isn't yet on disk.
	canonical := filepath.Join(wd, "..", "test-vectors.json")
	placeholder := filepath.Join(wd, "..", "ts", ".placeholder-vectors.json")
	path := canonical
	if _, statErr := os.Stat(path); statErr != nil {
		path = placeholder
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var f vectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return f
}

func TestVectorCases(t *testing.T) {
	f := loadFixture(t)
	for _, c := range f.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(TokenHeader, c.Token)
			opts := &Options{Now: time.Unix(c.VerifyAt, 0).UTC()}

			claims, err := Verify(headers, f.TrustedPeerID, opts)

			if c.Expect == "ok" {
				if err != nil {
					t.Fatalf("expected ok, got error: %v", err)
				}
				for k, v := range c.ExpectedClaims {
					if got := claimGet(claims, k); !equalAny(got, v) {
						t.Errorf("claim %q: got %v, want %v", k, got, v)
					}
				}
			} else {
				wantVariant := c.Expect[len("err:"):]
				if err == nil {
					t.Fatalf("expected error %s, got claims: %+v", wantVariant, claims)
				}
				var ve *VerifyError
				if !errors.As(err, &ve) {
					t.Fatalf("expected *VerifyError, got %T: %v", err, err)
				}
				if string(ve.Kind) != wantVariant {
					t.Errorf("kind: got %q, want %q (msg=%s)", ve.Kind, wantVariant, ve.Message)
				}
			}
		})
	}
}

func TestMissingTokenHeader(t *testing.T) {
	f := loadFixture(t)
	_, err := Verify(http.Header{}, f.TrustedPeerID, nil)
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Kind != ErrTokenMissing {
		t.Fatalf("expected TokenMissing, got %v", err)
	}
}

func TestInvalidPeerID(t *testing.T) {
	headers := http.Header{}
	headers.Set(TokenHeader, "not-relevant")
	_, err := Verify(headers, "not-a-z-base-32-string", nil)
	if err == nil {
		t.Fatal("expected configuration error")
	}
	var ve *VerifyError
	if errors.As(err, &ve) {
		t.Fatalf("invalid peer_id should NOT surface as *VerifyError, got %v", ve)
	}
}

// ---------- helpers ----------

func claimGet(c *Claims, key string) interface{} {
	switch key {
	case "sub":
		return c.Sub
	case "iss":
		return c.Iss
	case "iat":
		return c.Iat
	case "exp":
		return c.Exp
	case "email":
		return c.Email
	case "name":
		return c.Name
	case "auth_method":
		return c.AuthMethod
	default:
		return c.Extra[key]
	}
}

// equalAny compares JSON-decoded values where numbers may come in as
// float64. iat/exp on the Claims struct are int64, so we coerce
// before comparing.
func equalAny(a, b interface{}) bool {
	switch av := a.(type) {
	case int64:
		switch bv := b.(type) {
		case int64:
			return av == bv
		case float64:
			return float64(av) == bv
		case int:
			return av == int64(bv)
		}
	case float64:
		switch bv := b.(type) {
		case float64:
			return av == bv
		case int64:
			return av == float64(bv)
		}
	case string:
		bs, ok := b.(string)
		return ok && av == bs
	}
	return false
}
