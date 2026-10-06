// SPDX-License-Identifier: MIT
// Package identityverify verifies the X-P2claw-Identity-Token (EdDSA
// JWT) minted by p2claw agent against an operator-supplied
// peer_id (the box's Ed25519 public key encoded as 52-char
// z-base-32).
//
// Thin wrapper over github.com/golang-jwt/jwt/v5; the crypto is
// theirs, the package's value is the API shape + the cross-language
// test-vector fidelity that matches the Rust, TypeScript, and Python
// reference libs.
package identityverify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenHeader is the canonical header the daemon mints into.
const TokenHeader = "X-P2claw-Identity-Token"

// LeewaySeconds is the clock-skew tolerance applied to exp/nbf.
// Attestations live 60s; 15s leeway in either direction.
const LeewaySeconds = 15

// HeaderGetter is the minimal subset of http.Header / canonical
// header containers used by Verify. Anything with a case-insensitive
// Get(name) string satisfies it — including http.Header itself.
type HeaderGetter interface {
	Get(name string) string
}

// Options tunes the verify call.
type Options struct {
	// Now overrides the reference time (mostly for tests). The zero
	// value falls back to time.Now().UTC().
	Now time.Time
}

// Verify checks the X-P2claw-Identity-Token carried on headers
// against the operator-supplied trustedPeerID (z-base-32 box pubkey).
// On success it returns the verified Claims; on a verification
// failure it returns a *VerifyError whose Kind discriminates the
// case. On a configuration failure (invalid trustedPeerID) it
// returns a plain error.
//
// No "extract claims without verifying" path is offered by design.
func Verify(headers HeaderGetter, trustedPeerID string, opts *Options) (*Claims, error) {
	pubkeyBytes, err := DecodePeerID(trustedPeerID)
	if err != nil {
		return nil, fmt.Errorf("invalid trustedPeerID: %w", err)
	}
	pubkey := ed25519.PublicKey(pubkeyBytes)

	token := headers.Get(TokenHeader)
	if token == "" {
		return nil, newVerifyError(ErrTokenMissing, "no "+TokenHeader+" header")
	}

	// Peek the JOSE header's `alg` before handing to golang-jwt.
	// golang-jwt v5's `WithValidMethods` rejection bubbles through as
	// `ErrTokenSignatureInvalid`, which makes downstream classification
	// brittle — peeking pins `AlgorithmRejected` unconditionally and
	// mirrors the Rust reference lib's defence-in-depth.
	if alg, ok := peekJoseAlg(token); ok && alg != "EdDSA" {
		return nil, newVerifyError(ErrAlgorithmRejected, fmt.Sprintf("alg=%q is not EdDSA", alg))
	}

	now := time.Now().UTC()
	if opts != nil && !opts.Now.IsZero() {
		now = opts.Now
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithLeeway(time.Duration(LeewaySeconds)*time.Second),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)

	claims := jwt.MapClaims{}
	parsed, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		return pubkey, nil
	})
	if err != nil {
		return nil, mapJWTError(err)
	}
	if parsed == nil || !parsed.Valid {
		return nil, newVerifyError(ErrBadSignature, "token failed validation")
	}

	out, err := claimsFromMap(claims)
	if err != nil {
		return nil, newVerifyError(ErrMalformed, err.Error())
	}

	// Defence-in-depth: even if signature verifies, the iss claim
	// must match the trusted peer_id.
	if out.Iss != trustedPeerID {
		return nil, newVerifyError(
			ErrIssuerMismatch,
			fmt.Sprintf("iss=%q does not match trusted peer_id", out.Iss),
		)
	}
	// iat-future: golang-jwt only validates nbf for not-before
	// semantics; the canonical fixture's not_yet_valid case uses iat
	// in the future (no nbf), so enforce iat-future too.
	if out.Iat > 0 {
		nowTs := now.Unix()
		if nowTs+int64(LeewaySeconds) < out.Iat {
			return nil, newVerifyError(
				ErrNotYetValid,
				fmt.Sprintf("iat=%d > now=%d (leeway %ds)", out.Iat, nowTs, LeewaySeconds),
			)
		}
	}
	return out, nil
}

// VerifyHTTP is a convenience wrapper for callers that already have
// an *http.Request.
func VerifyHTTP(r *http.Request, trustedPeerID string, opts *Options) (*Claims, error) {
	return Verify(r.Header, trustedPeerID, opts)
}

// mapJWTError translates golang-jwt's error inventory onto the
// canonical PascalCase variant vocabulary.
func mapJWTError(err error) *VerifyError {
	switch {
	case errors.Is(err, jwt.ErrTokenExpired):
		return newVerifyError(ErrExpired, err.Error())
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return newVerifyError(ErrNotYetValid, err.Error())
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return newVerifyError(ErrBadSignature, err.Error())
	case errors.Is(err, jwt.ErrTokenMalformed):
		return newVerifyError(ErrMalformed, err.Error())
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		// golang-jwt surfaces alg rejection via SignatureInvalid OR
		// Unverifiable depending on the parse path; the validation
		// hook rejecting an unknown method routes here.
		if strings.Contains(err.Error(), "signing method") ||
			strings.Contains(err.Error(), "alg") {
			return newVerifyError(ErrAlgorithmRejected, err.Error())
		}
		return newVerifyError(ErrMalformed, err.Error())
	case errors.Is(err, jwt.ErrInvalidKeyType) ||
		errors.Is(err, jwt.ErrInvalidKey):
		return newVerifyError(ErrBadSignature, err.Error())
	default:
		// `jwt.WithValidMethods` rejects non-allow-listed algs with
		// a wrapped error that doesn't always pass errors.Is for the
		// sentinel above — match on substring as a last resort.
		msg := err.Error()
		if strings.Contains(msg, "signing method") ||
			strings.Contains(msg, "unexpected method") ||
			strings.Contains(msg, "alg none") {
			return newVerifyError(ErrAlgorithmRejected, msg)
		}
		if strings.Contains(msg, "signature is invalid") {
			return newVerifyError(ErrBadSignature, msg)
		}
		return newVerifyError(ErrMalformed, msg)
	}
}

// claimsFromMap extracts the named fields out of a jwt.MapClaims and
// puts everything else into Claims.Extra.
func claimsFromMap(m jwt.MapClaims) (*Claims, error) {
	c := &Claims{Extra: map[string]any{}}
	for k, v := range m {
		switch k {
		case "sub":
			s, _ := v.(string)
			c.Sub = s
		case "iss":
			s, _ := v.(string)
			c.Iss = s
		case "iat":
			c.Iat = int64Of(v)
		case "exp":
			c.Exp = int64Of(v)
		case "email":
			s, _ := v.(string)
			c.Email = s
		case "name":
			s, _ := v.(string)
			c.Name = s
		case "auth_method":
			s, _ := v.(string)
			c.AuthMethod = s
		default:
			c.Extra[k] = v
		}
	}
	return c, nil
}

// peekJoseAlg decodes the JOSE header's `alg` field by hand. Returns
// (alg, true) on a parseable header, ("", false) when the token
// doesn't even parse as a JWS header — those cases are left for the
// JWT library's full decode to classify as Malformed.
func peekJoseAlg(token string) (string, bool) {
	parts := strings.SplitN(token, ".", 4)
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", false
	}
	if header.Alg == "" {
		return "", false
	}
	return header.Alg, true
}

// int64Of coerces a JSON-decoded number (float64) to int64. The JWT
// spec puts iat/exp as NumericDate (seconds, possibly fractional);
// we always truncate to whole seconds.
func int64Of(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	default:
		return 0
	}
}
