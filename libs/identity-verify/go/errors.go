// SPDX-License-Identifier: MIT
package identityverify

import "fmt"

// ErrorKind discriminates the verification failure variants.
// The string values match the cross-language test-vector
// vocabulary used by the Rust / TypeScript / Python reference libs.
type ErrorKind string

const (
	ErrTokenMissing      ErrorKind = "TokenMissing"
	ErrMalformed         ErrorKind = "Malformed"
	ErrAlgorithmRejected ErrorKind = "AlgorithmRejected"
	ErrBadSignature      ErrorKind = "BadSignature"
	ErrExpired           ErrorKind = "Expired"
	ErrNotYetValid       ErrorKind = "NotYetValid"
	ErrIssuerMismatch    ErrorKind = "IssuerMismatch"
)

// VerifyError is returned when a presented token fails verification.
// The Kind field is the structured discriminant; Message is
// human-readable detail.
//
// Configuration errors (e.g. a malformed trustedPeerID) are returned
// as plain `error` values via the standard error wrapping — they're
// a programmer / operator issue, not a verification outcome.
type VerifyError struct {
	Kind    ErrorKind
	Message string
}

func (e *VerifyError) Error() string {
	return fmt.Sprintf("%s: %s", e.Kind, e.Message)
}

// newVerifyError constructs a *VerifyError from the kind and an
// optional underlying error message.
func newVerifyError(kind ErrorKind, msg string) *VerifyError {
	return &VerifyError{Kind: kind, Message: msg}
}
