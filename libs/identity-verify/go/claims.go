// SPDX-License-Identifier: MIT
package identityverify

// Claims is the verified identity claims dict returned by Verify.
// The named fields are the stable set; the open-ended Extra map carries
// any additional claims the box has minted so call sites grow into
// reading more fields without an API change.
type Claims struct {
	Sub        string `json:"sub"`
	Iss        string `json:"iss"`
	Iat        int64  `json:"iat"`
	Exp        int64  `json:"exp"`
	Email      string `json:"email,omitempty"`
	Name       string `json:"name,omitempty"`
	AuthMethod string `json:"auth_method,omitempty"`

	// Extra captures any non-standard claim the box has added. The
	// JWT decoder populates this from the raw payload after extracting
	// the named fields.
	Extra map[string]any `json:"-"`
}
