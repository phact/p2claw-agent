// SPDX-License-Identifier: MIT
package identityverify

// z-base-32 codec for p2claw peer ids.
//
// peer_id is the box's Ed25519 public key (32 bytes) encoded as 52
// z-base-32 characters. The alphabet is the canonical Zooko form:
// human-readable, no easy-to-confuse pairs.
//
// Reference: http://philzimmermann.com/docs/human-oriented-base-32-encoding.txt

import "fmt"

const zBase32Alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"

var zBase32Decode = func() map[byte]uint8 {
	m := make(map[byte]uint8, len(zBase32Alphabet))
	for i := 0; i < len(zBase32Alphabet); i++ {
		m[zBase32Alphabet[i]] = uint8(i)
	}
	return m
}()

// DecodePeerID decodes a 52-char z-base-32 string into a 32-byte
// Ed25519 public key. Returns a non-nil error if the input isn't
// exactly 52 characters of the z-base-32 alphabet or has non-zero
// trailing pad bits.
func DecodePeerID(peerID string) ([]byte, error) {
	if len(peerID) != 52 {
		return nil, fmt.Errorf("peer_id length must be 52 z-base-32 characters, got %d", len(peerID))
	}
	out := make([]byte, 32)
	var buffer uint32
	var bitsHeld uint
	outIdx := 0
	for i := 0; i < len(peerID); i++ {
		ch := peerID[i]
		v, ok := zBase32Decode[ch]
		if !ok {
			return nil, fmt.Errorf("peer_id contains non-z-base-32 character at index %d", i)
		}
		buffer = (buffer << 5) | uint32(v)
		bitsHeld += 5
		if bitsHeld >= 8 {
			bitsHeld -= 8
			out[outIdx] = byte((buffer >> bitsHeld) & 0xff)
			outIdx++
		}
	}
	if bitsHeld > 0 && (buffer&((1<<bitsHeld)-1)) != 0 {
		return nil, fmt.Errorf("peer_id has non-zero trailing bits")
	}
	return out, nil
}

// EncodePeerID encodes a 32-byte Ed25519 public key into its 52-char
// z-base-32 form. Used by the placeholder vector generator; not part
// of the public verify API.
func EncodePeerID(pubkey []byte) (string, error) {
	if len(pubkey) != 32 {
		return "", fmt.Errorf("pubkey must be 32 bytes, got %d", len(pubkey))
	}
	var buffer uint32
	var bitsHeld uint
	out := make([]byte, 0, 52)
	for _, b := range pubkey {
		buffer = (buffer << 8) | uint32(b)
		bitsHeld += 8
		for bitsHeld >= 5 {
			bitsHeld -= 5
			out = append(out, zBase32Alphabet[(buffer>>bitsHeld)&0x1f])
		}
	}
	if bitsHeld > 0 {
		out = append(out, zBase32Alphabet[(buffer<<(5-bitsHeld))&0x1f])
	}
	return string(out), nil
}
