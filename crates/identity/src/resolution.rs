//! Checking coordination's answer to "which peer serves this alias?".
//!
//! Coordination resolves an alias to a peer id, and the client then
//! authenticates the connection against that peer id. Unless the client
//! checks the answer, whoever answers for coordination picks the peer.
//! The answer carries a binding signed by coordination's root key; a
//! client holding that key verifies it here.

use ed25519_dalek::Signature;

use crate::error::IdentityError;
use crate::keypair::VerifyingKey;
use crate::peer_id::PeerId;
use crate::proofs::verify_alias_binding;

/// Root key of the production coordination service, `coord.p2claw.com`.
pub const P2CLAW_COORD_ROOT_PEER_ID: &str = "jrzxgywqpxi9mptyhz4it1up4g8kdbg8qgydc1itpmot4nonbrhy";

/// [`P2CLAW_COORD_ROOT_PEER_ID`], decoded.
pub fn p2claw_coord_root() -> PeerId {
    PeerId::from_z32(P2CLAW_COORD_ROOT_PEER_ID).expect("built-in root key is valid z-base-32")
}

/// The binding fields of a resolution answer.
#[derive(Debug, Clone, Copy)]
pub struct AliasBindingRef<'a> {
    pub alias: &'a str,
    pub issued_at: u64,
    /// Raw 64-byte Ed25519 signature.
    pub sig: &'a [u8],
}

/// Accept `peer_id` as the answer for `target` only if the answer is
/// self-evidently right (`target` is that peer id) or comes with a
/// binding of `target` to `peer_id` signed by `root`.
pub fn verify_alias_resolution(
    root: &PeerId,
    target: &str,
    peer_id: &PeerId,
    binding: Option<AliasBindingRef<'_>>,
) -> Result<(), IdentityError> {
    if let Ok(requested) = PeerId::from_z32(target) {
        return if &requested == peer_id {
            Ok(())
        } else {
            Err(IdentityError::ResolutionMismatch)
        };
    }
    let binding = binding.ok_or(IdentityError::MissingBinding)?;
    if binding.alias != target {
        return Err(IdentityError::ResolutionMismatch);
    }
    let sig = Signature::from_slice(binding.sig).map_err(|_| IdentityError::BadSignature)?;
    let root_vk = VerifyingKey::from_peer_id(root)?;
    verify_alias_binding(&root_vk, binding.alias, peer_id, binding.issued_at, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::SigningKey;
    use crate::proofs::sign_alias_binding;

    struct Fixture {
        root: SigningKey,
        peer: PeerId,
        sig: [u8; 64],
    }

    fn fixture() -> Fixture {
        let root = SigningKey::generate();
        let peer = SigningKey::generate().peer_id();
        let sig = sign_alias_binding(&root, "calm-river-hat", &peer, 1_700_000_000)
            .unwrap()
            .to_bytes();
        Fixture { root, peer, sig }
    }

    fn binding(sig: &[u8]) -> AliasBindingRef<'_> {
        AliasBindingRef {
            alias: "calm-river-hat",
            issued_at: 1_700_000_000,
            sig,
        }
    }

    #[test]
    fn built_in_root_decodes() {
        assert_eq!(p2claw_coord_root().to_z32(), P2CLAW_COORD_ROOT_PEER_ID);
    }

    #[test]
    fn signed_binding_is_accepted() {
        let f = fixture();
        let root = f.root.peer_id();
        verify_alias_resolution(&root, "calm-river-hat", &f.peer, Some(binding(&f.sig))).unwrap();
    }

    #[test]
    fn binding_from_another_root_is_rejected() {
        let f = fixture();
        let other_root = SigningKey::generate().peer_id();
        let err = verify_alias_resolution(
            &other_root,
            "calm-river-hat",
            &f.peer,
            Some(binding(&f.sig)),
        );
        assert!(matches!(err, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn substituted_peer_is_rejected() {
        let f = fixture();
        let root = f.root.peer_id();
        let impostor = SigningKey::generate().peer_id();
        let err =
            verify_alias_resolution(&root, "calm-river-hat", &impostor, Some(binding(&f.sig)));
        assert!(matches!(err, Err(IdentityError::BadSignature)));
    }

    #[test]
    fn binding_for_another_alias_is_rejected() {
        let f = fixture();
        let root = f.root.peer_id();
        let err = verify_alias_resolution(&root, "odd-moon-8639", &f.peer, Some(binding(&f.sig)));
        assert!(matches!(err, Err(IdentityError::ResolutionMismatch)));
    }

    #[test]
    fn missing_binding_is_rejected() {
        let f = fixture();
        let root = f.root.peer_id();
        let err = verify_alias_resolution(&root, "calm-river-hat", &f.peer, None);
        assert!(matches!(err, Err(IdentityError::MissingBinding)));
    }

    #[test]
    fn peer_id_target_needs_no_binding_but_must_match() {
        let f = fixture();
        let root = f.root.peer_id();
        verify_alias_resolution(&root, &f.peer.to_z32(), &f.peer, None).unwrap();
        let other = SigningKey::generate().peer_id();
        let err = verify_alias_resolution(&root, &f.peer.to_z32(), &other, None);
        assert!(matches!(err, Err(IdentityError::ResolutionMismatch)));
    }
}
