//! Generate cross-language test vectors for the browser bootstrap's
//! signature verifiers (DTLS-fingerprint + alias-binding).
//!
//! Run:   cargo run -p p2claw-identity --example dump_identity_vectors
//!
//! Prints one JSON object to stdout with two families of vectors:
//!
//! 1. `vectors[]` — `p2claw-dtls-fp-v1` signatures, consumed by
//!    `bootstrap/test/identity-verify.test.ts`.
//! 2. `alias_binding_vectors[]` — `p2claw-binding-v1` signatures, for
//!    cross-impl pinning of coord's alias→peer_id attestation.
//!    Consumed by `bootstrap/test/binding-verify.test.ts`.
//!
//! Pipe into `bootstrap/test/identity-vectors.json`. Seeds are fixed
//! (all-zero + small variations) so the output is stable across runs.
//! Existing consumers that only read `vectors[]` are unaffected —
//! the new family is a parallel top-level field.

use p2claw_identity::{
    build_alias_binding_payload, build_dtls_fp_payload, sign_alias_binding, sign_dtls_fp,
    SigningKey,
};

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

struct Case {
    name: &'static str,
    description: &'static str,
    seed: [u8; 32],
    session_id: &'static str,
    fp_alg: u8,
    fp: Vec<u8>,
}

/// One alias-binding vector. Coord's root key signs over
/// `p2claw-binding-v1 || 0x0A || u16_be(len(alias)) || alias || 0x00 ||
/// pubkey(32) || u64_be(issued_at)` — see
/// `crates/identity/src/proofs.rs::build_alias_binding_payload`.
/// The TS verifier reconstructs the payload from `{alias, peer_id_hex,
/// issued_at}` and verifies the signature against `root_pubkey_hex`.
struct BindingCase {
    name: &'static str,
    description: &'static str,
    root_seed: [u8; 32],
    peer_seed: [u8; 32],
    alias: &'static str,
    issued_at: u64,
}

fn main() {
    let cases: Vec<Case> = vec![
        Case {
            name: "dtls_fp_sha256_minimal",
            description: "dtls-fp-v1 signature over SHA-256 fingerprint with a short session id",
            seed: [0u8; 32],
            session_id: "01HW3QABCDEFGHJKMNPQRSTVWX",
            fp_alg: 0x01,
            fp: (0..32u8).collect(),
        },
        Case {
            name: "dtls_fp_sha256_realistic",
            description: "dtls-fp-v1 with a realistic session id and varied fingerprint bytes",
            seed: {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(7).wrapping_add(1);
                }
                s
            },
            session_id: "01JCXZ7YK8R2V3QMNP4W5H6ZAE",
            fp_alg: 0x01,
            fp: (0..32u8).map(|i| i.wrapping_mul(11).wrapping_add(3)).collect(),
        },
        Case {
            name: "dtls_fp_empty_session_id",
            description: "edge: session_id is empty (not valid in practice, but verifier should still compute a correct payload)",
            seed: [0x42u8; 32],
            session_id: "",
            fp_alg: 0x01,
            fp: vec![0xab; 32],
        },
    ];

    let mut entries: Vec<String> = Vec::new();
    for case in &cases {
        let sk = SigningKey::from_seed(&case.seed);
        let pid = sk.peer_id();
        let sig = sign_dtls_fp(&sk, case.session_id, case.fp_alg, &case.fp).unwrap();
        let msg =
            build_dtls_fp_payload(pid.as_bytes(), case.session_id, case.fp_alg, &case.fp).unwrap();
        let entry = format!(
            concat!(
                "    {{\n",
                "      \"name\": \"{name}\",\n",
                "      \"description\": \"{desc}\",\n",
                "      \"seed_hex\": \"{seed}\",\n",
                "      \"peer_id_z32\": \"{pid}\",\n",
                "      \"peer_id_hex\": \"{pid_hex}\",\n",
                "      \"session_id\": \"{sid}\",\n",
                "      \"fp_alg\": {alg},\n",
                "      \"fp_hex\": \"{fp}\",\n",
                "      \"message_hex\": \"{msg}\",\n",
                "      \"signature_hex\": \"{sig}\"\n",
                "    }}",
            ),
            name = case.name,
            desc = case.description,
            seed = hex_encode(&case.seed),
            pid = pid,
            pid_hex = hex_encode(pid.as_bytes()),
            sid = case.session_id,
            alg = case.fp_alg,
            fp = hex_encode(&case.fp),
            msg = hex_encode(&msg),
            sig = hex_encode(&sig.to_bytes()),
        );
        entries.push(entry);
    }

    // ---- alias-binding vectors ------------------------------------
    //
    // The coordination root key signs the alias→peer_id binding the
    // edge injects into the wrapper. Bootstrap
    // pins coord's root pubkey and verifies this signature before
    // trusting the peer_id meta tag — these vectors let the TS side
    // confirm its reconstruction of the signed payload + its Ed25519
    // verify path agree with the Rust signer byte-for-byte.
    //
    // Root seeds are `01..20` / `21..40` so the root is visibly
    // distinct from the peer keys and from the DTLS seeds above. The
    // `blue-otter-7392` case lines up with the in-TS golden layout
    // test (`buildAliasBindingPayload`), giving the TS suite one
    // vector where *both* the payload bytes *and* the signature can
    // be cross-checked against the Rust source of truth.
    let binding_cases: Vec<BindingCase> = vec![
        BindingCase {
            name: "binding_blue_otter_typical",
            description: "alias-binding-v1: typical haiku alias with a realistic issued_at",
            root_seed: {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = (i as u8) + 1;
                }
                s
            },
            peer_seed: {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = (i as u8) + 0x21;
                }
                s
            },
            alias: "blue-otter-7392",
            issued_at: 1_767_312_000,
        },
        BindingCase {
            name: "binding_vanity_alias",
            description: "alias-binding-v1: a vanity alias (no trailing digits), ASCII-lowercase",
            root_seed: [0x55u8; 32],
            peer_seed: [0xaau8; 32],
            alias: "recipebook",
            issued_at: 1_800_000_000,
        },
        BindingCase {
            name: "binding_extended_haiku_5_digits",
            description: "alias-binding-v1: 5-digit haiku tail (collision extension)",
            root_seed: {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(3).wrapping_add(0x10);
                }
                s
            },
            peer_seed: {
                let mut s = [0u8; 32];
                for (i, b) in s.iter_mut().enumerate() {
                    *b = (i as u8).wrapping_mul(5).wrapping_add(0x80);
                }
                s
            },
            alias: "quiet-river-00042",
            issued_at: 1_700_000_000,
        },
    ];

    let mut binding_entries: Vec<String> = Vec::new();
    for case in &binding_cases {
        let root_sk = SigningKey::from_seed(&case.root_seed);
        let peer_sk = SigningKey::from_seed(&case.peer_seed);
        let peer_id = peer_sk.peer_id();
        // Ed25519 public keys are the same 32 bytes whether you ask
        // the VerifyingKey or the PeerId — PeerId is the transport
        // wrapper, so we route through it to reuse its byte accessor.
        let root_pubkey = root_sk.peer_id();
        let msg =
            build_alias_binding_payload(case.alias, peer_id.as_bytes(), case.issued_at).unwrap();
        let sig = sign_alias_binding(&root_sk, case.alias, &peer_id, case.issued_at).unwrap();
        let entry = format!(
            concat!(
                "    {{\n",
                "      \"name\": \"{name}\",\n",
                "      \"description\": \"{desc}\",\n",
                "      \"root_seed_hex\": \"{root_seed}\",\n",
                "      \"root_pubkey_hex\": \"{root_pub}\",\n",
                "      \"peer_seed_hex\": \"{peer_seed}\",\n",
                "      \"peer_id_z32\": \"{pid}\",\n",
                "      \"peer_id_hex\": \"{pid_hex}\",\n",
                "      \"alias\": \"{alias}\",\n",
                "      \"issued_at\": {issued_at},\n",
                "      \"message_hex\": \"{msg}\",\n",
                "      \"signature_hex\": \"{sig}\"\n",
                "    }}",
            ),
            name = case.name,
            desc = case.description,
            root_seed = hex_encode(&case.root_seed),
            root_pub = hex_encode(root_pubkey.as_bytes()),
            peer_seed = hex_encode(&case.peer_seed),
            pid = peer_id,
            pid_hex = hex_encode(peer_id.as_bytes()),
            alias = case.alias,
            issued_at = case.issued_at,
            msg = hex_encode(&msg),
            sig = hex_encode(&sig.to_bytes()),
        );
        binding_entries.push(entry);
    }

    println!("{{");
    println!("  \"note\": \"Generated by crates/identity/examples/dump_identity_vectors.rs. Do not edit by hand; re-run the example to update.\",");
    println!("  \"dtls_fp_domain_separator\": \"p2claw-dtls-fp-v1\",");
    println!("  \"vectors\": [");
    println!("{}", entries.join(",\n"));
    println!("  ],");
    println!("  \"alias_binding_domain_separator\": \"p2claw-binding-v1\",");
    println!("  \"alias_binding_vectors\": [");
    println!("{}", binding_entries.join(",\n"));
    println!("  ]");
    println!("}}");
}
