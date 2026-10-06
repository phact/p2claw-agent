use p2claw_identity::*;

#[test]
fn zbase32_roundtrip_aligned() {
    // 5 bytes = 40 bits = exactly 8 z-base-32 chars; no padding.
    let input = [0x01, 0x23, 0x45, 0x67, 0x89];
    let s = zbase32_encode(&input);
    assert_eq!(s.len(), 8);
    let back = zbase32_decode(&s, 5).unwrap();
    assert_eq!(back, input);
}

#[test]
fn zbase32_roundtrip_32_bytes() {
    let input = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
        0xCD, 0xEF,
    ];
    let s = zbase32_encode(&input);
    assert_eq!(s.len(), PEER_ID_Z32_LEN);
    let back = zbase32_decode(&s, 32).unwrap();
    assert_eq!(back, input);
}

#[test]
fn zbase32_alphabet_sanity() {
    assert_eq!(Z32_ALPHABET, b"ybndrfg8ejkmcpqxot1uwisza345h769");
    assert_eq!(Z32_ALPHABET.len(), 32);
}

#[test]
fn zbase32_rejects_bad_char() {
    // "L" is not in the alphabet.
    let mut s = zbase32_encode(&[0u8; 32]);
    assert!(s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    s.pop();
    s.push('L');
    match zbase32_decode(&s, 32) {
        Err(IdentityError::Z32InvalidChar(_)) => {}
        other => panic!("expected Z32InvalidChar, got {other:?}"),
    }
}

#[test]
fn zbase32_rejects_wrong_length() {
    match zbase32_decode("abc", 32) {
        Err(IdentityError::Z32WrongLength {
            got: 3,
            expected: 52,
        }) => {}
        other => panic!("expected Z32WrongLength, got {other:?}"),
    }
}

#[test]
fn zbase32_rejects_nonzero_padding() {
    // Construct a 52-char z-base-32 whose tail carries non-zero padding
    // bits. Easiest: take an empty encoding and scramble the last char.
    let mut s = zbase32_encode(&[0u8; 32]);
    // The first char of the alphabet is 'y' (value 0); pick one whose
    // low 4 bits are non-zero.
    // Find any character whose value has a non-zero low nibble.
    let bad_char = (0u8..32u8)
        .find(|&v| (v & 0x0F) != 0)
        .map(|v| Z32_ALPHABET[v as usize] as char)
        .unwrap();
    s.pop();
    s.push(bad_char);
    match zbase32_decode(&s, 32) {
        Err(IdentityError::Z32NonZeroPadding) => {}
        other => panic!("expected Z32NonZeroPadding, got {other:?}"),
    }
}

#[test]
fn peer_id_roundtrip() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let s = pid.to_z32();
    assert_eq!(s.len(), PEER_ID_Z32_LEN);
    let back = PeerId::from_z32(&s).unwrap();
    assert_eq!(pid, back);
    assert_eq!(pid.alias_base().len(), ALIAS_BASE_LEN);
    assert_eq!(&pid.alias_base(), &s[..ALIAS_BASE_LEN]);
}

#[test]
fn signing_key_disk_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");

    let k1 = SigningKey::load_or_generate(&path).unwrap();
    let pid1 = k1.peer_id();

    // Second load reuses the same seed.
    let k2 = SigningKey::load_or_generate(&path).unwrap();
    assert_eq!(k1.seed(), k2.seed());
    assert_eq!(pid1, k2.peer_id());

    // File is exactly 32 bytes.
    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.len(), 32);

    // 0600 on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }
}

#[test]
fn signing_key_wrong_size_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.key");
    std::fs::write(&path, [0u8; 31]).unwrap();
    match SigningKey::load_or_generate(&path) {
        Err(IdentityError::KeyFileWrongSize(31)) => {}
        other => panic!("expected KeyFileWrongSize(31), got {other:?}"),
    }
}

#[test]
fn registration_roundtrip() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();

    let ts = 1_767_312_000u64;
    let sig = sign_registration(&sk, "coord.p2claw.com", ts).unwrap();

    verify_registration(&pid, "coord.p2claw.com", ts, &sig, ts).unwrap();
    verify_registration(&pid, "coord.p2claw.com", ts, &sig, ts + 30).unwrap();
    verify_registration(&pid, "coord.p2claw.com", ts, &sig, ts - 30).unwrap();
}

#[test]
fn registration_wrong_domain_rejected() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let ts = 1_767_312_000u64;
    let sig = sign_registration(&sk, "coord.p2claw.com", ts).unwrap();

    match verify_registration(&pid, "evil.example.com", ts, &sig, ts) {
        Err(IdentityError::BadSignature) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn registration_skew_rejected() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let ts = 1_767_312_000u64;
    let sig = sign_registration(&sk, "coord.p2claw.com", ts).unwrap();

    match verify_registration(&pid, "coord.p2claw.com", ts, &sig, ts + 120) {
        Err(IdentityError::ClockSkew { skew: 120, max: 60 }) => {}
        other => panic!("expected ClockSkew, got {other:?}"),
    }
}

#[test]
fn registration_tampered_sig_rejected() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let ts = 1_767_312_000u64;
    let sig = sign_registration(&sk, "coord.p2claw.com", ts).unwrap();

    // Flip a bit in the signature.
    let mut bytes = sig.to_bytes();
    bytes[0] ^= 0x01;
    let bad = Signature::from_bytes(&bytes);

    match verify_registration(&pid, "coord.p2claw.com", ts, &bad, ts) {
        Err(IdentityError::BadSignature) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn dtls_fp_roundtrip() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let session_id = "01HW3QABCDEFGHJKMNPQRSTVWX";
    let fp = [0xAAu8; 32];
    let sig = sign_dtls_fp(&sk, session_id, 0x01, &fp).unwrap();
    verify_dtls_fp(&pid, session_id, 0x01, &fp, &sig).unwrap();
}

#[test]
fn dtls_fp_wrong_session_rejected() {
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let fp = [0xAAu8; 32];
    let sig = sign_dtls_fp(&sk, "session-a", 0x01, &fp).unwrap();
    match verify_dtls_fp(&pid, "session-b", 0x01, &fp, &sig) {
        Err(IdentityError::BadSignature) => {}
        other => panic!("expected BadSignature, got {other:?}"),
    }
}

#[test]
fn domain_separators_collide_protection() {
    // A signature for the registration domain must not verify as a
    // DTLS-fingerprint signature even if the payload shapes are
    // otherwise similar.
    let sk = SigningKey::generate();
    let pid = sk.peer_id();
    let sig = sign_registration(&sk, "coord.p2claw.com", 0).unwrap();
    // Attempt cross-protocol verification — should fail.
    let fake_fp = [0u8; 32];
    match verify_dtls_fp(&pid, "coord.p2claw.com", 0x01, &fake_fp, &sig) {
        Err(IdentityError::BadSignature) => {}
        other => panic!("expected cross-proto BadSignature, got {other:?}"),
    }
}
