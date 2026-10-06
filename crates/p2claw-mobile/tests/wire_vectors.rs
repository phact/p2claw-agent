//! Verifies the mobile-side codec produces bit-identical output to the
//! canonical wire fixture at `crates/wire/test-vectors.json`. The
//! same fixture drives the TypeScript bootstrap tests, so a green run
//! here means the codec agrees with both the TS bootstrap and the
//! Rust box-side wire crate on every byte of every supported frame.

use p2claw_mobile::{encode_frame, Decoder};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Vectors {
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[allow(dead_code)]
    description: String,
    hex: String,
}

fn fixture_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest.join("../wire/test-vectors.json")
}

fn load_vectors() -> Vec<Vector> {
    let path = fixture_path();
    let raw =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let parsed: Vectors = serde_json::from_str(&raw).expect("fixture is valid JSON");
    parsed.vectors
}

#[test]
fn decode_then_encode_matches_fixture_bytes() {
    let vectors = load_vectors();
    assert!(!vectors.is_empty(), "fixture must carry vectors");

    for v in &vectors {
        let bytes = hex::decode(&v.hex)
            .unwrap_or_else(|e| panic!("vector '{}': hex decode failed: {e}", v.name));

        let decoder = Decoder::new();
        decoder.push(bytes.clone());
        let frame = decoder
            .next_frame()
            .unwrap_or_else(|e| panic!("vector '{}': decode error: {e}", v.name))
            .unwrap_or_else(|| panic!("vector '{}': decode returned None on full frame", v.name));
        assert_eq!(
            decoder.buffered(),
            0,
            "vector '{}': decoder left bytes buffered",
            v.name
        );

        let re_encoded = encode_frame(&frame);
        assert_eq!(
            re_encoded, bytes,
            "vector '{}': re-encoded bytes diverge from fixture",
            v.name
        );
    }
}

#[test]
fn decoder_handles_concatenated_fixture_stream() {
    let vectors = load_vectors();
    let mut stream = Vec::new();
    for v in &vectors {
        stream.extend(hex::decode(&v.hex).expect("hex"));
    }

    let decoder = Decoder::new();
    decoder.push(stream);

    let mut decoded = Vec::new();
    while let Some(frame) = decoder.next_frame().expect("decode") {
        decoded.push(frame);
    }
    assert_eq!(
        decoded.len(),
        vectors.len(),
        "every fixture vector should decode from the stream"
    );
    assert_eq!(decoder.buffered(), 0, "stream fully drained");
}
