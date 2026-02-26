use crate::crypto::hex::{encode_hex, decode_hex};

#[test]
fn test_encode_hex() {
    let input = [0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0xAA];
    let mut out = [0u8; 40];
    encode_hex(&input, &mut out);
    assert_eq!(&out[..2], b"aa");
    assert_eq!(&out[38..40], b"aa");
}

#[test]
fn test_decode_hex() {
    let hex = b"aa000000000000000000000000000000000000aa";
    let mut out = [0u8; 20];
    assert!(decode_hex(hex, &mut out));
    assert_eq!(out[0], 0xAA);
    assert_eq!(out[19], 0xAA);
    assert_eq!(out[1], 0x00);
}

#[test]
fn test_hex_round_trip() {
    let original = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                    0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
                    0xFF, 0x00, 0x80, 0x42];
    let mut hex = [0u8; 40];
    encode_hex(&original, &mut hex);
    let mut decoded = [0u8; 20];
    assert!(decode_hex(&hex, &mut decoded));
    assert_eq!(original, decoded);
}

#[test]
fn test_decode_invalid_hex() {
    let bad = b"zz00000000000000000000000000000000000000";
    let mut out = [0u8; 20];
    assert!(!decode_hex(bad, &mut out));
}
