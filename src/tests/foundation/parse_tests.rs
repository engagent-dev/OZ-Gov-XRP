use crate::foundation::parse::*;
use crate::governance::governor::{parse_u64, format_u64};

#[test]
fn test_parse_u8_digit() {
    assert_eq!(parse_u8_digit(b"0"), Some(0));
    assert_eq!(parse_u8_digit(b"5"), Some(5));
    assert_eq!(parse_u8_digit(b"9"), Some(9));
    assert_eq!(parse_u8_digit(b"a"), None);
    assert_eq!(parse_u8_digit(b"12"), None);
    assert_eq!(parse_u8_digit(b""), None);
}

#[test]
fn test_parse_u32() {
    assert_eq!(parse_u32(b"0"), Some(0));
    assert_eq!(parse_u32(b"42"), Some(42));
    assert_eq!(parse_u32(b"1000000"), Some(1_000_000));
    assert_eq!(parse_u32(b"4294967295"), Some(u32::MAX));
    assert_eq!(parse_u32(b""), None);
    assert_eq!(parse_u32(b"abc"), None);
}

#[test]
fn test_format_u32() {
    let mut buf = [0u8; 10];
    assert_eq!(format_u32(0, &mut buf), 1);
    assert_eq!(&buf[..1], b"0");

    let len = format_u32(42, &mut buf);
    assert_eq!(&buf[..len], b"42");

    let len = format_u32(259200, &mut buf);
    assert_eq!(&buf[..len], b"259200");
}

#[test]
fn test_parse_u64() {
    assert_eq!(parse_u64(b"0"), Some(0));
    assert_eq!(parse_u64(b"100000000"), Some(100_000_000));
    assert_eq!(parse_u64(b"1000000000000"), Some(1_000_000_000_000));
    assert_eq!(parse_u64(b""), None);
}

#[test]
fn test_format_u64() {
    let mut buf = [0u8; 20];
    let len = format_u64(0, &mut buf);
    assert_eq!(&buf[..len], b"0");

    let len = format_u64(100_000_000, &mut buf);
    assert_eq!(&buf[..len], b"100000000");
}

#[test]
fn test_u32_round_trip() {
    let mut buf = [0u8; 10];
    for val in [0, 1, 42, 300, 172800, 259200, u32::MAX] {
        let len = format_u32(val, &mut buf);
        assert_eq!(parse_u32(&buf[..len]), Some(val));
    }
}

#[test]
fn test_u64_round_trip() {
    let mut buf = [0u8; 20];
    for val in [0u64, 1, 100_000_000, 1_000_000_000_000] {
        let len = format_u64(val, &mut buf);
        assert_eq!(parse_u64(&buf[..len]), Some(val));
    }
}
