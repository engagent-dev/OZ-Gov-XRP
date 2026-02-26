use crate::foundation::data::*;

#[test]
fn test_find_value_basic() {
    let data = b"key1=val1;key2=val2;key3=val3";
    assert_eq!(find_value(data, b"key1"), Some(b"val1" as &[u8]));
    assert_eq!(find_value(data, b"key2"), Some(b"val2" as &[u8]));
    assert_eq!(find_value(data, b"key3"), Some(b"val3" as &[u8]));
}

#[test]
fn test_find_value_missing_key() {
    let data = b"a=1;b=2";
    assert_eq!(find_value(data, b"c"), None);
}

#[test]
fn test_find_value_empty_data() {
    assert_eq!(find_value(b"", b"key"), None);
}

#[test]
fn test_find_value_single_entry() {
    let data = b"only=one";
    assert_eq!(find_value(data, b"only"), Some(b"one" as &[u8]));
}

#[test]
fn test_write_entry_basic() {
    let mut buf = [0u8; 64];
    let pos = write_entry(&mut buf, 0, b"key", b"val");
    assert_eq!(&buf[..pos], b"key=val");
}

#[test]
fn test_write_separator() {
    let mut buf = [0u8; 64];
    let pos = write_entry(&mut buf, 0, b"a", b"1");
    let pos = write_separator(&mut buf, pos);
    let pos = write_entry(&mut buf, pos, b"b", b"2");
    assert_eq!(&buf[..pos], b"a=1;b=2");
}

#[test]
fn test_build_indexed_key() {
    let mut buf = [0u8; 16];
    let len = build_indexed_key(b"member_", 3, &mut buf);
    assert_eq!(&buf[..len], b"member_3");
}

#[test]
fn test_round_trip_data() {
    let mut buf = [0u8; 128];
    let mut pos = 0;
    pos = write_entry(&mut buf, pos, b"count", b"2");
    pos = write_separator(&mut buf, pos);
    pos = write_entry(&mut buf, pos, b"item_0", b"hello");
    pos = write_separator(&mut buf, pos);
    pos = write_entry(&mut buf, pos, b"item_1", b"world");

    assert_eq!(find_value(&buf[..pos], b"count"), Some(b"2" as &[u8]));
    assert_eq!(find_value(&buf[..pos], b"item_0"), Some(b"hello" as &[u8]));
    assert_eq!(find_value(&buf[..pos], b"item_1"), Some(b"world" as &[u8]));
}
