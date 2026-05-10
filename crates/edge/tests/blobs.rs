//! Integration tests for the content-addressed blob store.

use edge::storage::blobs::BlobStore;
use tempfile::TempDir;

fn fresh_store() -> (TempDir, BlobStore) {
    let tmp = TempDir::new().expect("tempdir");
    let store = BlobStore::open(tmp.path().join("blobs")).expect("open store");
    (tmp, store)
}

#[test]
fn put_then_get_roundtrips() {
    let (_tmp, store) = fresh_store();
    let data = b"hello, lbc";
    let hash = store.put(data).expect("put");
    assert!(store.exists(&hash));
    let got = store.get(&hash).expect("get").expect("present");
    assert_eq!(got, data);
}

#[test]
fn put_is_idempotent_for_identical_bytes() {
    let (_tmp, store) = fresh_store();
    let data = b"same bytes twice";
    let h1 = store.put(data).expect("put 1");
    let h2 = store.put(data).expect("put 2");
    assert_eq!(h1, h2, "same content yields same hash");
    let path = store.path_for(&h1);
    assert!(path.is_file(), "single file on disk");
}

#[test]
fn distinct_content_yields_distinct_hashes() {
    let (_tmp, store) = fresh_store();
    let a = store.put(b"alpha").expect("put a");
    let b = store.put(b"beta").expect("put b");
    assert_ne!(a, b);
    assert!(store.exists(&a));
    assert!(store.exists(&b));
}

#[test]
fn get_unknown_returns_none() {
    let (_tmp, store) = fresh_store();
    let missing = [0u8; 32];
    assert!(!store.exists(&missing));
    assert!(store.get(&missing).expect("get").is_none());
}

#[test]
fn layout_is_sharded_by_first_two_hex_pairs() {
    let (_tmp, store) = fresh_store();
    let data = b"layout check";
    let hash = store.put(data).expect("put");
    let path = store.path_for(&hash);
    let hex = blake3::Hash::from(hash).to_hex();
    let s = hex.as_str();
    let dir1 = path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .file_name()
        .unwrap();
    let dir2 = path.parent().unwrap().file_name().unwrap();
    let file = path.file_name().unwrap();
    assert_eq!(dir1.to_str().unwrap(), &s[..2]);
    assert_eq!(dir2.to_str().unwrap(), &s[2..4]);
    assert_eq!(file.to_str().unwrap(), s);
}
