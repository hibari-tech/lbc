//! Content-addressed blob store on the local filesystem.
//!
//! Layout: `<root>/<aa>/<bb>/<hex64>` where `hex64` is the lowercase hex of
//! a blake3 digest, sharded by its first two and next two hex chars to keep
//! per-directory file counts small.
//!
//! [`put`](BlobStore::put) is idempotent: writing the same bytes twice
//! returns the same hash and no error. Writes are atomic via tmpfile +
//! rename in the same directory.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

pub type Hash = [u8; 32];

#[derive(Debug, Clone)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("creating blob root {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn put(&self, bytes: &[u8]) -> anyhow::Result<Hash> {
        let hash = *blake3::hash(bytes).as_bytes();
        let path = self.path_for(&hash);
        if path.is_file() {
            return Ok(hash);
        }
        let dir = path.parent().expect("blob path has parent");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating blob dir {}", dir.display()))?;
        write_atomic(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
        Ok(hash)
    }

    pub fn get(&self, hash: &Hash) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.path_for(hash);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn exists(&self, hash: &Hash) -> bool {
        self.path_for(hash).is_file()
    }

    pub fn path_for(&self, hash: &Hash) -> PathBuf {
        let hex = blake3::Hash::from(*hash).to_hex();
        let s = hex.as_str();
        self.root.join(&s[..2]).join(&s[2..4]).join(s)
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = path.parent().expect("path has parent");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut tmp_name = OsString::from(path.file_name().expect("path has filename"));
    tmp_name.push(format!(".tmp.{}.{nanos}", std::process::id()));
    let tmp = dir.join(tmp_name);
    std::fs::write(&tmp, bytes)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}
