//! Persisted signed license + signature verification.
//!
//! The Edge Node stores a single license per install on the filesystem
//! (path is configurable). On every start, the runtime loads it and
//! verifies the ed25519 signature against the configured Control-Plane
//! public key. A missing license is currently tolerated (warn-log only);
//! a present-but-invalid license is a hard error — refuse to start.
//!
//! Phase 0 ships license verification only; the grace-period state
//! machine (last_seen + degraded mode) is a follow-up — see `TASKS.md`
//! §0.9.

use std::path::Path;

use anyhow::Context as _;
use shared::license::{LicensePayload, SignedLicense};

use crate::auth::CpPublicKey;

/// Read a signed license from `path` and verify it with the supplied
/// Control-Plane public key. Returns `Ok(None)` if the file does not
/// exist; `Err` for any other I/O / parse / signature failure.
pub fn load_and_verify(
    path: &Path,
    cp_public_key: &CpPublicKey,
) -> anyhow::Result<Option<LoadedLicense>> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e).with_context(|| format!("reading license file {}", path.display()));
        }
    };
    let signed: SignedLicense =
        serde_json::from_slice(&bytes).context("parsing license file as SignedLicense")?;
    let payload_owned = signed
        .verify(cp_public_key.as_bytes())
        .context("verifying license signature")?
        .clone();
    Ok(Some(LoadedLicense {
        payload: payload_owned,
        signed,
    }))
}

/// Persist a signed license to disk. Atomic via tmpfile + rename so a
/// crash mid-write cannot leave an unparseable file in place.
pub fn save(path: &Path, license: &SignedLicense) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating dir {}", parent.display()))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(license).context("serialising license")?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = std::ffi::OsString::from(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("license.json")),
    );
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct LoadedLicense {
    pub payload: LicensePayload,
    pub signed: SignedLicense,
}
