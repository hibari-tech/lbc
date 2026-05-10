//! argon2id password hashing.
//!
//! [`hash`] returns a self-describing PHC string (algorithm, params, salt,
//! hash) ready to store directly in `user.password_hash`. [`verify`] takes
//! that string back and constant-time-compares against a candidate.

use argon2::password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString};
use argon2::Argon2;
use rand_core::OsRng;

pub fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

pub fn verify(password: &str, stored_phc: &str) -> anyhow::Result<bool> {
    let parsed =
        PasswordHash::new(stored_phc).map_err(|e| anyhow::anyhow!("parsing stored hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}
