//! Authentication & RBAC primitives.
//!
//! Phase 0 §0.5 covers the building blocks: [`Role`] enum, [`password`]
//! hashing/verification, and [`token`] JWT issue/verify. Route-level
//! middleware that extracts an authenticated user lands with §0.6, when
//! there are protected endpoints to wire it into.

pub mod password;
pub mod role;
pub mod token;

pub use role::Role;
pub use token::{Claims, JwtSecret};
