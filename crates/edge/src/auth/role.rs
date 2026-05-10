//! RBAC roles for LBC edge users.
//!
//! The privilege ordering is:
//! `admin > manager > auditor > operator > installer > viewer`.
//! Use [`Role::has_at_least`] to gate operations by minimum role.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Manager,
    Auditor,
    Operator,
    Installer,
    Viewer,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Manager => "manager",
            Self::Auditor => "auditor",
            Self::Operator => "operator",
            Self::Installer => "installer",
            Self::Viewer => "viewer",
        }
    }

    fn rank(self) -> u8 {
        match self {
            Self::Admin => 60,
            Self::Manager => 50,
            Self::Auditor => 40,
            Self::Operator => 30,
            Self::Installer => 20,
            Self::Viewer => 10,
        }
    }

    pub fn has_at_least(self, required: Self) -> bool {
        self.rank() >= required.rank()
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Role {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> anyhow::Result<Self> {
        match s {
            "admin" => Ok(Self::Admin),
            "manager" => Ok(Self::Manager),
            "auditor" => Ok(Self::Auditor),
            "operator" => Ok(Self::Operator),
            "installer" => Ok(Self::Installer),
            "viewer" => Ok(Self::Viewer),
            other => Err(anyhow::anyhow!("unknown role: {other}")),
        }
    }
}
