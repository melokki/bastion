use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultId(Uuid);

impl VaultId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for VaultId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretId(Uuid);

impl SecretId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}
