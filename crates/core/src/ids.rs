use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VaultId(Uuid);

impl VaultId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub(crate) fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
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

    pub(crate) fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CustomFieldId(Uuid);

impl CustomFieldId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub(crate) fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for CustomFieldId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecoveryCodeId(Uuid);

impl RecoveryCodeId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub(crate) fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for RecoveryCodeId {
    fn default() -> Self {
        Self::new()
    }
}
