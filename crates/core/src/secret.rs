use crate::ids::SecretId;
use crate::postgres::PostgreSqlCredential;
use chrono::{DateTime, Utc};
use std::fmt;

pub struct Secret {
    id: SecretId,
    kind: SecretKind,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Secret")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

impl Secret {
    pub fn new_postgres(credential: PostgreSqlCredential, now: DateTime<Utc>) -> Self {
        Self {
            id: SecretId::new(),
            kind: SecretKind::PostgreSqlCredential(credential),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn id(&self) -> SecretId {
        self.id
    }

    pub fn kind(&self) -> &SecretKind {
        &self.kind
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn title(&self) -> &str {
        match &self.kind {
            SecretKind::PostgreSqlCredential(credential) => credential.title(),
        }
    }

    pub fn tags(&self) -> &[String] {
        match &self.kind {
            SecretKind::PostgreSqlCredential(credential) => credential.tags(),
        }
    }

    pub(crate) fn replace_postgres(
        &mut self,
        credential: PostgreSqlCredential,
        now: DateTime<Utc>,
    ) {
        self.kind = SecretKind::PostgreSqlCredential(credential);
        self.updated_at = now;
    }
}

pub enum SecretKind {
    PostgreSqlCredential(PostgreSqlCredential),
}

impl fmt::Debug for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostgreSqlCredential(credential) => formatter
                .debug_tuple("PostgreSqlCredential")
                .field(credential)
                .finish(),
        }
    }
}
