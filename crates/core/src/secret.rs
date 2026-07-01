use crate::api_key_token::ApiKeyToken;
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

    pub fn new_api_key_token(token: ApiKeyToken, now: DateTime<Utc>) -> Self {
        Self {
            id: SecretId::new(),
            kind: SecretKind::ApiKeyToken(token),
            created_at: now,
            updated_at: now,
        }
    }

    pub(crate) fn postgres_from_persisted(
        id: SecretId,
        credential: PostgreSqlCredential,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            kind: SecretKind::PostgreSqlCredential(credential),
            created_at,
            updated_at,
        }
    }

    pub(crate) fn api_key_token_from_persisted(
        id: SecretId,
        token: ApiKeyToken,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            kind: SecretKind::ApiKeyToken(token),
            created_at,
            updated_at,
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
            SecretKind::ApiKeyToken(token) => token.title(),
        }
    }

    pub fn tags(&self) -> &[String] {
        match &self.kind {
            SecretKind::PostgreSqlCredential(credential) => credential.tags(),
            SecretKind::ApiKeyToken(token) => token.tags(),
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

    pub(crate) fn replace_api_key_token(&mut self, token: ApiKeyToken, now: DateTime<Utc>) {
        self.kind = SecretKind::ApiKeyToken(token);
        self.updated_at = now;
    }
}

pub enum SecretKind {
    PostgreSqlCredential(PostgreSqlCredential),
    ApiKeyToken(ApiKeyToken),
}

impl fmt::Debug for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostgreSqlCredential(credential) => formatter
                .debug_tuple("PostgreSqlCredential")
                .field(credential)
                .finish(),
            Self::ApiKeyToken(token) => formatter.debug_tuple("ApiKeyToken").field(token).finish(),
        }
    }
}
