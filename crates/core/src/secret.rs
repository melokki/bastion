use crate::account_recovery::AccountRecovery;
use crate::api_key_token::ApiKeyToken;
use crate::ids::SecretId;
use crate::postgres::{DatabaseCredential, PostgreSqlCredential};
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
        Self::new_database_credential(credential, now)
    }

    pub fn new_database_credential(credential: DatabaseCredential, now: DateTime<Utc>) -> Self {
        Self {
            id: SecretId::new(),
            kind: SecretKind::DatabaseCredential(credential),
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

    pub fn new_account_recovery(item: AccountRecovery, now: DateTime<Utc>) -> Self {
        Self {
            id: SecretId::new(),
            kind: SecretKind::AccountRecovery(item),
            created_at: now,
            updated_at: now,
        }
    }

    pub(crate) fn database_credential_from_persisted(
        id: SecretId,
        credential: DatabaseCredential,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            kind: SecretKind::DatabaseCredential(credential),
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

    pub(crate) fn account_recovery_from_persisted(
        id: SecretId,
        item: AccountRecovery,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            kind: SecretKind::AccountRecovery(item),
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
            SecretKind::DatabaseCredential(credential) => credential.title(),
            SecretKind::ApiKeyToken(token) => token.title(),
            SecretKind::AccountRecovery(item) => item.title(),
        }
    }

    pub fn tags(&self) -> &[String] {
        match &self.kind {
            SecretKind::DatabaseCredential(credential) => credential.tags(),
            SecretKind::ApiKeyToken(token) => token.tags(),
            SecretKind::AccountRecovery(item) => item.tags(),
        }
    }

    pub(crate) fn replace_postgres(
        &mut self,
        credential: PostgreSqlCredential,
        now: DateTime<Utc>,
    ) {
        self.replace_database_credential(credential, now);
    }

    pub(crate) fn replace_database_credential(
        &mut self,
        credential: DatabaseCredential,
        now: DateTime<Utc>,
    ) {
        self.kind = SecretKind::DatabaseCredential(credential);
        self.updated_at = now;
    }

    pub(crate) fn replace_api_key_token(&mut self, token: ApiKeyToken, now: DateTime<Utc>) {
        self.kind = SecretKind::ApiKeyToken(token);
        self.updated_at = now;
    }
}

pub enum SecretKind {
    DatabaseCredential(DatabaseCredential),
    ApiKeyToken(ApiKeyToken),
    AccountRecovery(AccountRecovery),
}

impl fmt::Debug for SecretKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DatabaseCredential(credential) => formatter
                .debug_tuple("DatabaseCredential")
                .field(credential)
                .finish(),
            Self::ApiKeyToken(token) => formatter.debug_tuple("ApiKeyToken").field(token).finish(),
            Self::AccountRecovery(item) => formatter
                .debug_tuple("AccountRecovery")
                .field(item)
                .finish(),
        }
    }
}
