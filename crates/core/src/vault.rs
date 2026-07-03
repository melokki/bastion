use crate::api_key_token::ApiKeyToken;
use crate::custom_field::CustomField;
use crate::filtering::SecretFilter;
use crate::ids::{RecoveryCodeId, SecretId, VaultId};
use crate::postgres::{DatabaseCredential, PostgreSqlCredential};
use crate::rotation::RotationMetadata;
use crate::rotation::RotationStatus;
use crate::secret::{Secret, SecretKind};
use crate::sorting::visible_secret_order;
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;
use std::fmt;

pub struct Vault {
    id: VaultId,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    secrets: Vec<Secret>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Vault")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("secrets", &self.secrets)
            .finish()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum VaultMutationError {
    SecretNotFound,
    InvalidSecretShape,
}

impl Vault {
    pub fn new_personal(now: DateTime<Utc>) -> Self {
        Self {
            id: VaultId::new(),
            name: "Personal".to_owned(),
            created_at: now,
            updated_at: now,
            secrets: Vec::new(),
        }
    }

    pub(crate) fn from_persisted(
        id: VaultId,
        name: String,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        secrets: Vec<Secret>,
    ) -> Self {
        Self {
            id,
            name,
            created_at,
            updated_at,
            secrets,
        }
    }

    pub fn id(&self) -> VaultId {
        self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn created_at(&self) -> DateTime<Utc> {
        self.created_at
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at
    }

    pub fn secrets(&self) -> &[Secret] {
        &self.secrets
    }

    pub fn add_secret(&mut self, secret: Secret, now: DateTime<Utc>) {
        self.secrets.push(secret);
        self.updated_at = now;
    }

    pub fn tag_counts(&self) -> TagCounts {
        let mut counts = TagCounts {
            all: self.secrets.len(),
            untagged: 0,
            tags: BTreeMap::new(),
        };

        for secret in &self.secrets {
            let tags = secret.tags();
            if tags.is_empty() {
                counts.untagged += 1;
            }

            for tag in tags {
                *counts.tags.entry(tag.to_owned()).or_default() += 1;
            }
        }

        counts
    }

    pub fn visible_secrets(&self, filter: SecretFilter<'_>) -> Vec<&Secret> {
        let mut secrets = self
            .secrets
            .iter()
            .filter(|secret| match filter {
                SecretFilter::All => true,
                SecretFilter::Untagged => secret.tags().is_empty(),
                SecretFilter::Tag(tag) => secret.tags().iter().any(|secret_tag| secret_tag == tag),
            })
            .collect::<Vec<_>>();

        secrets.sort_by(visible_secret_order);

        secrets
    }

    pub fn search_visible_secrets(&self, filter: SecretFilter<'_>, query: &str) -> Vec<&Secret> {
        let query = query.trim();
        if query.is_empty() {
            return self.visible_secrets(filter);
        }

        let query = query.to_lowercase();
        self.visible_secrets(filter)
            .into_iter()
            .filter(|secret| secret_matches_query(secret, &query))
            .collect()
    }

    pub fn replace_postgres_secret(
        &mut self,
        secret_id: SecretId,
        credential: PostgreSqlCredential,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret.replace_postgres(credential, now);
        self.updated_at = now;

        Ok(())
    }

    pub fn replace_database_credential_secret(
        &mut self,
        secret_id: SecretId,
        credential: DatabaseCredential,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret.replace_database_credential(credential, now);
        self.updated_at = now;

        Ok(())
    }

    pub fn replace_api_key_token_secret(
        &mut self,
        secret_id: SecretId,
        token: ApiKeyToken,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret.replace_api_key_token(token, now);
        self.updated_at = now;

        Ok(())
    }

    pub fn delete_secret(
        &mut self,
        secret_id: SecretId,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let index = self
            .secrets
            .iter()
            .position(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        self.secrets.remove(index);
        self.updated_at = now;

        Ok(())
    }

    pub fn mark_recovery_code_used(
        &mut self,
        secret_id: SecretId,
        code_id: RecoveryCodeId,
        used_at: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret
            .mark_recovery_code_used(code_id, used_at)
            .map_err(|_| VaultMutationError::InvalidSecretShape)?;
        self.updated_at = used_at;

        Ok(())
    }

    pub fn mark_recovery_code_unused(
        &mut self,
        secret_id: SecretId,
        code_id: RecoveryCodeId,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret
            .mark_recovery_code_unused(code_id)
            .map_err(|_| VaultMutationError::InvalidSecretShape)?;
        self.updated_at = now;

        Ok(())
    }

    pub fn replace_secret_metadata(
        &mut self,
        secret_id: SecretId,
        custom_fields: Vec<CustomField>,
        rotation: RotationMetadata,
        now: DateTime<Utc>,
    ) -> Result<(), VaultMutationError> {
        let secret = self
            .secrets
            .iter_mut()
            .find(|secret| secret.id() == secret_id)
            .ok_or(VaultMutationError::SecretNotFound)?;

        secret.set_custom_fields(custom_fields, now);
        secret.set_rotation(rotation, now);
        self.updated_at = now;

        Ok(())
    }
}

fn secret_matches_query(secret: &Secret, query: &str) -> bool {
    if let Some(matches_filter) = secret_matches_metadata_filter(secret, query) {
        return matches_filter;
    }

    if secret.custom_fields().iter().any(|field| {
        contains_query(field.label(), query)
            || (!field.is_sensitive() && contains_query(field.display_value(), query))
    }) {
        return true;
    }

    match secret.kind() {
        SecretKind::DatabaseCredential(credential) => {
            contains_query(credential.title(), query)
                || contains_query(credential.engine().label(), query)
                || contains_query(credential.hostname(), query)
                || contains_query(&credential.port().to_string(), query)
                || contains_query(credential.database(), query)
                || contains_query(credential.username(), query)
                || credential
                    .schema()
                    .is_some_and(|schema| contains_query(schema, query))
                || credential
                    .tags()
                    .iter()
                    .any(|tag| contains_query(tag, query))
        }
        SecretKind::ApiKeyToken(token) => {
            contains_query(token.title(), query)
                || contains_query(token.service(), query)
                || contains_query(token.kind().label(), query)
                || token
                    .account()
                    .is_some_and(|account| contains_query(account, query))
                || token.url().is_some_and(|url| contains_query(url, query))
                || token.tags().iter().any(|tag| contains_query(tag, query))
        }
        SecretKind::AccountRecovery(item) => {
            contains_query(item.title(), query)
                || contains_query(item.service(), query)
                || item
                    .account()
                    .is_some_and(|account| contains_query(account, query))
                || item.url().is_some_and(|url| contains_query(url, query))
                || contains_query(item.kind().label(), query)
                || contains_query(item.format().label(), query)
                || item.tags().iter().any(|tag| contains_query(tag, query))
        }
    }
}

fn secret_matches_metadata_filter(secret: &Secret, query: &str) -> Option<bool> {
    let rotation = secret.rotation();
    let status = rotation.status(Utc::now());
    let matches = match query {
        "rotation:configured" | "expires:any" => rotation.is_configured(),
        "rotation:none" | "expires:none" => !rotation.is_configured(),
        "rotation:expired" | "expires:expired" | "expired:true" => {
            status == RotationStatus::Expired
        }
        "rotation:due" | "expires:due" | "due:true" => matches!(
            status,
            RotationStatus::Due | RotationStatus::DueSoon | RotationStatus::Expired
        ),
        "rotation:soon" | "expires:soon" => status == RotationStatus::DueSoon,
        "rotation:healthy" => status == RotationStatus::Healthy,
        _ => return None,
    };

    Some(matches)
}

fn contains_query(value: &str, query: &str) -> bool {
    value.to_lowercase().contains(query)
}

#[derive(Debug, PartialEq, Eq)]
pub struct TagCounts {
    pub all: usize,
    pub untagged: usize,
    pub tags: BTreeMap<String, usize>,
}
