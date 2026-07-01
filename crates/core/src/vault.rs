use crate::filtering::SecretFilter;
use crate::ids::{SecretId, VaultId};
use crate::postgres::PostgreSqlCredential;
use crate::secret::Secret;
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
}

#[derive(Debug, PartialEq, Eq)]
pub struct TagCounts {
    pub all: usize,
    pub untagged: usize,
    pub tags: BTreeMap<String, usize>,
}
