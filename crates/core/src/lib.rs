mod filtering;
mod ids;
mod postgres;
mod secret;
mod sorting;
mod tags;
mod validation;
mod vault;

pub use filtering::SecretFilter;
pub use ids::{SecretId, VaultId};
pub use postgres::{PostgreSqlCredential, PostgreSqlCredentialInput};
pub use secret::{Secret, SecretKind};
pub use validation::{ValidationError, validate_master_passphrase};
pub use vault::{TagCounts, Vault, VaultMutationError};

pub fn app_name() -> &'static str {
    "Bastion"
}
