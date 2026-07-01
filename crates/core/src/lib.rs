mod api_key_token;
mod filtering;
mod ids;
mod persistence;
mod postgres;
mod secret;
mod sorting;
mod tags;
mod validation;
mod vault;

pub use api_key_token::{ApiKeyToken, ApiKeyTokenInput};
pub use filtering::SecretFilter;
pub use ids::{SecretId, VaultId};
pub use persistence::{
    BASTION_VAULT_PATH_ENV, VaultFileWarning, VaultPersistenceError, backup_path, load_vault,
    resolve_vault_path, save_vault, vault_file_warning,
};
pub use postgres::{PostgreSqlCredential, PostgreSqlCredentialInput};
pub use secret::{Secret, SecretKind};
pub use validation::{ValidationError, validate_master_passphrase};
pub use vault::{TagCounts, Vault, VaultMutationError};

pub fn app_name() -> &'static str {
    "Bastion"
}
