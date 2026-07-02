mod account_recovery;
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

pub use account_recovery::{
    AccountRecovery, AccountRecoveryInput, RecoveryCode, RecoveryCodeStatus, RecoveryFileReference,
    RecoveryInstructions, RecoveryKey, RecoveryMaterial, RecoveryMaterialFormat,
    RecoveryMaterialInput, RecoveryMaterialKind, RecoveryPhrase, SecurityQuestion,
    SecurityQuestionInput,
};
pub use api_key_token::{ApiKeyToken, ApiKeyTokenInput, ApiTokenKind};
pub use filtering::SecretFilter;
pub use ids::{SecretId, VaultId};
pub use persistence::{
    BASTION_VAULT_PATH_ENV, VaultFileWarning, VaultPersistenceError, backup_path, load_vault,
    resolve_vault_path, save_vault, vault_file_warning,
};
pub use postgres::{
    DatabaseCredential, DatabaseCredentialInput, DatabaseEngine, PostgreSqlCredential,
    PostgreSqlCredentialInput, SECRET_CONNECTION_STRING_MASK,
};
pub use secret::{Secret, SecretKind};
pub use validation::{ValidationError, validate_master_passphrase};
pub use vault::{TagCounts, Vault, VaultMutationError};

pub fn app_name() -> &'static str {
    "Bastion"
}
