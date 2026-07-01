use crate::{
    PostgreSqlCredential, PostgreSqlCredentialInput, Secret, SecretId, SecretKind, ValidationError,
    Vault, VaultId,
};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use chrono::{DateTime, Utc};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use std::{
    env, fmt, fs, io,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const MAGIC: &str = "BASTION";
const FORMAT_VERSION: u16 = 1;
const KDF_NAME: &str = "argon2id";
const CIPHER_NAME: &str = "xchacha20poly1305";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const ARGON2_MEMORY_COST_KIB: u32 = 19_456;
const ARGON2_TIME_COST: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;
pub const BASTION_VAULT_PATH_ENV: &str = "BASTION_VAULT_PATH";

#[derive(Debug)]
pub enum VaultPersistenceError {
    AuthenticationFailed,
    CorruptCiphertext,
    InvalidEnvelope,
    Io(io::Error),
    PathUnavailable,
    UnsupportedVersion(u16),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultFileWarning {
    InsecurePermissions,
}

impl VaultPersistenceError {
    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Could not unlock vault. Check the master passphrase.",
            Self::CorruptCiphertext | Self::InvalidEnvelope | Self::UnsupportedVersion(_) => {
                "Vault file could not be read."
            }
            Self::Io(_) => "Vault file could not be accessed.",
            Self::PathUnavailable => "Vault path could not be resolved.",
        }
    }
}

impl PartialEq for VaultPersistenceError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::AuthenticationFailed, Self::AuthenticationFailed)
            | (Self::CorruptCiphertext, Self::CorruptCiphertext)
            | (Self::InvalidEnvelope, Self::InvalidEnvelope)
            | (Self::Io(_), Self::Io(_))
            | (Self::PathUnavailable, Self::PathUnavailable) => true,
            (Self::UnsupportedVersion(left), Self::UnsupportedVersion(right)) => left == right,
            _ => false,
        }
    }
}

impl Eq for VaultPersistenceError {}

impl fmt::Display for VaultPersistenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.safe_message())
    }
}

impl std::error::Error for VaultPersistenceError {}

impl From<io::Error> for VaultPersistenceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn save_vault(
    path: &Path,
    vault: &Vault,
    master_passphrase: &str,
) -> Result<(), VaultPersistenceError> {
    let envelope = encrypt_vault(vault, master_passphrase)?;
    let bytes =
        serde_json::to_vec(&envelope).map_err(|_| VaultPersistenceError::InvalidEnvelope)?;

    write_atomic(path, &bytes)
}

pub fn load_vault(path: &Path, master_passphrase: &str) -> Result<Vault, VaultPersistenceError> {
    let bytes = fs::read(path)?;
    let envelope: VaultEnvelope =
        serde_json::from_slice(&bytes).map_err(|_| VaultPersistenceError::InvalidEnvelope)?;

    decrypt_vault(envelope, master_passphrase)
}

pub fn resolve_vault_path() -> Result<PathBuf, VaultPersistenceError> {
    if let Some(path) = env::var_os(BASTION_VAULT_PATH_ENV).filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path));
    }

    default_vault_path()
}

#[cfg(unix)]
pub fn vault_file_warning(path: &Path) -> Result<Option<VaultFileWarning>, VaultPersistenceError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        Ok(Some(VaultFileWarning::InsecurePermissions))
    } else {
        Ok(None)
    }
}

#[cfg(not(unix))]
pub fn vault_file_warning(_path: &Path) -> Result<Option<VaultFileWarning>, VaultPersistenceError> {
    Ok(None)
}

#[cfg(target_os = "linux")]
fn default_vault_path() -> Result<PathBuf, VaultPersistenceError> {
    if let Some(data_home) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(data_home).join("bastion").join("vault.bst"));
    }

    let home = env::var_os("HOME").ok_or(VaultPersistenceError::PathUnavailable)?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("bastion")
        .join("vault.bst"))
}

#[cfg(target_os = "macos")]
fn default_vault_path() -> Result<PathBuf, VaultPersistenceError> {
    let home = env::var_os("HOME").ok_or(VaultPersistenceError::PathUnavailable)?;
    Ok(PathBuf::from(home)
        .join("Library")
        .join("Application Support")
        .join("Bastion")
        .join("vault.bst"))
}

#[cfg(target_os = "windows")]
fn default_vault_path() -> Result<PathBuf, VaultPersistenceError> {
    let app_data = env::var_os("APPDATA").ok_or(VaultPersistenceError::PathUnavailable)?;
    Ok(PathBuf::from(app_data).join("Bastion").join("vault.bst"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn default_vault_path() -> Result<PathBuf, VaultPersistenceError> {
    Err(VaultPersistenceError::PathUnavailable)
}

fn encrypt_vault(
    vault: &Vault,
    master_passphrase: &str,
) -> Result<VaultEnvelope, VaultPersistenceError> {
    let salt = random_vec(SALT_LEN);
    let nonce_bytes = random_vec(NONCE_LEN);
    let kdf = KdfEnvelope::argon2id();
    let key = derive_key(master_passphrase, &salt, &kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;
    let nonce = XNonce::try_from(nonce_bytes.as_slice())
        .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;
    let payload = VaultPayload::from_vault(vault);
    let plaintext =
        serde_json::to_vec(&payload).map_err(|_| VaultPersistenceError::CorruptCiphertext)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| VaultPersistenceError::CorruptCiphertext)?;

    Ok(VaultEnvelope {
        magic: MAGIC.to_owned(),
        format_version: FORMAT_VERSION,
        kdf,
        cipher: CIPHER_NAME.to_owned(),
        salt,
        nonce: nonce_bytes,
        ciphertext,
    })
}

fn decrypt_vault(
    envelope: VaultEnvelope,
    master_passphrase: &str,
) -> Result<Vault, VaultPersistenceError> {
    validate_envelope(&envelope)?;

    let key = derive_key(master_passphrase, &envelope.salt, &envelope.kdf)?;
    let cipher = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;
    let nonce = XNonce::try_from(envelope.nonce.as_slice())
        .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;
    let plaintext = cipher
        .decrypt(&nonce, envelope.ciphertext.as_ref())
        .map_err(|_| VaultPersistenceError::AuthenticationFailed)?;
    let payload: VaultPayload =
        serde_json::from_slice(&plaintext).map_err(|_| VaultPersistenceError::CorruptCiphertext)?;

    payload.into_vault()
}

fn validate_envelope(envelope: &VaultEnvelope) -> Result<(), VaultPersistenceError> {
    if envelope.magic != MAGIC || envelope.cipher != CIPHER_NAME {
        return Err(VaultPersistenceError::InvalidEnvelope);
    }

    if envelope.format_version != FORMAT_VERSION {
        return Err(VaultPersistenceError::UnsupportedVersion(
            envelope.format_version,
        ));
    }

    if envelope.kdf.name != KDF_NAME
        || envelope.kdf.output_len != KEY_LEN
        || envelope.salt.len() != SALT_LEN
        || envelope.nonce.len() != NONCE_LEN
    {
        return Err(VaultPersistenceError::InvalidEnvelope);
    }

    if envelope.ciphertext.is_empty() {
        return Err(VaultPersistenceError::CorruptCiphertext);
    }

    Ok(())
}

fn derive_key(
    master_passphrase: &str,
    salt: &[u8],
    kdf: &KdfEnvelope,
) -> Result<[u8; KEY_LEN], VaultPersistenceError> {
    let params = Params::new(
        kdf.memory_cost_kib,
        kdf.time_cost,
        kdf.parallelism,
        Some(kdf.output_len),
    )
    .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0_u8; KEY_LEN];

    argon2
        .hash_password_into(master_passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| VaultPersistenceError::InvalidEnvelope)?;

    Ok(key)
}

fn random_vec(len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len];
    getrandom::fill(&mut bytes).expect("operating system random source should be available");
    bytes
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), VaultPersistenceError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let temp_path = temporary_path(path);
    write_new_file(&temp_path, bytes)?;

    if path.exists() {
        fs::copy(path, backup_path(path))?;
        set_private_permissions(&backup_path(path))?;
    }

    fs::rename(&temp_path, path)?;
    set_private_permissions(path)?;
    sync_parent_directory(parent);

    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), VaultPersistenceError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    apply_private_mode(&mut options);

    let mut file = options.open(path)?;
    use io::Write;
    file.write_all(bytes)?;
    file.sync_all()?;

    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.bst");
    path.with_file_name(format!(".{file_name}.tmp-{}", Uuid::new_v4()))
}

pub fn backup_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("vault.bst");
    path.with_file_name(format!("{file_name}.bak"))
}

#[cfg(unix)]
fn apply_private_mode(options: &mut fs::OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn apply_private_mode(_options: &mut fs::OpenOptions) {}

#[cfg(unix)]
fn set_private_permissions(path: &Path) -> Result<(), VaultPersistenceError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path) -> Result<(), VaultPersistenceError> {
    Ok(())
}

fn sync_parent_directory(parent: &Path) {
    if let Ok(directory) = fs::OpenOptions::new().read(true).open(parent) {
        let _ = directory.sync_all();
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct VaultEnvelope {
    magic: String,
    format_version: u16,
    kdf: KdfEnvelope,
    cipher: String,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct KdfEnvelope {
    name: String,
    memory_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
    output_len: usize,
}

impl KdfEnvelope {
    fn argon2id() -> Self {
        Self {
            name: KDF_NAME.to_owned(),
            memory_cost_kib: ARGON2_MEMORY_COST_KIB,
            time_cost: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            output_len: KEY_LEN,
        }
    }
}

#[derive(Deserialize, Serialize)]
struct VaultPayload {
    id: Uuid,
    name: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    secrets: Vec<SecretPayload>,
}

impl VaultPayload {
    fn from_vault(vault: &Vault) -> Self {
        Self {
            id: vault.id().as_uuid(),
            name: vault.name().to_owned(),
            created_at: vault.created_at(),
            updated_at: vault.updated_at(),
            secrets: vault
                .secrets()
                .iter()
                .map(SecretPayload::from_secret)
                .collect(),
        }
    }

    fn into_vault(self) -> Result<Vault, VaultPersistenceError> {
        let secrets = self
            .secrets
            .into_iter()
            .map(SecretPayload::into_secret)
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Vault::from_persisted(
            VaultId::from_uuid(self.id),
            self.name,
            self.created_at,
            self.updated_at,
            secrets,
        ))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SecretPayload {
    PostgreSqlCredential {
        id: Uuid,
        created_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
        title: String,
        hostname: String,
        port: u16,
        database: String,
        username: String,
        password: String,
        schema: Option<String>,
        tags: Vec<String>,
    },
}

impl SecretPayload {
    fn from_secret(secret: &Secret) -> Self {
        match secret.kind() {
            SecretKind::PostgreSqlCredential(credential) => Self::PostgreSqlCredential {
                id: secret.id().as_uuid(),
                created_at: secret.created_at(),
                updated_at: secret.updated_at(),
                title: credential.title().to_owned(),
                hostname: credential.hostname().to_owned(),
                port: credential.port(),
                database: credential.database().to_owned(),
                username: credential.username().to_owned(),
                password: credential.password().expose_secret().to_owned(),
                schema: credential.schema().map(str::to_owned),
                tags: credential.tags().to_vec(),
            },
        }
    }

    fn into_secret(self) -> Result<Secret, VaultPersistenceError> {
        match self {
            Self::PostgreSqlCredential {
                id,
                created_at,
                updated_at,
                title,
                hostname,
                port,
                database,
                username,
                password,
                schema,
                tags,
            } => {
                let credential = PostgreSqlCredential::from_persisted(PostgreSqlCredentialInput {
                    title,
                    hostname,
                    port,
                    database,
                    username,
                    password,
                    schema,
                    tags,
                })
                .map_err(corrupt_payload)?;

                Ok(Secret::postgres_from_persisted(
                    SecretId::from_uuid(id),
                    credential,
                    created_at,
                    updated_at,
                ))
            }
        }
    }
}

fn corrupt_payload(_error: ValidationError) -> VaultPersistenceError {
    VaultPersistenceError::CorruptCiphertext
}
