use bastion_core::{
    AccountRecovery, AccountRecoveryInput, ApiKeyToken, ApiKeyTokenInput, ApiTokenKind,
    BASTION_VAULT_PATH_ENV, PostgreSqlCredential, RecoveryMaterialInput, RecoveryMaterialKind,
    Secret, SecretFilter, SecretKind, Vault, VaultFileWarning, VaultPersistenceError, backup_path,
    load_vault, resolve_vault_path, save_vault, vault_file_warning,
};
use chrono::{TimeZone, Utc};
use secrecy::ExposeSecret;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use uuid::Uuid;

mod common;

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn saves_and_reloads_empty_encrypted_vault() {
    let path = test_vault_path("empty");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let encrypted = fs::read_to_string(&path).expect("vault file should exist");
    assert!(encrypted.contains("\"magic\":\"BASTION\""));
    assert!(!encrypted.contains("Personal"));

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");

    assert_eq!("Personal", reloaded.name());
    assert_eq!(created_at, reloaded.created_at());
    assert_eq!(created_at, reloaded.updated_at());
    assert!(reloaded.secrets().is_empty());
}

#[test]
fn saves_and_reloads_postgresql_credential() {
    let path = test_vault_path("postgres");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let saved_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 0).unwrap();
    let credential = PostgreSqlCredential::new(common::valid_postgres_input())
        .expect("credential should be valid");
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(Secret::new_postgres(credential, created_at), saved_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let encrypted = fs::read_to_string(&path).expect("vault file should exist");
    assert!(!encrypted.contains("Production DB"));
    assert!(!encrypted.contains("correct horse battery staple"));

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");
    let visible = reloaded.visible_secrets(SecretFilter::All);

    assert_eq!(1, visible.len());
    assert_eq!("Production DB", visible[0].title());
    assert_eq!(created_at, visible[0].created_at());
    assert_eq!(saved_at, reloaded.updated_at());

    let password = match visible[0].kind() {
        SecretKind::PostgreSqlCredential(credential) => credential.password().expose_secret(),
        SecretKind::ApiKeyToken(_) | SecretKind::AccountRecovery(_) => {
            panic!("expected PostgreSQL credential")
        }
    };
    assert_eq!("correct horse battery staple", password);
}

#[test]
fn saves_and_reloads_api_key_token_without_plaintext_leaks() {
    let path = test_vault_path("api-key-token");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let saved_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 0).unwrap();
    let token = ApiKeyToken::new(valid_api_key_token_input()).expect("token should be valid");
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(Secret::new_api_key_token(token, created_at), saved_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let encrypted = fs::read_to_string(&path).expect("vault file should exist");
    assert!(!encrypted.contains("Cloudflare API Token"));
    assert!(!encrypted.contains("cf-secret-token"));

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");
    let visible = reloaded.visible_secrets(SecretFilter::All);

    assert_eq!(1, visible.len());
    assert_eq!("Cloudflare API Token", visible[0].title());
    assert_eq!(created_at, visible[0].created_at());
    assert_eq!(saved_at, reloaded.updated_at());

    let token_value = match visible[0].kind() {
        SecretKind::ApiKeyToken(token) => {
            assert_eq!(ApiTokenKind::ApiKey, token.kind());
            token.token().expose_secret()
        }
        SecretKind::PostgreSqlCredential(_) | SecretKind::AccountRecovery(_) => {
            panic!("expected API key token")
        }
    };
    assert_eq!("cf-secret-token", token_value);
}

#[test]
fn saves_and_reloads_account_recovery_without_plaintext_leaks() {
    let path = test_vault_path("account-recovery");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let saved_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 0).unwrap();
    let recovery = AccountRecovery::new(AccountRecoveryInput {
        title: "GitHub Recovery Codes".to_owned(),
        service: "GitHub".to_owned(),
        account: Some("bogdan".to_owned()),
        url: Some("https://github.com".to_owned()),
        kind: RecoveryMaterialKind::RecoveryCodeSet,
        material: RecoveryMaterialInput::CodeSet("secret-code-one\nsecret-code-two".to_owned()),
        tags: vec!["github".to_owned(), "recovery".to_owned()],
    })
    .expect("account recovery item should be valid");
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(Secret::new_account_recovery(recovery, created_at), saved_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let encrypted = fs::read_to_string(&path).expect("vault file should exist");
    assert!(!encrypted.contains("GitHub Recovery Codes"));
    assert!(!encrypted.contains("secret-code-one"));

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");
    let visible = reloaded.visible_secrets(SecretFilter::All);

    assert_eq!(1, visible.len());
    assert_eq!("GitHub Recovery Codes", visible[0].title());
    assert_eq!(saved_at, reloaded.updated_at());

    let item = match visible[0].kind() {
        SecretKind::AccountRecovery(item) => item,
        SecretKind::PostgreSqlCredential(_) | SecretKind::ApiKeyToken(_) => {
            panic!("expected account recovery item")
        }
    };
    assert_eq!(RecoveryMaterialKind::RecoveryCodeSet, item.kind());
    assert_eq!((2, 2), item.recovery_code_counts());
}

#[test]
fn saves_and_reloads_edited_postgresql_credential() {
    let path = test_vault_path("edited");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let edited_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 10, 0).unwrap();
    let original = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &["production"]))
            .expect("credential should be valid"),
        created_at,
    );
    let secret_id = original.id();
    let replacement = PostgreSqlCredential::new(common::postgres_input("Staging DB", &["staging"]))
        .expect("credential should be valid");
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(original, created_at);
    vault
        .replace_postgres_secret(secret_id, replacement, edited_at)
        .expect("secret should be replaced");

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");
    let visible = reloaded.visible_secrets(SecretFilter::All);

    assert_eq!(1, visible.len());
    assert_eq!("Staging DB", visible[0].title());
    assert_eq!(created_at, visible[0].created_at());
    assert_eq!(edited_at, visible[0].updated_at());
    assert_eq!(edited_at, reloaded.updated_at());
}

#[test]
fn saves_and_reloads_deleted_postgresql_credential() {
    let path = test_vault_path("deleted");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let deleted_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 15, 0).unwrap();
    let secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::valid_postgres_input())
            .expect("credential should be valid"),
        created_at,
    );
    let secret_id = secret.id();
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(secret, created_at);
    vault
        .delete_secret(secret_id, deleted_at)
        .expect("secret should be deleted");

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");

    assert!(reloaded.secrets().is_empty());
    assert_eq!(deleted_at, reloaded.updated_at());
}

#[test]
fn wrong_master_passphrase_fails_safely_without_destroying_vault() {
    let path = test_vault_path("wrong-passphrase");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");

    let error =
        load_vault(&path, "wrong horse battery staple").expect_err("wrong passphrase should fail");

    assert_eq!(VaultPersistenceError::AuthenticationFailed, error);
    assert!(!error.safe_message().contains("wrong horse battery staple"));

    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");
    assert_eq!("Personal", reloaded.name());
}

#[test]
fn unsupported_envelope_version_fails_safely() {
    let path = test_vault_path("unsupported-version");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");
    let mut envelope = read_envelope_json(&path);
    envelope["format_version"] = serde_json::json!(2);
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let error = load_vault(&path, "correct horse battery staple")
        .expect_err("unsupported version should fail");

    assert_eq!(VaultPersistenceError::UnsupportedVersion(2), error);
    assert_eq!("Vault file could not be read.", error.safe_message());
}

#[test]
fn invalid_envelope_fails_safely() {
    let path = test_vault_path("invalid-envelope");
    fs::write(&path, b"not a bastion envelope").expect("invalid envelope should be written");

    let error = load_vault(&path, "correct horse battery staple")
        .expect_err("invalid envelope should fail");

    assert_eq!(VaultPersistenceError::InvalidEnvelope, error);
    assert_eq!("Vault file could not be read.", error.safe_message());
}

#[test]
fn corrupt_ciphertext_fails_safely() {
    let path = test_vault_path("corrupt-ciphertext");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("vault should save");
    let mut envelope = read_envelope_json(&path);
    envelope["ciphertext"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let error = load_vault(&path, "correct horse battery staple")
        .expect_err("corrupt ciphertext should fail");

    assert_eq!(VaultPersistenceError::CorruptCiphertext, error);
    assert_eq!("Vault file could not be read.", error.safe_message());
}

#[test]
fn atomic_save_preserves_previous_encrypted_backup() {
    let path = test_vault_path("backup");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let edited_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 10, 0).unwrap();
    let first = Vault::new_personal(created_at);
    let mut second = Vault::new_personal(created_at);
    second.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(common::valid_postgres_input())
                .expect("credential should be valid"),
            created_at,
        ),
        edited_at,
    );

    save_vault(&path, &first, "correct horse battery staple").expect("first save should work");
    let first_encrypted = fs::read(&path).expect("first vault should exist");

    save_vault(&path, &second, "correct horse battery staple").expect("second save should work");

    let backup = fs::read(backup_path(&path)).expect("backup should exist");
    let current = fs::read(&path).expect("current vault should exist");
    let reloaded = load_vault(&path, "correct horse battery staple").expect("vault should load");

    assert_eq!(first_encrypted, backup);
    assert_ne!(backup, current);
    assert_eq!(1, reloaded.secrets().len());
}

#[test]
fn failed_save_leaves_previous_vault_recoverable() {
    let path = test_vault_path("failed-save");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let first = Vault::new_personal(created_at);
    let mut second = Vault::new_personal(created_at);
    second.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(common::valid_postgres_input())
                .expect("credential should be valid"),
            created_at,
        ),
        created_at,
    );

    save_vault(&path, &first, "correct horse battery staple").expect("first save should work");
    fs::create_dir(backup_path(&path)).expect("backup path should block backup creation");

    let error = save_vault(&path, &second, "correct horse battery staple")
        .expect_err("second save should fail");

    assert_eq!(
        VaultPersistenceError::Io(std::io::ErrorKind::Other.into()),
        error
    );
    let reloaded =
        load_vault(&path, "correct horse battery staple").expect("old vault should load");
    assert!(reloaded.secrets().is_empty());
}

#[test]
fn every_save_uses_fresh_encryption_material() {
    let first_path = test_vault_path("fresh-first");
    let second_path = test_vault_path("fresh-second");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&first_path, &vault, "correct horse battery staple")
        .expect("first save should work");
    save_vault(&second_path, &vault, "correct horse battery staple")
        .expect("second save should work");

    assert_ne!(
        fs::read(&first_path).expect("first vault should exist"),
        fs::read(&second_path).expect("second vault should exist")
    );
}

#[cfg(unix)]
#[test]
fn unix_vault_and_backup_files_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_vault_path("permissions");
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let vault = Vault::new_personal(created_at);

    save_vault(&path, &vault, "correct horse battery staple").expect("first save should work");
    save_vault(&path, &vault, "correct horse battery staple").expect("second save should work");

    let vault_mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let backup_mode = fs::metadata(backup_path(&path))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(0o600, vault_mode);
    assert_eq!(0o600, backup_mode);
}

#[test]
fn bastion_vault_path_env_overrides_default_path() {
    let _guard = ENV_LOCK.lock().unwrap();
    let path = test_vault_path("override");

    unsafe {
        std::env::set_var(BASTION_VAULT_PATH_ENV, &path);
    }
    let resolved = resolve_vault_path().expect("vault path should resolve");
    unsafe {
        std::env::remove_var(BASTION_VAULT_PATH_ENV);
    }

    assert_eq!(path, resolved);
}

#[cfg(unix)]
#[test]
fn unix_group_or_world_readable_vault_produces_warning() {
    use std::os::unix::fs::PermissionsExt;

    let path = test_vault_path("readable-warning");
    fs::write(&path, b"placeholder").expect("vault file should be written");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

    assert_eq!(
        Some(VaultFileWarning::InsecurePermissions),
        vault_file_warning(&path).expect("warning check should work")
    );
}

fn read_envelope_json(path: &PathBuf) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).expect("vault file should exist"))
        .expect("vault envelope should be json")
}

fn test_vault_path(label: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!("bastion-{label}-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).expect("test directory should be created");
    directory.join("vault.bst")
}

fn valid_api_key_token_input() -> ApiKeyTokenInput {
    ApiKeyTokenInput {
        title: "Cloudflare API Token".to_owned(),
        service: "Cloudflare".to_owned(),
        kind: ApiTokenKind::ApiKey,
        token: "cf-secret-token".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: Some("https://dash.cloudflare.com".to_owned()),
        tags: vec!["production".to_owned()],
    }
}
