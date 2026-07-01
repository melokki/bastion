use bastion_core::{
    ApiKeyToken, ApiKeyTokenInput, PostgreSqlCredential, Secret, SecretFilter, SecretKind, Vault,
};
use chrono::{TimeZone, Utc};
use secrecy::ExposeSecret;

mod common;

#[test]
fn creates_personal_vault_and_postgresql_secret_with_timestamps() {
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let credential = PostgreSqlCredential::new(common::valid_postgres_input())
        .expect("credential should be valid");

    let vault = Vault::new_personal(now);
    let secret = Secret::new_postgres(credential, now);

    assert_eq!("Personal", vault.name());
    assert_eq!(now, vault.created_at());
    assert_eq!(now, vault.updated_at());
    assert!(vault.secrets().is_empty());

    assert_eq!(now, secret.created_at());
    assert_eq!(now, secret.updated_at());
    assert!(matches!(secret.kind(), SecretKind::PostgreSqlCredential(_)));
}

#[test]
fn creates_api_key_token_secret_and_searches_metadata_without_token_plaintext() {
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let token = ApiKeyToken::new(valid_api_key_token_input()).expect("token should be valid");
    let secret = Secret::new_api_key_token(token, now);
    let mut vault = Vault::new_personal(now);
    let secret_id = secret.id();

    vault.add_secret(secret, now);

    assert_eq!("Cloudflare API Token", vault.secrets()[0].title());
    assert_eq!(["production"], vault.secrets()[0].tags());
    assert!(matches!(
        vault.secrets()[0].kind(),
        SecretKind::ApiKeyToken(_)
    ));

    let service_titles = vault
        .search_visible_secrets(SecretFilter::All, "cloudflare")
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();
    assert_eq!(vec!["Cloudflare API Token"], service_titles);

    assert!(
        vault
            .search_visible_secrets(SecretFilter::All, "cf-secret-token")
            .is_empty()
    );

    let replacement = ApiKeyToken::new(ApiKeyTokenInput {
        title: "Fastly Token".to_owned(),
        service: "Fastly".to_owned(),
        token: "fastly-secret-token".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: Some("https://manage.fastly.com".to_owned()),
        tags: vec!["edge".to_owned()],
    })
    .expect("replacement should be valid");
    let edited_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 10, 0).unwrap();

    vault
        .replace_api_key_token_secret(secret_id, replacement, edited_at)
        .expect("secret should be replaced");

    assert_eq!("Fastly Token", vault.secrets()[0].title());
    assert_eq!(edited_at, vault.secrets()[0].updated_at());
    assert_eq!(edited_at, vault.updated_at());
}

#[test]
fn counts_and_filters_secrets_by_tag() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let updated_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 5, 0).unwrap();
    let production = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &["production"]))
            .expect("credential should be valid"),
        created_at,
    );
    let local = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Local DB", &[]))
            .expect("credential should be valid"),
        created_at,
    );
    let mut vault = Vault::new_personal(created_at);

    vault.add_secret(production, updated_at);
    vault.add_secret(local, updated_at);

    let counts = vault.tag_counts();
    assert_eq!(2, counts.all);
    assert_eq!(1, counts.untagged);
    assert_eq!(Some(&1), counts.tags.get("production"));
    assert_eq!(updated_at, vault.updated_at());

    let production_titles = vault
        .visible_secrets(SecretFilter::Tag("production"))
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();
    assert_eq!(vec!["Production DB"], production_titles);

    let untagged_titles = vault
        .visible_secrets(SecretFilter::Untagged)
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();
    assert_eq!(vec!["Local DB"], untagged_titles);
}

#[test]
fn allows_duplicate_secret_titles() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let mut vault = Vault::new_personal(created_at);
    let first = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &["production"]))
            .expect("credential should be valid"),
        created_at,
    );
    let second = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &["staging"]))
            .expect("credential should be valid"),
        created_at,
    );

    vault.add_secret(first, created_at);
    vault.add_secret(second, created_at);

    let visible = vault.visible_secrets(SecretFilter::All);
    assert_eq!(2, visible.len());
    assert_eq!("Production DB", visible[0].title());
    assert_eq!("Production DB", visible[1].title());
    assert_ne!(visible[0].id(), visible[1].id());
}

#[test]
fn sorts_visible_secrets_deterministically() {
    let first_created = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let second_created = Utc.with_ymd_and_hms(2026, 7, 1, 12, 1, 0).unwrap();
    let mut vault = Vault::new_personal(first_created);

    for (title, created_at) in [
        ("zeta DB", first_created),
        ("Alpha DB", second_created),
        ("alpha db", first_created),
        ("Beta DB", first_created),
    ] {
        vault.add_secret(
            Secret::new_postgres(
                PostgreSqlCredential::new(common::postgres_input(title, &[]))
                    .expect("credential should be valid"),
                created_at,
            ),
            created_at,
        );
    }

    let titles = vault
        .visible_secrets(SecretFilter::All)
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();

    assert_eq!(vec!["alpha db", "Alpha DB", "Beta DB", "zeta DB"], titles);
}

#[test]
fn searches_visible_secrets_without_matching_password_plaintext() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let mut vault = Vault::new_personal(created_at);
    let mut production_input = common::postgres_input("Production DB", &["production"]);
    production_input.hostname = "prod.db.example.com".to_owned();
    production_input.database = "customer_records".to_owned();
    production_input.username = "prod_app".to_owned();
    production_input.password = "needle-password".to_owned();
    let mut local_input = common::postgres_input("Local DB", &["local"]);
    local_input.hostname = "localhost".to_owned();
    local_input.database = "scratch".to_owned();
    local_input.username = "developer".to_owned();

    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(production_input).expect("credential should be valid"),
            created_at,
        ),
        created_at,
    );
    vault.add_secret(
        Secret::new_postgres(
            PostgreSqlCredential::new(local_input).expect("credential should be valid"),
            created_at,
        ),
        created_at,
    );

    let local_titles = vault
        .search_visible_secrets(SecretFilter::All, "LOCAL")
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();
    assert_eq!(vec!["Local DB"], local_titles);

    let production_titles = vault
        .search_visible_secrets(SecretFilter::Tag("production"), "customer")
        .iter()
        .map(|secret| secret.title())
        .collect::<Vec<_>>();
    assert_eq!(vec!["Production DB"], production_titles);

    assert!(
        vault
            .search_visible_secrets(SecretFilter::All, "needle-password")
            .is_empty()
    );
}

#[test]
fn editing_postgresql_secret_updates_secret_and_vault_timestamps() {
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

    let visible = vault.visible_secrets(SecretFilter::All);
    assert_eq!("Staging DB", visible[0].title());
    assert_eq!(edited_at, visible[0].updated_at());
    assert_eq!(edited_at, vault.updated_at());
}

#[test]
fn deleting_secret_removes_it_and_updates_vault_timestamp() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let deleted_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 15, 0).unwrap();
    let secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &["production"]))
            .expect("credential should be valid"),
        created_at,
    );
    let secret_id = secret.id();
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(secret, created_at);

    vault
        .delete_secret(secret_id, deleted_at)
        .expect("secret should be deleted");

    assert!(vault.secrets().is_empty());
    assert_eq!(0, vault.tag_counts().all);
    assert_eq!(deleted_at, vault.updated_at());
}

#[test]
fn read_helpers_do_not_mutate_timestamps() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::valid_postgres_input())
            .expect("credential should be valid"),
        created_at,
    );
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(secret, created_at);

    let before_vault_updated_at = vault.updated_at();
    let before_secret_updated_at = vault.visible_secrets(SecretFilter::All)[0].updated_at();
    let password = match vault.visible_secrets(SecretFilter::All)[0].kind() {
        SecretKind::PostgreSqlCredential(credential) => credential.password().expose_secret(),
        SecretKind::ApiKeyToken(_) => panic!("expected PostgreSQL credential"),
    };

    assert_eq!("correct horse battery staple", password);
    assert_eq!(before_vault_updated_at, vault.updated_at());
    assert_eq!(
        before_secret_updated_at,
        vault.visible_secrets(SecretFilter::All)[0].updated_at()
    );
}

#[test]
fn debug_output_redacts_secret_values() {
    let created_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::valid_postgres_input())
            .expect("credential should be valid"),
        created_at,
    );
    let mut vault = Vault::new_personal(created_at);
    vault.add_secret(secret, created_at);

    let debug_output = format!("{vault:?}");

    assert!(debug_output.contains("PostgreSqlCredential"));
    assert!(!debug_output.contains("Production DB"));
    assert!(!debug_output.contains("db.example.com"));
    assert!(!debug_output.contains("app_production"));
    assert!(!debug_output.contains("app_user"));
    assert!(!debug_output.contains("correct horse battery staple"));
    assert!(!debug_output.contains("production"));
}

fn valid_api_key_token_input() -> ApiKeyTokenInput {
    ApiKeyTokenInput {
        title: "Cloudflare API Token".to_owned(),
        service: "Cloudflare".to_owned(),
        token: "cf-secret-token".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: Some("https://dash.cloudflare.com".to_owned()),
        tags: vec!["production".to_owned()],
    }
}
