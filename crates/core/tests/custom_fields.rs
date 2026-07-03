use bastion_core::{CustomField, CustomFieldInput, PostgreSqlCredential, Secret, SecretKind};
use chrono::{TimeZone, Utc};
use secrecy::ExposeSecret;

mod common;

#[test]
fn secrets_can_store_sensitive_and_non_sensitive_custom_fields() {
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let mut secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::postgres_input("Production DB", &[]))
            .expect("credential should be valid"),
        now,
    );

    secret
        .add_custom_field(
            CustomField::new(CustomFieldInput {
                label: "Client Secret".to_owned(),
                value: "super-secret".to_owned(),
                sensitive: true,
            })
            .expect("custom field should be valid"),
            now,
        )
        .expect("field should be added");
    secret
        .add_custom_field(
            CustomField::new(CustomFieldInput {
                label: "Region".to_owned(),
                value: "eu-central".to_owned(),
                sensitive: false,
            })
            .expect("custom field should be valid"),
            now,
        )
        .expect("field should be added");

    assert_eq!(2, secret.custom_fields().len());
    assert_ne!(
        secret.custom_fields()[0].id(),
        secret.custom_fields()[1].id()
    );
    assert_eq!("Client Secret", secret.custom_fields()[0].label());
    assert!(secret.custom_fields()[0].is_sensitive());
    assert_eq!("********", secret.custom_fields()[0].display_value());
    assert_eq!(
        "super-secret",
        secret.custom_fields()[0].value().expose_secret()
    );
    assert_eq!("eu-central", secret.custom_fields()[1].display_value());
    assert!(matches!(secret.kind(), SecretKind::DatabaseCredential(_)));
}

#[test]
fn empty_custom_field_labels_are_rejected() {
    assert!(
        CustomField::new(CustomFieldInput {
            label: " ".to_owned(),
            value: "value".to_owned(),
            sensitive: false,
        })
        .is_err()
    );
}
