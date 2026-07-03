use bastion_core::{
    AccountRecovery, AccountRecoveryInput, PostgreSqlCredential, RecoveryCodeStatus,
    RecoveryMaterialInput, RecoveryMaterialKind, Secret, Vault, VaultMutationError,
};
use chrono::{TimeZone, Utc};

mod common;

#[test]
fn recovery_codes_have_ids_and_can_be_marked_used_or_unused() {
    let mut item = AccountRecovery::new(AccountRecoveryInput {
        title: "GitHub Recovery Codes".to_owned(),
        service: "GitHub".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: None,
        kind: RecoveryMaterialKind::RecoveryCodeSet,
        material: RecoveryMaterialInput::CodeSet("one\ntwo\nthree".to_owned()),
        tags: Vec::new(),
    })
    .expect("recovery item should be valid");

    let first = item.recovery_codes()[0].id();
    let second = item.recovery_codes()[1].id();
    assert_ne!(first, second);
    assert_eq!((3, 3), item.recovery_code_counts());
    assert_eq!(
        Some(first),
        item.next_unused_recovery_code().map(|code| code.id())
    );

    let used_at = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    item.mark_recovery_code_used(first, used_at)
        .expect("code should mark used");

    assert_eq!((2, 3), item.recovery_code_counts());
    assert_eq!(Some(used_at), item.recovery_codes()[0].used_at());
    assert_eq!(
        Some(second),
        item.next_unused_recovery_code().map(|code| code.id())
    );

    item.mark_recovery_code_unused(first)
        .expect("code should mark unused");
    assert_eq!((3, 3), item.recovery_code_counts());
}

#[test]
fn duplicate_recovery_codes_are_rejected() {
    assert!(
        AccountRecovery::new(AccountRecoveryInput {
            title: "GitHub Recovery Codes".to_owned(),
            service: "GitHub".to_owned(),
            account: None,
            url: None,
            kind: RecoveryMaterialKind::RecoveryCodeSet,
            material: RecoveryMaterialInput::CodeSet("one\ntwo\none".to_owned()),
            tags: Vec::new(),
        })
        .is_err()
    );
}

#[test]
fn vault_marks_recovery_codes_used_and_unused() {
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();
    let used_at = Utc.with_ymd_and_hms(2026, 7, 2, 12, 0, 0).unwrap();
    let recovery = AccountRecovery::new(AccountRecoveryInput {
        title: "GitHub Recovery Codes".to_owned(),
        service: "GitHub".to_owned(),
        account: Some("ops@example.com".to_owned()),
        url: None,
        kind: RecoveryMaterialKind::RecoveryCodeSet,
        material: RecoveryMaterialInput::CodeSet("one\ntwo".to_owned()),
        tags: Vec::new(),
    })
    .expect("recovery item should be valid");
    let code_id = recovery.recovery_codes()[0].id();
    let recovery_secret = Secret::new_account_recovery(recovery, now);
    let recovery_secret_id = recovery_secret.id();
    let postgres_secret = Secret::new_postgres(
        PostgreSqlCredential::new(common::valid_postgres_input())
            .expect("credential should be valid"),
        now,
    );
    let postgres_secret_id = postgres_secret.id();
    let mut vault = Vault::new_personal(now);
    vault.add_secret(recovery_secret, now);
    vault.add_secret(postgres_secret, now);

    vault
        .mark_recovery_code_used(recovery_secret_id, code_id, used_at)
        .expect("code should be marked used");

    let item = match vault.secrets()[0].kind() {
        bastion_core::SecretKind::AccountRecovery(item) => item,
        _ => panic!("expected recovery item"),
    };
    assert_eq!(RecoveryCodeStatus::Used, item.recovery_codes()[0].status());
    assert_eq!(used_at, vault.updated_at());

    vault
        .mark_recovery_code_unused(recovery_secret_id, code_id, used_at)
        .expect("code should be marked unused");

    let item = match vault.secrets()[0].kind() {
        bastion_core::SecretKind::AccountRecovery(item) => item,
        _ => panic!("expected recovery item"),
    };
    assert_eq!(
        RecoveryCodeStatus::Unused,
        item.recovery_codes()[0].status()
    );
    assert_eq!(
        Err(VaultMutationError::InvalidSecretShape),
        vault.mark_recovery_code_used(postgres_secret_id, code_id, used_at)
    );
}
