use bastion_core::{
    AccountRecovery, AccountRecoveryInput, RecoveryMaterialInput, RecoveryMaterialKind,
    ValidationError,
};
use secrecy::ExposeSecret;

#[test]
fn creates_recovery_code_set_with_generic_validation() {
    let item = AccountRecovery::new(AccountRecoveryInput {
        title: "GitHub Recovery Codes".to_owned(),
        service: "GitHub".to_owned(),
        account: Some("bogdan".to_owned()),
        url: Some("https://github.com".to_owned()),
        kind: RecoveryMaterialKind::RecoveryCodeSet,
        material: RecoveryMaterialInput::CodeSet("\n  abcde-12345  \n\nfghij-67890\n".to_owned()),
        tags: vec!["github".to_owned(), " recovery ".to_owned()],
    })
    .expect("recovery code set should be valid");

    assert_eq!("GitHub Recovery Codes", item.title());
    assert_eq!("GitHub", item.service());
    assert_eq!(Some("bogdan"), item.account());
    assert_eq!(Some("https://github.com"), item.url());
    assert_eq!(RecoveryMaterialKind::RecoveryCodeSet, item.kind());
    assert_eq!((2, 2), item.recovery_code_counts());
    assert_eq!(
        "abcde-12345",
        item.recovery_codes()[0].value().expose_secret()
    );
    assert_eq!(["github", "recovery"], item.tags());
}

#[test]
fn rejects_empty_recovery_material_without_echoing_values() {
    let cases = [
        (
            AccountRecoveryInput {
                title: "   ".to_owned(),
                ..valid_recovery_key_input()
            },
            ValidationError::MissingRequiredField("title"),
        ),
        (
            AccountRecoveryInput {
                service: "   ".to_owned(),
                ..valid_recovery_key_input()
            },
            ValidationError::MissingRequiredField("service"),
        ),
        (
            AccountRecoveryInput {
                material: RecoveryMaterialInput::Key("   ".to_owned()),
                ..valid_recovery_key_input()
            },
            ValidationError::MissingRequiredField("recovery key"),
        ),
    ];

    for (input, expected_error) in cases {
        let error = AccountRecovery::new(input).expect_err("input should be invalid");

        assert_eq!(expected_error, error);
        assert!(!format!("{error:?}").contains("tuta-secret-recovery-code"));
    }
}

#[test]
fn account_recovery_debug_output_redacts_recovery_material() {
    let item =
        AccountRecovery::new(valid_recovery_key_input()).expect("recovery key should be valid");

    let debug_output = format!("{item:?}");

    assert!(debug_output.contains("material"));
    assert!(!debug_output.contains("Tuta Recovery Code"));
    assert!(!debug_output.contains("tuta-secret-recovery-code"));
}

fn valid_recovery_key_input() -> AccountRecoveryInput {
    AccountRecoveryInput {
        title: "Tuta Recovery Code".to_owned(),
        service: "Tuta".to_owned(),
        account: Some("bogdan@example.com".to_owned()),
        url: None,
        kind: RecoveryMaterialKind::RecoveryKey,
        material: RecoveryMaterialInput::Key("tuta-secret-recovery-code".to_owned()),
        tags: vec!["tuta".to_owned(), "recovery".to_owned()],
    }
}
