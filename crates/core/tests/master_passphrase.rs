use bastion_core::{ValidationError, validate_master_passphrase};

#[test]
fn validates_master_passphrase_rules() {
    assert_eq!(
        Err(ValidationError::MasterPassphraseTooShort),
        validate_master_passphrase("short", "short")
    );

    assert_eq!(
        Err(ValidationError::MasterPassphraseConfirmationMismatch),
        validate_master_passphrase("correct horse battery staple", "different passphrase")
    );

    assert_eq!(
        Ok(()),
        validate_master_passphrase(
            "correct horse battery staple",
            "correct horse battery staple"
        )
    );
}
