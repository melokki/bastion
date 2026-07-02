#[derive(Debug, PartialEq, Eq)]
pub enum ValidationError {
    MissingRequiredField(&'static str),
    InvalidPort,
    InvalidSecretShape,
    InvalidTag,
    MasterPassphraseTooShort,
    MasterPassphraseConfirmationMismatch,
}

pub fn validate_master_passphrase(
    passphrase: &str,
    confirmation: &str,
) -> Result<(), ValidationError> {
    if passphrase.chars().count() < 9 {
        return Err(ValidationError::MasterPassphraseTooShort);
    }

    if passphrase != confirmation {
        return Err(ValidationError::MasterPassphraseConfirmationMismatch);
    }

    Ok(())
}

pub fn require_present(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::MissingRequiredField(field))
    } else {
        Ok(())
    }
}
