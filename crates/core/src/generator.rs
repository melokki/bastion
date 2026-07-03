use secrecy::SecretString;
use std::fmt;

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?/";
const HEX: &[u8] = b"0123456789abcdef";
const BASE64_URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const ALPHANUMERIC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GeneratedSecretKind {
    Password,
    HexToken,
    Base64UrlToken,
    AlphanumericToken,
}

#[derive(Clone, Eq, PartialEq)]
pub struct SecretGeneratorConfig {
    pub kind: GeneratedSecretKind,
    pub length: usize,
    pub include_uppercase: bool,
    pub include_lowercase: bool,
    pub include_digits: bool,
    pub include_symbols: bool,
}

impl SecretGeneratorConfig {
    pub const fn password() -> Self {
        Self {
            kind: GeneratedSecretKind::Password,
            length: 32,
            include_uppercase: true,
            include_lowercase: true,
            include_digits: true,
            include_symbols: true,
        }
    }

    pub const fn hex_token(length: usize) -> Self {
        Self::token(GeneratedSecretKind::HexToken, length)
    }

    pub const fn base64_url_token(length: usize) -> Self {
        Self::token(GeneratedSecretKind::Base64UrlToken, length)
    }

    pub const fn alphanumeric_token(length: usize) -> Self {
        Self::token(GeneratedSecretKind::AlphanumericToken, length)
    }

    const fn token(kind: GeneratedSecretKind, length: usize) -> Self {
        Self {
            kind,
            length,
            include_uppercase: false,
            include_lowercase: false,
            include_digits: false,
            include_symbols: false,
        }
    }
}

impl fmt::Debug for SecretGeneratorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretGeneratorConfig")
            .field("kind", &self.kind)
            .field("length", &self.length)
            .field("include_uppercase", &self.include_uppercase)
            .field("include_lowercase", &self.include_lowercase)
            .field("include_digits", &self.include_digits)
            .field("include_symbols", &self.include_symbols)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecretGenerationError {
    EmptyCharacterSet,
    RandomUnavailable,
}

pub fn generate_secret(
    config: &SecretGeneratorConfig,
) -> Result<SecretString, SecretGenerationError> {
    let alphabet = alphabet_for(config)?;
    let value = random_string(config.length, &alphabet)?;
    Ok(SecretString::new(value.into()))
}

fn alphabet_for(config: &SecretGeneratorConfig) -> Result<Vec<u8>, SecretGenerationError> {
    let mut alphabet = Vec::new();
    match config.kind {
        GeneratedSecretKind::Password => {
            if config.include_uppercase {
                alphabet.extend_from_slice(UPPERCASE);
            }
            if config.include_lowercase {
                alphabet.extend_from_slice(LOWERCASE);
            }
            if config.include_digits {
                alphabet.extend_from_slice(DIGITS);
            }
            if config.include_symbols {
                alphabet.extend_from_slice(SYMBOLS);
            }
        }
        GeneratedSecretKind::HexToken => alphabet.extend_from_slice(HEX),
        GeneratedSecretKind::Base64UrlToken => alphabet.extend_from_slice(BASE64_URL),
        GeneratedSecretKind::AlphanumericToken => alphabet.extend_from_slice(ALPHANUMERIC),
    }

    if alphabet.is_empty() {
        return Err(SecretGenerationError::EmptyCharacterSet);
    }
    Ok(alphabet)
}

fn random_string(length: usize, alphabet: &[u8]) -> Result<String, SecretGenerationError> {
    let mut output = String::with_capacity(length);
    while output.len() < length {
        let byte = random_byte()?;
        let limit = u8::MAX - (u8::MAX % alphabet.len() as u8);
        if byte < limit {
            output.push(alphabet[usize::from(byte) % alphabet.len()] as char);
        }
    }
    Ok(output)
}

fn random_byte() -> Result<u8, SecretGenerationError> {
    let mut byte = [0_u8; 1];
    getrandom::fill(&mut byte).map_err(|_| SecretGenerationError::RandomUnavailable)?;
    Ok(byte[0])
}
