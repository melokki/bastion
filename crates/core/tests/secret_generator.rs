use bastion_core::{GeneratedSecretKind, SecretGeneratorConfig, generate_secret};
use secrecy::ExposeSecret;

#[test]
fn generator_produces_requested_secret_shapes() {
    let password = generate_secret(&SecretGeneratorConfig {
        kind: GeneratedSecretKind::Password,
        length: 32,
        include_uppercase: true,
        include_lowercase: true,
        include_digits: true,
        include_symbols: true,
    })
    .expect("password should generate");
    assert_eq!(32, password.expose_secret().chars().count());

    let hex =
        generate_secret(&SecretGeneratorConfig::hex_token(40)).expect("hex token should generate");
    assert_eq!(40, hex.expose_secret().len());
    assert!(hex.expose_secret().chars().all(|ch| ch.is_ascii_hexdigit()));

    let base64url = generate_secret(&SecretGeneratorConfig::base64_url_token(43))
        .expect("base64url token should generate");
    assert_eq!(43, base64url.expose_secret().len());
    assert!(
        base64url
            .expose_secret()
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    );

    let alpha = generate_secret(&SecretGeneratorConfig::alphanumeric_token(24))
        .expect("alphanumeric token should generate");
    assert_eq!(24, alpha.expose_secret().len());
    assert!(
        alpha
            .expose_secret()
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric())
    );
}

#[test]
fn repeated_generated_values_are_not_identical() {
    let config = SecretGeneratorConfig::password();

    let first = generate_secret(&config).expect("first value should generate");
    let second = generate_secret(&config).expect("second value should generate");

    assert_ne!(first.expose_secret(), second.expose_secret());
}
