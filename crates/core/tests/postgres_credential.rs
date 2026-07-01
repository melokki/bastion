use bastion_core::{PostgreSqlCredential, PostgreSqlCredentialInput, ValidationError};
use secrecy::ExposeSecret;

#[test]
fn creates_valid_postgresql_credential() {
    let credential = PostgreSqlCredential::new(PostgreSqlCredentialInput {
        title: "Production DB".to_owned(),
        hostname: "db.example.com".to_owned(),
        port: 5432,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("   ".to_owned()),
        tags: vec!["production".to_owned()],
    })
    .expect("credential should be valid");

    assert_eq!("Production DB", credential.title());
    assert_eq!("db.example.com", credential.hostname());
    assert_eq!(5432, credential.port());
    assert_eq!("app_production", credential.database());
    assert_eq!("app_user", credential.username());
    assert_eq!(
        "correct horse battery staple",
        credential.password().expose_secret()
    );
    assert_eq!(None, credential.schema());
    assert_eq!(["production"], credential.tags());
}

#[test]
fn rejects_zero_port() {
    let error = match PostgreSqlCredential::new(valid_input_with_port(0)) {
        Ok(_) => panic!("port should be invalid"),
        Err(error) => error,
    };

    assert_eq!(ValidationError::InvalidPort, error);
}

#[test]
fn rejects_missing_required_fields_without_echoing_values() {
    let cases = [
        (
            PostgreSqlCredentialInput {
                title: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("title"),
        ),
        (
            PostgreSqlCredentialInput {
                hostname: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("hostname"),
        ),
        (
            PostgreSqlCredentialInput {
                database: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("database"),
        ),
        (
            PostgreSqlCredentialInput {
                username: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("username"),
        ),
        (
            PostgreSqlCredentialInput {
                password: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("password"),
        ),
    ];

    for (input, expected_error) in cases {
        let error = match PostgreSqlCredential::new(input) {
            Ok(_) => panic!("required field should be invalid"),
            Err(error) => error,
        };

        assert_eq!(expected_error, error);
        assert!(!format!("{error:?}").contains("correct horse battery staple"));
    }
}

#[test]
fn normalizes_tags() {
    let mut input = valid_input_with_port(5432);
    input.tags = vec![
        " Production ".to_owned(),
        "critical data".to_owned(),
        "production".to_owned(),
        " ".to_owned(),
    ];

    let credential = PostgreSqlCredential::new(input).expect("credential should be valid");

    assert_eq!(["production", "critical-data"], credential.tags());
}

#[test]
fn rejects_invalid_tags() {
    let mut input = valid_input_with_port(5432);
    input.tags = vec!["prod/eu".to_owned()];

    let error = match PostgreSqlCredential::new(input) {
        Ok(_) => panic!("tag should be invalid"),
        Err(error) => error,
    };

    assert_eq!(ValidationError::InvalidTag, error);
}

#[test]
fn debug_output_redacts_secret_fields() {
    let credential =
        PostgreSqlCredential::new(valid_input_with_port(5432)).expect("credential should be valid");

    let debug_output = format!("{credential:?}");

    assert!(debug_output.contains("password"));
    assert!(!debug_output.contains("Production DB"));
    assert!(!debug_output.contains("db.example.com"));
    assert!(!debug_output.contains("app_production"));
    assert!(!debug_output.contains("app_user"));
    assert!(!debug_output.contains("correct horse battery staple"));
    assert!(!debug_output.contains("production"));
}

fn valid_input_with_port(port: u16) -> PostgreSqlCredentialInput {
    PostgreSqlCredentialInput {
        title: "Production DB".to_owned(),
        hostname: "db.example.com".to_owned(),
        port,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: vec!["production".to_owned()],
    }
}
