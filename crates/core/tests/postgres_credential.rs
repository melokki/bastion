use bastion_core::{
    DatabaseCredential, DatabaseCredentialInput, DatabaseEngine, SECRET_CONNECTION_STRING_MASK,
    ValidationError,
};
use secrecy::ExposeSecret;

#[test]
fn creates_valid_database_credential() {
    let credential = DatabaseCredential::new(DatabaseCredentialInput {
        title: "Production DB".to_owned(),
        engine: DatabaseEngine::PostgreSql,
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
    assert_eq!(DatabaseEngine::PostgreSql, credential.engine());
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
fn builds_masked_connection_string_without_revealing_password_length() {
    let credential =
        DatabaseCredential::new(valid_input_with_port(5432)).expect("credential should be valid");

    assert_eq!("*******", SECRET_CONNECTION_STRING_MASK);
    assert_eq!(
        "postgresql://app_user:*******@db.example.com:5432/app_production?schema=public",
        credential.masked_connection_string()
    );
    assert!(
        !credential
            .masked_connection_string()
            .contains("correct horse battery staple")
    );
}

#[test]
fn builds_engine_specific_masked_connection_strings() {
    let cases = [
        (
            DatabaseEngine::MySql,
            3306,
            "mysql://app_user:*******@db.example.com:3306/app_production",
        ),
        (
            DatabaseEngine::MariaDb,
            3306,
            "mysql://app_user:*******@db.example.com:3306/app_production",
        ),
        (
            DatabaseEngine::Other,
            1234,
            "database://app_user:*******@db.example.com:1234/app_production",
        ),
    ];

    for (engine, port, expected) in cases {
        let mut input = valid_input_with_port(port);
        input.engine = engine;
        input.schema = Some("public".to_owned());

        let credential = DatabaseCredential::new(input).expect("credential should be valid");

        assert_eq!(expected, credential.masked_connection_string());
    }
}

#[test]
fn rejects_zero_port() {
    let error = match DatabaseCredential::new(valid_input_with_port(0)) {
        Ok(_) => panic!("port should be invalid"),
        Err(error) => error,
    };

    assert_eq!(ValidationError::InvalidPort, error);
}

#[test]
fn rejects_missing_required_fields_without_echoing_values() {
    let cases = [
        (
            DatabaseCredentialInput {
                title: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("title"),
        ),
        (
            DatabaseCredentialInput {
                hostname: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("hostname"),
        ),
        (
            DatabaseCredentialInput {
                database: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("database"),
        ),
        (
            DatabaseCredentialInput {
                username: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("username"),
        ),
        (
            DatabaseCredentialInput {
                password: "   ".to_owned(),
                ..valid_input_with_port(5432)
            },
            ValidationError::MissingRequiredField("password"),
        ),
    ];

    for (input, expected_error) in cases {
        let error = match DatabaseCredential::new(input) {
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

    let credential = DatabaseCredential::new(input).expect("credential should be valid");

    assert_eq!(["production", "critical-data"], credential.tags());
}

#[test]
fn rejects_invalid_tags() {
    let mut input = valid_input_with_port(5432);
    input.tags = vec!["prod/eu".to_owned()];

    let error = match DatabaseCredential::new(input) {
        Ok(_) => panic!("tag should be invalid"),
        Err(error) => error,
    };

    assert_eq!(ValidationError::InvalidTag, error);
}

#[test]
fn debug_output_redacts_secret_fields() {
    let credential =
        DatabaseCredential::new(valid_input_with_port(5432)).expect("credential should be valid");

    let debug_output = format!("{credential:?}");

    assert!(debug_output.contains("password"));
    assert!(!debug_output.contains("Production DB"));
    assert!(!debug_output.contains("db.example.com"));
    assert!(!debug_output.contains("app_production"));
    assert!(!debug_output.contains("app_user"));
    assert!(!debug_output.contains("correct horse battery staple"));
    assert!(!debug_output.contains("production"));
}

fn valid_input_with_port(port: u16) -> DatabaseCredentialInput {
    DatabaseCredentialInput {
        title: "Production DB".to_owned(),
        engine: DatabaseEngine::PostgreSql,
        hostname: "db.example.com".to_owned(),
        port,
        database: "app_production".to_owned(),
        username: "app_user".to_owned(),
        password: "correct horse battery staple".to_owned(),
        schema: Some("public".to_owned()),
        tags: vec!["production".to_owned()],
    }
}
