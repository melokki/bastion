use bastion_core::{ApiKeyToken, ApiKeyTokenInput, ApiTokenKind, ValidationError};
use secrecy::ExposeSecret;

#[test]
fn creates_valid_api_key_token() {
    let token = ApiKeyToken::new(valid_input()).expect("api key token should be valid");

    assert_eq!("Cloudflare API Token", token.title());
    assert_eq!("Cloudflare", token.service());
    assert_eq!(ApiTokenKind::ApiKey, token.kind());
    assert_eq!("cf-api-token", token.token().expose_secret());
    assert_eq!(Some("bogdan@example.com"), token.account());
    assert_eq!(Some("https://dash.cloudflare.com"), token.url());
    assert_eq!(["production", "edge"], token.tags());
}

#[test]
fn rejects_missing_required_api_key_token_fields_without_echoing_token() {
    let cases = [
        (
            ApiKeyTokenInput {
                title: "   ".to_owned(),
                ..valid_input()
            },
            ValidationError::MissingRequiredField("title"),
        ),
        (
            ApiKeyTokenInput {
                service: "   ".to_owned(),
                ..valid_input()
            },
            ValidationError::MissingRequiredField("service"),
        ),
        (
            ApiKeyTokenInput {
                token: "   ".to_owned(),
                ..valid_input()
            },
            ValidationError::MissingRequiredField("token"),
        ),
    ];

    for (input, expected_error) in cases {
        let error = ApiKeyToken::new(input).expect_err("required field should be invalid");

        assert_eq!(expected_error, error);
        assert!(!format!("{error:?}").contains("cf-api-token"));
    }
}

#[test]
fn api_key_token_debug_output_redacts_sensitive_fields() {
    let token = ApiKeyToken::new(valid_input()).expect("api key token should be valid");

    let debug_output = format!("{token:?}");

    assert!(debug_output.contains("token"));
    assert!(!debug_output.contains("Cloudflare API Token"));
    assert!(!debug_output.contains("Cloudflare"));
    assert!(!debug_output.contains("cf-api-token"));
    assert!(!debug_output.contains("bogdan@example.com"));
    assert!(!debug_output.contains("production"));
}

fn valid_input() -> ApiKeyTokenInput {
    ApiKeyTokenInput {
        title: "Cloudflare API Token".to_owned(),
        service: "Cloudflare".to_owned(),
        kind: ApiTokenKind::ApiKey,
        token: "cf-api-token".to_owned(),
        account: Some("bogdan@example.com".to_owned()),
        url: Some("https://dash.cloudflare.com".to_owned()),
        tags: vec![" Production ".to_owned(), "edge".to_owned()],
    }
}
