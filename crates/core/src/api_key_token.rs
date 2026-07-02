use crate::tags::normalize_tags;
use crate::validation::{ValidationError, require_present};
use secrecy::SecretString;
use std::fmt;

pub struct ApiKeyTokenInput {
    pub title: String,
    pub service: String,
    pub kind: ApiTokenKind,
    pub token: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ApiTokenKind {
    PersonalAccessToken,
    ApiKey,
    BearerToken,
    RegistryToken,
    AppPassword,
    WebhookSecret,
    OAuthClientSecret,
    #[default]
    GenericToken,
}

impl ApiTokenKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PersonalAccessToken => "Personal Access Token",
            Self::ApiKey => "API Key",
            Self::BearerToken => "Bearer Token",
            Self::RegistryToken => "Registry Token",
            Self::AppPassword => "App Password",
            Self::WebhookSecret => "Webhook Secret",
            Self::OAuthClientSecret => "OAuth Client Secret",
            Self::GenericToken => "Generic Token",
        }
    }
}

pub struct ApiKeyToken {
    title: String,
    service: String,
    kind: ApiTokenKind,
    token: SecretString,
    account: Option<String>,
    url: Option<String>,
    tags: Vec<String>,
}

impl fmt::Debug for ApiKeyToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApiKeyToken")
            .field("title", &"[redacted]")
            .field("service", &"[redacted]")
            .field("kind", &self.kind)
            .field("token", &"[redacted]")
            .field("account", &self.account.as_ref().map(|_| "[redacted]"))
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .field("tags", &"[redacted]")
            .finish()
    }
}

impl ApiKeyToken {
    pub fn new(input: ApiKeyTokenInput) -> Result<Self, ValidationError> {
        require_present("title", &input.title)?;
        require_present("service", &input.service)?;
        require_present("token", &input.token)?;

        Ok(Self {
            title: input.title,
            service: input.service,
            kind: input.kind,
            token: SecretString::new(input.token.into()),
            account: normalize_optional(input.account),
            url: normalize_optional(input.url),
            tags: normalize_tags(input.tags)?,
        })
    }

    pub(crate) fn from_persisted(input: ApiKeyTokenInput) -> Result<Self, ValidationError> {
        Self::new(input)
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn kind(&self) -> ApiTokenKind {
        self.kind
    }

    pub fn token(&self) -> &SecretString {
        &self.token
    }

    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}
