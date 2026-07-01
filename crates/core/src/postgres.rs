use crate::tags::normalize_tags;
use crate::validation::{ValidationError, require_present};
use secrecy::SecretString;
use std::fmt;

pub struct PostgreSqlCredentialInput {
    pub title: String,
    pub hostname: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub schema: Option<String>,
    pub tags: Vec<String>,
}

pub struct PostgreSqlCredential {
    title: String,
    hostname: String,
    port: u16,
    database: String,
    username: String,
    password: SecretString,
    schema: Option<String>,
    tags: Vec<String>,
}

impl fmt::Debug for PostgreSqlCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgreSqlCredential")
            .field("title", &self.title)
            .field("hostname", &self.hostname)
            .field("port", &self.port)
            .field("database", &self.database)
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("schema", &self.schema)
            .field("tags", &self.tags)
            .finish()
    }
}

impl PostgreSqlCredential {
    pub fn new(input: PostgreSqlCredentialInput) -> Result<Self, ValidationError> {
        require_present("title", &input.title)?;
        require_present("hostname", &input.hostname)?;
        require_present("database", &input.database)?;
        require_present("username", &input.username)?;
        require_present("password", &input.password)?;
        if input.port == 0 {
            return Err(ValidationError::InvalidPort);
        }

        Ok(Self {
            title: input.title,
            hostname: input.hostname,
            port: input.port,
            database: input.database,
            username: input.username,
            password: SecretString::new(input.password.into()),
            schema: normalize_optional(input.schema),
            tags: normalize_tags(input.tags)?,
        })
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn database(&self) -> &str {
        &self.database
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &SecretString {
        &self.password
    }

    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
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
