use crate::tags::normalize_tags;
use crate::validation::{ValidationError, require_present};
use secrecy::SecretString;
use std::fmt;

pub const SECRET_CONNECTION_STRING_MASK: &str = "*******";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DatabaseEngine {
    #[default]
    PostgreSql,
    MySql,
    MariaDb,
    Other,
}

impl DatabaseEngine {
    pub const fn label(self) -> &'static str {
        match self {
            Self::PostgreSql => "PostgreSQL",
            Self::MySql => "MySQL",
            Self::MariaDb => "MariaDB",
            Self::Other => "Other",
        }
    }

    pub const fn default_port(self) -> Option<u16> {
        match self {
            Self::PostgreSql => Some(5432),
            Self::MySql | Self::MariaDb => Some(3306),
            Self::Other => None,
        }
    }

    const fn scheme(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgresql",
            Self::MySql | Self::MariaDb => "mysql",
            Self::Other => "database",
        }
    }
}

pub struct DatabaseCredentialInput {
    pub title: String,
    pub engine: DatabaseEngine,
    pub hostname: String,
    pub port: u16,
    pub database: String,
    pub username: String,
    pub password: String,
    pub schema: Option<String>,
    pub tags: Vec<String>,
}

pub struct DatabaseCredential {
    title: String,
    engine: DatabaseEngine,
    hostname: String,
    port: u16,
    database: String,
    username: String,
    password: SecretString,
    schema: Option<String>,
    tags: Vec<String>,
}

impl fmt::Debug for DatabaseCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DatabaseCredential")
            .field("title", &"[redacted]")
            .field("engine", &self.engine)
            .field("hostname", &"[redacted]")
            .field("port", &self.port)
            .field("database", &"[redacted]")
            .field("username", &"[redacted]")
            .field("password", &"[redacted]")
            .field("schema", &self.schema.as_ref().map(|_| "[redacted]"))
            .field("tags", &"[redacted]")
            .finish()
    }
}

impl DatabaseCredential {
    pub fn new(input: DatabaseCredentialInput) -> Result<Self, ValidationError> {
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
            engine: input.engine,
            hostname: input.hostname,
            port: input.port,
            database: input.database,
            username: input.username,
            password: SecretString::new(input.password.into()),
            schema: normalize_optional(input.schema),
            tags: normalize_tags(input.tags)?,
        })
    }

    pub(crate) fn from_persisted(input: DatabaseCredentialInput) -> Result<Self, ValidationError> {
        Self::new(input)
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn engine(&self) -> DatabaseEngine {
        self.engine
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

    pub fn masked_connection_string(&self) -> String {
        let base = format!(
            "{}://{}:{}@{}:{}/{}",
            self.engine.scheme(),
            self.username,
            SECRET_CONNECTION_STRING_MASK,
            self.hostname,
            self.port,
            self.database
        );

        if self.engine == DatabaseEngine::PostgreSql
            && let Some(schema) = self.schema()
        {
            return format!("{base}?schema={schema}");
        }

        base
    }
}

pub type PostgreSqlCredentialInput = DatabaseCredentialInput;
pub type PostgreSqlCredential = DatabaseCredential;

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}
