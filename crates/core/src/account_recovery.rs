use crate::tags::normalize_tags;
use crate::validation::{ValidationError, require_present};
use secrecy::SecretString;
use std::fmt;

pub struct AccountRecoveryInput {
    pub title: String,
    pub service: String,
    pub account: Option<String>,
    pub url: Option<String>,
    pub kind: RecoveryMaterialKind,
    pub material: RecoveryMaterialInput,
    pub tags: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMaterialKind {
    RecoveryCodeSet,
    RecoveryPhrase,
    RecoveryKey,
    RecoveryFile,
    RecoveryInstructions,
    SecurityQuestions,
}

impl RecoveryMaterialKind {
    pub const fn label(self) -> &'static str {
        match self {
            Self::RecoveryCodeSet => "Recovery Code Set",
            Self::RecoveryPhrase => "Recovery Phrase",
            Self::RecoveryKey => "Recovery Key",
            Self::RecoveryFile => "Recovery File",
            Self::RecoveryInstructions => "Recovery Instructions",
            Self::SecurityQuestions => "Security Questions",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMaterialFormat {
    Generic,
    MultilineCodes,
    Words,
    GroupedText,
    FileReference,
}

impl RecoveryMaterialFormat {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Generic => "Generic",
            Self::MultilineCodes => "Multiline Codes",
            Self::Words => "Words",
            Self::GroupedText => "Grouped Text",
            Self::FileReference => "File Reference",
        }
    }
}

pub enum RecoveryMaterialInput {
    CodeSet(String),
    Phrase(String),
    Key(String),
    FileReference {
        file_name: Option<String>,
        location: String,
        checksum: Option<String>,
    },
    Instructions(String),
    SecurityQuestions(Vec<SecurityQuestionInput>),
}

pub struct SecurityQuestionInput {
    pub question: String,
    pub answer: String,
}

pub struct AccountRecovery {
    title: String,
    service: String,
    account: Option<String>,
    url: Option<String>,
    kind: RecoveryMaterialKind,
    format: RecoveryMaterialFormat,
    material: RecoveryMaterial,
    tags: Vec<String>,
}

impl fmt::Debug for AccountRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountRecovery")
            .field("title", &"[redacted]")
            .field("service", &"[redacted]")
            .field("account", &self.account.as_ref().map(|_| "[redacted]"))
            .field("url", &self.url.as_ref().map(|_| "[redacted]"))
            .field("kind", &self.kind)
            .field("format", &self.format)
            .field("material", &"[redacted]")
            .field("tags", &"[redacted]")
            .finish()
    }
}

impl AccountRecovery {
    pub fn new(input: AccountRecoveryInput) -> Result<Self, ValidationError> {
        require_present("title", &input.title)?;
        require_present("service", &input.service)?;

        let (material, format) = RecoveryMaterial::from_input(input.kind, input.material)?;

        Ok(Self {
            title: input.title,
            service: input.service,
            account: normalize_optional(input.account),
            url: normalize_optional(input.url),
            kind: input.kind,
            format,
            material,
            tags: normalize_tags(input.tags)?,
        })
    }

    pub(crate) fn from_persisted(input: AccountRecoveryInput) -> Result<Self, ValidationError> {
        Self::new(input)
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn service(&self) -> &str {
        &self.service
    }

    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn kind(&self) -> RecoveryMaterialKind {
        self.kind
    }

    pub fn format(&self) -> RecoveryMaterialFormat {
        self.format
    }

    pub fn material(&self) -> &RecoveryMaterial {
        &self.material
    }

    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    pub fn recovery_codes(&self) -> &[RecoveryCode] {
        match &self.material {
            RecoveryMaterial::CodeSet(codes) => codes,
            _ => &[],
        }
    }

    pub fn recovery_code_counts(&self) -> (usize, usize) {
        let codes = self.recovery_codes();
        let unused = codes
            .iter()
            .filter(|code| code.status() == RecoveryCodeStatus::Unused)
            .count();
        (unused, codes.len())
    }
}

pub enum RecoveryMaterial {
    CodeSet(Vec<RecoveryCode>),
    Phrase(RecoveryPhrase),
    Key(RecoveryKey),
    FileReference(RecoveryFileReference),
    Instructions(RecoveryInstructions),
    SecurityQuestions(Vec<SecurityQuestion>),
}

impl RecoveryMaterial {
    fn from_input(
        kind: RecoveryMaterialKind,
        input: RecoveryMaterialInput,
    ) -> Result<(Self, RecoveryMaterialFormat), ValidationError> {
        match (kind, input) {
            (RecoveryMaterialKind::RecoveryCodeSet, RecoveryMaterialInput::CodeSet(text)) => {
                let codes = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(RecoveryCode::new_unused)
                    .collect::<Vec<_>>();
                if codes.is_empty() {
                    return Err(ValidationError::MissingRequiredField("recovery codes"));
                }
                Ok((Self::CodeSet(codes), RecoveryMaterialFormat::MultilineCodes))
            }
            (RecoveryMaterialKind::RecoveryPhrase, RecoveryMaterialInput::Phrase(value)) => {
                require_present("recovery phrase", &value)?;
                Ok((
                    Self::Phrase(RecoveryPhrase::new(value)),
                    RecoveryMaterialFormat::Words,
                ))
            }
            (RecoveryMaterialKind::RecoveryKey, RecoveryMaterialInput::Key(value)) => {
                require_present("recovery key", &value)?;
                Ok((
                    Self::Key(RecoveryKey::new(value)),
                    RecoveryMaterialFormat::GroupedText,
                ))
            }
            (
                RecoveryMaterialKind::RecoveryFile,
                RecoveryMaterialInput::FileReference {
                    file_name,
                    location,
                    checksum,
                },
            ) => {
                require_present("recovery file location", &location)?;
                Ok((
                    Self::FileReference(RecoveryFileReference {
                        file_name: normalize_optional(file_name),
                        location,
                        checksum: normalize_optional(checksum),
                    }),
                    RecoveryMaterialFormat::FileReference,
                ))
            }
            (
                RecoveryMaterialKind::RecoveryInstructions,
                RecoveryMaterialInput::Instructions(value),
            ) => {
                require_present("recovery instructions", &value)?;
                Ok((
                    Self::Instructions(RecoveryInstructions {
                        text: SecretString::new(value.into()),
                    }),
                    RecoveryMaterialFormat::Generic,
                ))
            }
            (
                RecoveryMaterialKind::SecurityQuestions,
                RecoveryMaterialInput::SecurityQuestions(questions),
            ) => {
                let questions = questions
                    .into_iter()
                    .map(SecurityQuestion::new)
                    .collect::<Result<Vec<_>, _>>()?;
                if questions.is_empty() {
                    return Err(ValidationError::MissingRequiredField("security question"));
                }
                Ok((
                    Self::SecurityQuestions(questions),
                    RecoveryMaterialFormat::Generic,
                ))
            }
            _ => Err(ValidationError::InvalidSecretShape),
        }
    }
}

pub struct RecoveryCode {
    value: SecretString,
    status: RecoveryCodeStatus,
}

impl RecoveryCode {
    fn new_unused(value: &str) -> Self {
        Self {
            value: SecretString::new(value.to_owned().into()),
            status: RecoveryCodeStatus::Unused,
        }
    }

    pub fn value(&self) -> &SecretString {
        &self.value
    }

    pub fn status(&self) -> RecoveryCodeStatus {
        self.status
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryCodeStatus {
    Unused,
    Used,
}

pub struct RecoveryPhrase {
    value: SecretString,
    word_count: usize,
}

impl RecoveryPhrase {
    fn new(value: String) -> Self {
        let word_count = value.split_whitespace().count();
        Self {
            value: SecretString::new(value.into()),
            word_count,
        }
    }

    pub fn value(&self) -> &SecretString {
        &self.value
    }

    pub fn word_count(&self) -> usize {
        self.word_count
    }
}

pub struct RecoveryKey {
    value: SecretString,
}

impl RecoveryKey {
    fn new(value: String) -> Self {
        Self {
            value: SecretString::new(value.into()),
        }
    }

    pub fn value(&self) -> &SecretString {
        &self.value
    }
}

pub struct RecoveryFileReference {
    file_name: Option<String>,
    location: String,
    checksum: Option<String>,
}

impl RecoveryFileReference {
    pub fn file_name(&self) -> Option<&str> {
        self.file_name.as_deref()
    }

    pub fn location(&self) -> &str {
        &self.location
    }

    pub fn checksum(&self) -> Option<&str> {
        self.checksum.as_deref()
    }
}

pub struct RecoveryInstructions {
    text: SecretString,
}

impl RecoveryInstructions {
    pub fn text(&self) -> &SecretString {
        &self.text
    }
}

pub struct SecurityQuestion {
    question: String,
    answer: SecretString,
}

impl SecurityQuestion {
    fn new(input: SecurityQuestionInput) -> Result<Self, ValidationError> {
        require_present("security question", &input.question)?;
        require_present("security answer", &input.answer)?;
        Ok(Self {
            question: input.question,
            answer: SecretString::new(input.answer.into()),
        })
    }

    pub fn question(&self) -> &str {
        &self.question
    }

    pub fn answer(&self) -> &SecretString {
        &self.answer
    }
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}
