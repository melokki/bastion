use crate::ids::CustomFieldId;
use crate::validation::{ValidationError, require_present};
use secrecy::{ExposeSecret, SecretString};
use std::fmt;

pub struct CustomFieldInput {
    pub label: String,
    pub value: String,
    pub sensitive: bool,
}

pub struct CustomField {
    id: CustomFieldId,
    label: String,
    value: SecretString,
    sensitive: bool,
}

impl fmt::Debug for CustomField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CustomField")
            .field("id", &self.id)
            .field("label", &self.label)
            .field("value", &"[redacted]")
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl CustomField {
    pub fn new(input: CustomFieldInput) -> Result<Self, ValidationError> {
        Self::from_parts(CustomFieldId::new(), input)
    }

    pub(crate) fn from_persisted(
        id: CustomFieldId,
        input: CustomFieldInput,
    ) -> Result<Self, ValidationError> {
        Self::from_parts(id, input)
    }

    fn from_parts(id: CustomFieldId, input: CustomFieldInput) -> Result<Self, ValidationError> {
        require_present("custom field label", &input.label)?;
        Ok(Self {
            id,
            label: input.label,
            value: SecretString::new(input.value.into()),
            sensitive: input.sensitive,
        })
    }

    pub fn id(&self) -> CustomFieldId {
        self.id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn value(&self) -> &SecretString {
        &self.value
    }

    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }

    pub fn display_value(&self) -> &str {
        if self.sensitive {
            "********"
        } else {
            self.value.expose_secret()
        }
    }
}
