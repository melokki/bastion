use crate::validation::ValidationError;
use std::collections::HashSet;

pub fn normalize_tags(tags: Vec<String>) -> Result<Vec<String>, ValidationError> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for tag in tags {
        let tag = tag
            .trim()
            .to_lowercase()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("-");

        if !tag.is_empty() && !is_valid_tag(&tag) {
            return Err(ValidationError::InvalidTag);
        }

        if !tag.is_empty() && seen.insert(tag.clone()) {
            normalized.push(tag);
        }
    }

    Ok(normalized)
}

fn is_valid_tag(tag: &str) -> bool {
    tag.len() <= 40
        && tag.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'_'
        })
}
