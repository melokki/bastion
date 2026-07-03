use chrono::{DateTime, Duration, Utc};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RotationMetadata {
    pub expires_at: Option<DateTime<Utc>>,
    pub rotate_every_days: Option<u16>,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

impl RotationMetadata {
    pub fn is_configured(&self) -> bool {
        self.expires_at.is_some()
            || self.rotate_every_days.is_some()
            || self.last_rotated_at.is_some()
    }

    pub fn status(&self, now: DateTime<Utc>) -> RotationStatus {
        let Some(due_at) = self.next_due_at() else {
            return RotationStatus::NotConfigured;
        };

        if due_at < now {
            return RotationStatus::Expired;
        }

        if due_at.date_naive() == now.date_naive() {
            return RotationStatus::Due;
        }

        if due_at <= now + Duration::days(7) {
            return RotationStatus::DueSoon;
        }

        RotationStatus::Healthy
    }

    pub fn next_due_at(&self) -> Option<DateTime<Utc>> {
        match (
            self.expires_at,
            self.rotate_every_days,
            self.last_rotated_at,
        ) {
            (Some(expires_at), _, _) => Some(expires_at),
            (None, Some(days), Some(last_rotated_at)) => {
                Some(last_rotated_at + Duration::days(i64::from(days)))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotationStatus {
    NotConfigured,
    Healthy,
    DueSoon,
    Due,
    Expired,
}

impl RotationStatus {
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotConfigured => "not configured",
            Self::Healthy => "healthy",
            Self::DueSoon => "due soon",
            Self::Due => "due",
            Self::Expired => "expired",
        }
    }
}
