use bastion_core::{RotationMetadata, RotationStatus};
use chrono::{TimeZone, Utc};

#[test]
fn rotation_status_detects_not_configured_healthy_due_soon_due_and_expired() {
    let now = Utc.with_ymd_and_hms(2026, 7, 1, 12, 0, 0).unwrap();

    assert_eq!(
        RotationStatus::NotConfigured,
        RotationMetadata::default().status(now)
    );

    assert_eq!(
        RotationStatus::Healthy,
        RotationMetadata {
            expires_at: Some(Utc.with_ymd_and_hms(2026, 8, 1, 0, 0, 0).unwrap()),
            rotate_every_days: Some(90),
            last_rotated_at: Some(Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap()),
        }
        .status(now)
    );

    assert_eq!(
        RotationStatus::DueSoon,
        RotationMetadata {
            expires_at: Some(Utc.with_ymd_and_hms(2026, 7, 5, 0, 0, 0).unwrap()),
            rotate_every_days: None,
            last_rotated_at: None,
        }
        .status(now)
    );

    assert_eq!(
        RotationStatus::Due,
        RotationMetadata {
            expires_at: Some(Utc.with_ymd_and_hms(2026, 7, 1, 23, 59, 59).unwrap()),
            rotate_every_days: None,
            last_rotated_at: None,
        }
        .status(now)
    );

    assert_eq!(
        RotationStatus::Expired,
        RotationMetadata {
            expires_at: Some(Utc.with_ymd_and_hms(2026, 6, 30, 23, 59, 59).unwrap()),
            rotate_every_days: None,
            last_rotated_at: None,
        }
        .status(now)
    );
}
