use bastion_core::{
    ReleaseAsset, ReleaseMetadata, UpdateCheck, UpdateCheckOutcome, UpdateInfo, Version,
};

#[test]
fn newer_stable_release_with_matching_asset_is_available() {
    let outcome = UpdateCheck {
        current_version: Version::parse("v0.1.0").expect("current version should parse"),
        platform_target: "x86_64-unknown-linux-gnu".to_owned(),
        skipped_version: None,
    }
    .evaluate(release("v0.2.0"));

    assert_eq!(
        UpdateCheckOutcome::Available(UpdateInfo {
            version: Version::parse("v0.2.0").expect("latest version should parse"),
            current_version: Version::parse("v0.1.0").expect("current version should parse"),
            release_notes: vec![
                "Added API token secret type".to_owned(),
                "Improved tag filtering".to_owned(),
            ],
            asset: ReleaseAsset {
                target: "x86_64-unknown-linux-gnu".to_owned(),
                filename: "bastion-v0.2.0-x86_64-unknown-linux-gnu.tar.gz".to_owned(),
                sha256: "abc123".to_owned(),
                download_url: "https://codeberg.example/bastion-v0.2.0.tar.gz".to_owned(),
            },
            release_url: "https://codeberg.example/releases/v0.2.0".to_owned(),
        }),
        outcome
    );
}

#[test]
fn update_check_filters_unsafe_or_non_applicable_releases() {
    let check = UpdateCheck {
        current_version: Version::parse("v0.2.0").expect("current version should parse"),
        platform_target: "x86_64-unknown-linux-gnu".to_owned(),
        skipped_version: None,
    };

    let mut draft = release("v0.3.0");
    draft.draft = true;
    assert_eq!(UpdateCheckOutcome::NoUpdate, check.evaluate(draft));

    let mut prerelease = release("v0.3.0");
    prerelease.prerelease = true;
    assert_eq!(UpdateCheckOutcome::NoUpdate, check.evaluate(prerelease));

    assert_eq!(
        UpdateCheckOutcome::NoUpdate,
        check.evaluate(release("v0.2.0"))
    );
    assert_eq!(
        UpdateCheckOutcome::NoUpdate,
        check.evaluate(release("v0.1.9"))
    );

    let skipped = UpdateCheck {
        skipped_version: Some(Version::parse("v0.3.0").expect("skipped version should parse")),
        ..check.clone()
    };
    assert_eq!(
        UpdateCheckOutcome::NoUpdate,
        skipped.evaluate(release("v0.3.0"))
    );

    let unsupported = UpdateCheck {
        platform_target: "aarch64-apple-darwin".to_owned(),
        ..check
    };
    assert_eq!(
        UpdateCheckOutcome::UnsupportedPlatform {
            version: Version::parse("v0.3.0").expect("latest version should parse"),
            current_version: Version::parse("v0.2.0").expect("current version should parse"),
        },
        unsupported.evaluate(release("v0.3.0"))
    );
}

fn release(tag: &str) -> ReleaseMetadata {
    ReleaseMetadata {
        tag: tag.to_owned(),
        draft: false,
        prerelease: false,
        release_notes: vec![
            "Added API token secret type".to_owned(),
            "Improved tag filtering".to_owned(),
        ],
        assets: vec![ReleaseAsset {
            target: "x86_64-unknown-linux-gnu".to_owned(),
            filename: "bastion-v0.2.0-x86_64-unknown-linux-gnu.tar.gz".to_owned(),
            sha256: "abc123".to_owned(),
            download_url: "https://codeberg.example/bastion-v0.2.0.tar.gz".to_owned(),
        }],
        release_url: "https://codeberg.example/releases/v0.2.0".to_owned(),
    }
}
