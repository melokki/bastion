use std::cmp::Ordering;
use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAsset {
    pub target: String,
    pub filename: String,
    pub sha256: String,
    pub download_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseMetadata {
    pub tag: String,
    pub draft: bool,
    pub prerelease: bool,
    pub release_notes: Vec<String>,
    pub assets: Vec<ReleaseAsset>,
    pub release_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateCheck {
    pub current_version: Version,
    pub platform_target: String,
    pub skipped_version: Option<Version>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateInfo {
    pub version: Version,
    pub current_version: Version,
    pub release_notes: Vec<String>,
    pub asset: ReleaseAsset,
    pub release_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpdateCheckOutcome {
    Available(UpdateInfo),
    NoUpdate,
    UnsupportedPlatform {
        version: Version,
        current_version: Version,
    },
    InvalidReleaseVersion,
}

impl UpdateCheck {
    pub fn evaluate(&self, release: ReleaseMetadata) -> UpdateCheckOutcome {
        if release.draft || release.prerelease {
            return UpdateCheckOutcome::NoUpdate;
        }

        let Ok(version) = Version::parse(&release.tag) else {
            return UpdateCheckOutcome::InvalidReleaseVersion;
        };

        if version <= self.current_version || self.skipped_version.as_ref() == Some(&version) {
            return UpdateCheckOutcome::NoUpdate;
        }

        let Some(asset) = release
            .assets
            .into_iter()
            .find(|asset| asset.target == self.platform_target)
        else {
            return UpdateCheckOutcome::UnsupportedPlatform {
                version,
                current_version: self.current_version.clone(),
            };
        };

        UpdateCheckOutcome::Available(UpdateInfo {
            version,
            current_version: self.current_version.clone(),
            release_notes: release.release_notes,
            asset,
            release_url: release.release_url,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Version {
    major: u64,
    minor: u64,
    patch: u64,
}

impl Version {
    pub fn parse(input: &str) -> Result<Self, VersionParseError> {
        let input = input.strip_prefix('v').unwrap_or(input);
        let mut parts = input.split('.');
        let major = parse_part(parts.next())?;
        let minor = parse_part(parts.next())?;
        let patch = parse_part(parts.next())?;

        if parts.next().is_some() {
            return Err(VersionParseError);
        }

        Ok(Self {
            major,
            minor,
            patch,
        })
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.major, self.minor, self.patch).cmp(&(other.major, other.minor, other.patch))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "v{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VersionParseError;

impl fmt::Display for VersionParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("version must use vMAJOR.MINOR.PATCH")
    }
}

impl std::error::Error for VersionParseError {}

fn parse_part(part: Option<&str>) -> Result<u64, VersionParseError> {
    let Some(part) = part else {
        return Err(VersionParseError);
    };
    part.parse().map_err(|_| VersionParseError)
}
