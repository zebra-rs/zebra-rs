#![allow(dead_code)]
/// Version information module containing package and git details
use std::fmt;

/// Build-time version information
pub struct VersionInfo {
    pub package_version: &'static str,
    pub package_name: &'static str,
    pub git_hash: &'static str,
    pub git_date: &'static str,
    pub git_message: &'static str,
    pub git_branch: &'static str,
    pub git_dirty: bool,
    pub build_date: &'static str,
}

impl VersionInfo {
    /// Get the current version information
    pub fn current() -> Self {
        VersionInfo {
            package_version: env!("CARGO_PKG_VERSION"),
            package_name: env!("CARGO_PKG_NAME"),
            git_hash: env!("GIT_HASH"),
            git_date: env!("GIT_DATE"),
            git_message: env!("GIT_MESSAGE"),
            git_branch: env!("GIT_BRANCH"),
            git_dirty: env!("GIT_DIRTY") == "true",
            build_date: env!("BUILD_DATE"),
        }
    }

    /// Get a formatted version string for display
    pub fn format_version(&self) -> String {
        let _dirty_indicator = if self.git_dirty { " (dirty)" } else { "" };
        format!(
            "{} version {} ({})\nBuild Date: {}",
            self.package_name, self.package_version, self.git_hash, self.build_date
        )
    }

    /// Get a short version string
    pub fn short_version(&self) -> String {
        let dirty_indicator = if self.git_dirty { "-dirty" } else { "" };
        format!(
            "{} {} ({}{})",
            self.package_name, self.package_version, self.git_hash, dirty_indicator
        )
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format_version())
    }
}
