//! The app's own preferences, kept beside the session in the app config dir —
//! the one thing the shell persists that is not a worker's index.
//!
//! Deliberately small and forgiving: an absent or unreadable file reads as the
//! defaults (a broken pref must never stop the app from opening), and unknown
//! fields are ignored, so a pref written by a newer build downgrades quietly.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Which palette a window paints. `System` leaves the decision to
/// `prefers-color-scheme`; the other two pin it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    /// Follow the desktop's light/dark setting.
    #[default]
    System,
    /// Always the light palette.
    Light,
    /// Always the dark palette.
    Dark,
}

/// Reads a theme forgivingly: a word this build does not know reads as
/// `System` rather than failing the whole file (the same downgrade rule as an
/// unknown field).
impl<'de> Deserialize<'de> for Theme {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "light" => Self::Light,
            "dark" => Self::Dark,
            _ => Self::System,
        })
    }
}

/// The stored switches. `camelCase` on disk matches what the webview exchanges.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Prefs {
    /// Reveal the advanced tier (create-vault, by-hand vault id, extra sync
    /// folders). Gates controls that really exist; stores nothing else.
    pub show_hidden: bool,
    /// The window palette; `System` follows the desktop.
    pub theme: Theme,
}

/// Reads the preferences; anything wrong on disk reads as the defaults.
#[must_use]
pub fn load(path: &Path) -> Prefs {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Writes the preferences, creating the directory if this is the first save.
///
/// # Errors
///
/// A human-readable reason if the file (or its directory) cannot be written.
pub fn save(path: &Path, prefs: &Prefs) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("could not create the config dir: {e}"))?;
    }
    let text = serde_json::to_string_pretty(prefs).map_err(|e| e.to_string())?;
    fs::write(path, text).map_err(|e| format!("could not write the preferences: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefs_survive_a_round_trip() {
        let dir = std::env::temp_dir().join(format!("syncbox-prefs-{}", std::process::id()));
        let file = dir.join("prefs.json");
        let _ = fs::remove_dir_all(&dir);

        assert_eq!(
            load(&file),
            Prefs::default(),
            "absent reads as the defaults"
        );
        let prefs = Prefs {
            show_hidden: true,
            theme: Theme::Dark,
        };
        save(&file, &prefs).expect("first save creates the dir");
        assert_eq!(load(&file), prefs);
        assert_eq!(
            serde_json::to_string(&prefs).unwrap(),
            r#"{"showHidden":true,"theme":"dark"}"#,
            "the webview exchanges the theme as a lowercase word"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_or_future_file_still_opens_the_app() {
        let dir = std::env::temp_dir().join(format!("syncbox-prefs-bad-{}", std::process::id()));
        let file = dir.join("prefs.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(&file, "not json at all").unwrap();
        assert_eq!(
            load(&file),
            Prefs::default(),
            "unreadable reads as the defaults"
        );

        // A newer build's file: its extra fields must not break this one.
        fs::write(&file, r#"{"showHidden":true,"nextPassAt":123}"#).unwrap();
        assert!(load(&file).show_hidden, "known fields still read");
        assert_eq!(
            load(&file).theme,
            Theme::System,
            "a file older than the theme field follows the desktop"
        );

        // A word this build does not know must not sink the known switches.
        fs::write(&file, r#"{"showHidden":true,"theme":"neon"}"#).unwrap();
        let loaded = load(&file);
        assert!(loaded.show_hidden, "known fields still read");
        assert_eq!(loaded.theme, Theme::System, "unknown theme reads as system");

        let _ = fs::remove_dir_all(&dir);
    }
}
