//! What Syncbox does when two clients edit the same file.
//!
//! There is no merge that is safe to do silently on arbitrary bytes, so both
//! copies survive: the file that arrived second is written next to the winner
//! with a name that says what it is and when it happened. Losing someone's work
//! to a timestamp race is the failure mode a sync tool is judged on.

/// Label inserted into a conflicted copy's name.
pub const CONFLICT_LABEL: &str = "conflicted copy";

/// Builds the name for the losing copy of a file both sides edited.
///
/// The label goes between the stem and the extension, so a conflicted `report.md`
/// still opens in the editor that handles `.md`, and `notes.txt` becomes
/// `notes (conflicted copy 2026-10-16).txt`.
///
/// Dotfiles keep their leading dot attached to the stem, so `.env` becomes
/// `.env (conflicted copy 2026-10-16)` rather than a hidden file with a stray
/// label in front of it.
///
/// `date` is a plain `YYYY-MM-DD` string; the caller owns the clock so this
/// function stays deterministic and testable.
#[must_use]
pub fn conflicted_copy_name(name: &str, date: &str) -> String {
    let label = format!(" ({CONFLICT_LABEL} {date})");
    let stem_end = extension_start(name);
    let (stem, extension) = name.split_at(stem_end);
    if stem.is_empty() {
        // Nothing to attach the label to, e.g. the empty name a corrupt index
        // might hand us.
        return format!("{CONFLICT_LABEL} {date}");
    }
    format!("{stem}{label}{extension}")
}

/// Offset where the extension begins, or `name.len()` when there is none.
///
/// The last dot wins, so `archive.tar.gz` keeps `.gz` as the extension; a dot at
/// position zero is a hidden-file marker and not an extension.
fn extension_start(name: &str) -> usize {
    match name.rfind('.') {
        // A dot in the last position is part of the name, not an extension.
        Some(index) if index > 0 && index + 1 < name.len() => index,
        _ => name.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DATE: &str = "2026-10-16";

    fn conflicted(name: &str) -> String {
        conflicted_copy_name(name, DATE)
    }

    #[test]
    fn the_label_lands_before_the_extension() {
        assert_eq!(
            conflicted("notes.txt"),
            "notes (conflicted copy 2026-10-16).txt"
        );
        assert_eq!(
            conflicted("report.md"),
            "report (conflicted copy 2026-10-16).md"
        );
    }

    #[test]
    fn a_file_without_an_extension_just_takes_the_label() {
        assert_eq!(
            conflicted("LICENSE"),
            "LICENSE (conflicted copy 2026-10-16)"
        );
    }

    #[test]
    fn dotfiles_keep_their_dot_attached_to_the_stem() {
        assert_eq!(conflicted(".env"), ".env (conflicted copy 2026-10-16)");
        assert_eq!(
            conflicted(".gitignore"),
            ".gitignore (conflicted copy 2026-10-16)"
        );
    }

    #[test]
    fn only_the_last_dot_counts_as_an_extension() {
        assert_eq!(
            conflicted("archive.tar.gz"),
            "archive.tar (conflicted copy 2026-10-16).gz"
        );
    }

    #[test]
    fn a_trailing_dot_is_part_of_the_name() {
        assert_eq!(conflicted("weird."), "weird. (conflicted copy 2026-10-16)");
    }

    #[test]
    fn an_empty_name_still_produces_something_usable() {
        assert_eq!(conflicted(""), "conflicted copy 2026-10-16");
    }
}
