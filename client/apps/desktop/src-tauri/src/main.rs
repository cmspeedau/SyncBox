//! Syncbox desktop shell.
//!
//! A thin Tauri v2 window over the Tauri-free `syncbox-agent` crate. The commands
//! in [`commands`] only read the shared [`state`] or hand blocking work (unlock,
//! the network) to a thread; every behaviour and its tests live in the agent
//! crate. The webview talks to these commands through the DTOs in [`dto`].
//!
//! The tray is deliberately left out: it needs `libappindicator`, which is absent
//! on the dev box and on the CI runner (and `tauri`'s `tray-icon` feature links it
//! at compile time), so `tauri` is built without it and the window is the whole
//! UI until a machine that carries the lib builds the app. Autostart and
//! single-instance shipped here — both are pure-Rust plugins, testable headless.

// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod dto;
mod prefs;
mod state;

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use tauri::Manager;

use state::AppState;

fn main() {
    let shared = Arc::new(Mutex::new(AppState::default()));

    tauri::Builder::default()
        // Must be the first plugin: a second launch does nothing but wake the
        // running instance — focus its window rather than start a second agent.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.unminimize();
                let _ = win.show();
                let _ = win.set_focus();
            }
        }))
        // Registers (or not) the app in the desktop session's autostart, driven
        // by the "Start at login" checkbox through set_autostart.
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        // Opens a synced folder in the OS file manager — Rust-side only (the
        // webview calls our `open_folder`, never the plugin directly), so the
        // capability file stays empty.
        .plugin(tauri_plugin_opener::init())
        .manage(shared)
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::activity,
            commands::usage,
            commands::unlock,
            commands::lock,
            commands::sync_now,
            commands::set_paused,
            commands::create_vault,
            commands::list_vaults,
            commands::open_folder,
            commands::quit,
            commands::get_prefs,
            commands::set_prefs,
            commands::get_autostart,
            commands::set_autostart,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Syncbox");
}

/// Today's date as `YYYY-MM-DD`, used to label conflicted copies. The clock lives
/// here, at the shell's edge, so the agent and engine stay deterministic.
pub(crate) fn today() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    format!("{year:04}-{month:02}-{day:02}")
}

/// Days since the Unix epoch to a proleptic Gregorian `(year, month, day)`, after
/// Howard Hinnant's `civil_from_days` — one date, no date crate.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let shifted = if z >= 0 { z } else { z - 146_096 };
    let era = shifted / 146_097;
    let day_of_era = z - era * 146_097; // [0, 146096]
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153; // [0, 11], March-based
    let day = (day_of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    if month <= 2 {
        year += 1;
    }
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn today_is_a_well_formed_date() {
        let date = today();
        assert_eq!(date.len(), 10, "{date}");
        assert_eq!(&date[4..5], "-");
        assert_eq!(&date[7..8], "-");
    }

    #[test]
    fn civil_from_days_maps_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_782), (2024, 2, 29), "leap day");
        assert_eq!(civil_from_days(19_783), (2024, 3, 1));
    }
}
