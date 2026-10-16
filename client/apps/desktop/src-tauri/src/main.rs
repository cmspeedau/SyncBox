//! Syncbox desktop shell.
//!
//! A thin Tauri v2 window over the Tauri-free `syncbox-agent` crate. This first
//! cut only proves the window shell compiles and links against the system webview
//! on Linux; the sync `Agent`/`SyncWorker`, tray, and panels are layered on next.

// Prevents an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

/// Round-trips a call from the webview so the frontend can confirm the IPC bridge
/// is live before any real commands are wired.
#[tauri::command]
fn ping() -> String {
    "pong".into()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![ping])
        .run(tauri::generate_context!())
        .expect("error while running Syncbox");
}
