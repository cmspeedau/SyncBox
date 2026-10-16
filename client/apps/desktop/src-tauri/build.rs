fn main() {
    // Embeds the frontend assets and generates the IPC glue from tauri.conf.json.
    // Runs under plain `cargo build`; no `tauri-cli` needed to compile.
    tauri_build::build();
}
