# Syncbox

A small self-hosted file workspace: Go `net/http` API and embedded Vue 3/Vite single-page application.

## Run locally

Requirements: Go 1.22+, Node.js 20+ and npm.

```sh
cd web
npm install
npm run build
cd ..
SYNCBOX_TOKEN='replace-with-a-long-random-token' go run .
```

Open http://localhost:8080, enter the same token in **Access token**, then connect. The default data directory is `./data`; set `SYNCBOX_DATA_DIR` to change it. `SYNCBOX_ADDR` changes the listen address. The development token fallback (`development-token`) is not appropriate for a public deployment.

## Docker Compose

```sh
export SYNCBOX_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
```

The named `syncbox-data` volume persists files. Set `SYNCBOX_PORT` to change the host port (default `8080`). Put a TLS-terminating reverse proxy in front of deployments exposed beyond a trusted network.

## API

Except for health, endpoints require `Authorization: Bearer <token>`:

- `GET /api/healthz` — unauthenticated liveness check.
- `GET /api/files?path=<relative-dir>` — directory entries, ordered with folders first.
- `POST /api/upload?path=<relative-dir>` — multipart upload, streamed to temporary files; total request limit 2 GiB.
- `GET /api/download?path=<relative-file>` — streamed attachment.
- `GET /api/manifest` — sorted file metadata with SHA-256 digests.
- `GET /api/events` — status heartbeat stream using Server-Sent Events.

All file paths are relative to the data directory. Lexical traversal and symlinks resolving outside the data root are rejected. The browser's native `EventSource` cannot set authorization headers, so the event endpoint accepts `access_token` as a query parameter for that stream; use HTTPS and avoid logging query strings. The remaining API endpoints use bearer headers.

This is a scaffold, not a full sync engine: SSE currently reports connection status only; manifest is available as a snapshot endpoint.
