// Package ui serves the operator's console: one HTML page, one script, one
// stylesheet, all embedded into the server binary at build time. There is no
// node, no npm, and no build step — the source under static/ is the shipped
// artifact, which keeps the deployment story (one binary, scratch container)
// intact.
//
// The page is deliberately narrow: it shows what the server can honestly know
// without a key — bookkeeping, chunk counts, snapshots — and its face says which
// spaces it can read (a sync space, stored in the clear) and which it cannot (a
// vault, encrypted on the client, M11 S1).
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed static
var static embed.FS

// assets is the embedded tree with its directory prefix removed.
var assets, _ = fs.Sub(static, "static")

// contentTypes pins the types of the shipped files. Content sniffing would
// label the stylesheet text/plain, and the console runs under a strict CSP
// that trusts nothing without a real type.
var contentTypes = map[string]string{
	"index.html": "text/html; charset=utf-8",
	"app.js":     "text/javascript; charset=utf-8",
	"style.css":  "text/css; charset=utf-8",
}

// Serve writes the named static file with headers that fit a console served
// beside the API it talks to. Unknown names answer 404, so this doubles as
// the asset allowlist: nothing on disk outside static/ is reachable.
//
// The CSP is the load-bearing header: default-src 'self' with nothing unsafe
// means the page can never phone home or run injected script — the promise it
// makes about itself in its own text, enforced by the browser.
//
// index.html is no-store because it hosts the login form; a stale console tab
// is worse than re-reading three small files. Script and stylesheet are
// no-cache, so a revalidated (usually 304) copy is always current.
func Serve(w http.ResponseWriter, r *http.Request, name string) {
	body, err := fs.ReadFile(assets, name)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	head := w.Header()
	head.Set("Content-Type", contentTypes[name])
	head.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'")
	if name == "index.html" {
		head.Set("Cache-Control", "no-store")
	} else {
		head.Set("Cache-Control", "no-cache")
	}
	w.Write(body)
}
