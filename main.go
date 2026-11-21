package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed web/dist
var webAssets embed.FS

type server struct {
	root  string
	token string
}

type fileInfo struct {
	Name    string    `json:"name"`
	Path    string    `json:"path"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"modTime"`
	IsDir   bool      `json:"isDir"`
}

func main() {
	root := env("SYNCBOX_DATA_DIR", "./data")
	if err := os.MkdirAll(root, 0750); err != nil {
		log.Fatalf("create data directory: %v", err)
	}
	token := env("SYNCBOX_TOKEN", "development-token")
	addr := env("SYNCBOX_ADDR", ":8080")
	s := &server{root: root, token: token}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", s.health)
	mux.HandleFunc("GET /api/files", s.auth(s.listFiles))
	mux.HandleFunc("POST /api/upload", s.auth(s.upload))
	mux.HandleFunc("GET /api/download", s.auth(s.download))
	mux.HandleFunc("GET /api/manifest", s.auth(s.manifest))
	mux.HandleFunc("GET /api/events", s.auth(s.events))
	mux.Handle("/", s.static())
	log.Printf("Syncbox listening on %s (data: %s)", addr, root)
	log.Fatal(http.ListenAndServe(addr, securityHeaders(mux)))
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.SplitN(auth, " ", 2)
		credential := ""
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			credential = parts[1]
		} else if r.URL.Path == "/api/events" {
			credential = r.URL.Query().Get("access_token")
		}
		if subtle.ConstantTimeCompare([]byte(credential), []byte(s.token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "valid bearer token required"})
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	dir, err := s.resolve(r.URL.Query().Get("path"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(w, "directory not found", http.StatusNotFound)
		} else {
			http.Error(w, "unable to read directory", http.StatusInternalServerError)
		}
		return
	}
	base := filepath.Clean(s.root)
	items := make([]fileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		full := filepath.Join(dir, entry.Name())
		rel, err := filepath.Rel(base, full)
		if err != nil {
			continue
		}
		items = append(items, fileInfo{Name: entry.Name(), Path: filepath.ToSlash(rel), Size: info.Size(), ModTime: info.ModTime(), IsDir: entry.IsDir()})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].IsDir != items[j].IsDir {
			return items[i].IsDir
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	relativeDir, _ := filepath.Rel(base, dir)
	if relativeDir == "." {
		relativeDir = ""
	}
	writeJSON(w, http.StatusOK, map[string]any{"path": filepath.ToSlash(relativeDir), "files": items})
}

// resolve constrains API paths to the configured storage root and rejects traversal.
func (s *server) resolve(input string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(input))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid path")
	}
	root, err := filepath.Abs(s.root)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	candidate := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("invalid path")
	}
	// Resolve the nearest existing ancestor so symlinks cannot escape storage.
	ancestor := candidate
	for {
		if _, statErr := os.Lstat(ancestor); statErr == nil {
			resolved, evalErr := filepath.EvalSymlinks(ancestor)
			if evalErr != nil {
				return "", errors.New("invalid path")
			}
			resolvedRel, relErr := filepath.Rel(root, resolved)
			if relErr != nil || resolvedRel == ".." || strings.HasPrefix(resolvedRel, ".."+string(filepath.Separator)) {
				return "", errors.New("invalid path")
			}
			break
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", errors.New("invalid path")
		}
		ancestor = parent
	}
	return candidate, nil
}

func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	// Read at most 2 GiB plus one byte; writes are streamed to a temporary file.
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "multipart/form-data required", http.StatusBadRequest)
		return
	}
	dirParam := r.URL.Query().Get("path")
	for {
		part, err := reader.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			http.Error(w, "invalid multipart upload", http.StatusBadRequest)
			return
		}
		if part.FileName() == "" {
			part.Close()
			continue
		}
		name := filepath.Base(strings.ReplaceAll(part.FileName(), "\\", "/"))
		if name == "." || name == string(filepath.Separator) || name == "" {
			part.Close()
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		dir, err := s.resolve(dirParam)
		if err == nil {
			err = os.MkdirAll(dir, 0750)
		}
		if err != nil {
			part.Close()
			http.Error(w, "invalid destination", http.StatusBadRequest)
			return
		}
		dest, err := s.resolve(filepath.Join(dirParam, name))
		if err != nil {
			part.Close()
			http.Error(w, "invalid filename", http.StatusBadRequest)
			return
		}
		tmp, err := os.CreateTemp(dir, ".syncbox-upload-*")
		if err != nil {
			part.Close()
			http.Error(w, "unable to create upload", http.StatusInternalServerError)
			return
		}
		_, copyErr := io.Copy(tmp, part)
		closeErr := tmp.Close()
		part.Close()
		if copyErr != nil || closeErr != nil {
			os.Remove(tmp.Name())
			http.Error(w, "upload write failed", http.StatusBadRequest)
			return
		}
		if err := os.Rename(tmp.Name(), dest); err != nil {
			os.Remove(tmp.Name())
			http.Error(w, "unable to finalize upload", http.StatusInternalServerError)
			return
		}
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "uploaded"})
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("path")
	if name == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}
	file, err := s.resolve(name)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, err := os.Stat(file)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(file)
	if err != nil {
		http.Error(w, "unable to open file", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(file)}))
	w.Header().Set("Content-Length", fmt.Sprint(info.Size()))
	http.ServeContent(w, r, filepath.Base(file), info.ModTime(), f)
}

func (s *server) manifest(w http.ResponseWriter, _ *http.Request) {
	items := make([]map[string]any, 0)
	err := filepath.WalkDir(s.root, func(file string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		f, err := os.Open(file)
		if err != nil {
			return err
		}
		hash := sha256.New()
		_, copyErr := io.Copy(hash, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		rel, _ := filepath.Rel(s.root, file)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		items = append(items, map[string]any{"path": filepath.ToSlash(rel), "size": info.Size(), "modTime": info.ModTime(), "sha256": hex.EncodeToString(hash.Sum(nil))})
		return nil
	})
	if err != nil {
		http.Error(w, "unable to create manifest", http.StatusInternalServerError)
		return
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["path"].(string) < items[j]["path"].(string) })
	writeJSON(w, http.StatusOK, map[string]any{"files": items})
}

func (s *server) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if _, err := fmt.Fprintf(w, "event: status\ndata: {\"status\":\"connected\",\"time\":%q}\n\n", time.Now().UTC().Format(time.RFC3339)); err != nil {
			return
		}
		flusher.Flush()
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *server) static() http.Handler {
	assets, err := fsSub(webAssets, "web/dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		clean := path.Clean("/" + r.URL.Path)
		if clean != "/" {
			if f, err := assets.Open(strings.TrimPrefix(clean, "/")); err == nil {
				f.Close()
				files.ServeHTTP(w, r)
				return
			}
		}
		http.ServeFileFS(w, r, assets, "index.html")
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func fsSub(fsys embed.FS, dir string) (fs.FS, error) { return fs.Sub(fsys, dir) }
