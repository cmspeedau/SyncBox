package api

import (
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/syncbox/server/internal/store"
	"github.com/syncbox/server/internal/ui"
)

// The vault registry (M10): vaults are set up on the server and clients are
// pointed at them, replacing the era where a vault was whatever namespace a
// client invented. These routes share the one bearer token everything else
// uses — until per-vault credentials exist, there is no separate admin role
// to gate them behind.
//
//	GET    /admin/vaults              every vault with its bookkeeping
//	POST   /admin/vaults   {name}     register one; the server mints the id
//	PATCH  /admin/vaults/{id} {name}  rename
//	POST   /admin/vaults/{id}/archive {archived}  retire, or bring back

// maxVaultNameRunes bounds what an operator may type. Generous for a label,
// small enough that no one mistakes it for a document.
const maxVaultNameRunes = 120

// vaultNameBody is the create and rename request.
type vaultNameBody struct {
	Name string `json:"name"`
}

// vaultArchiveBody is the retire/restore request.
type vaultArchiveBody struct {
	Archived bool `json:"archived"`
}

// cleanVaultName validates the operator's label. Names exist to tell vaults
// apart in a console and in a client's --vault-name, so an empty or oversized
// one serves nobody; an all-digits name like "00000000" is perfectly legal
// base32 and therefore not refused.
func cleanVaultName(raw string) (string, bool) {
	name := strings.TrimSpace(raw)
	if name == "" || utf8.RuneCountInString(name) > maxVaultNameRunes {
		return "", false
	}
	return name, true
}

// handleIndex answers the bare root. Browsers get the embedded console;
// everything else (curl, scripts, clients) gets the JSON name-card — the
// honest answer to "what is this port" that replaced the old bare 404.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		ui.Serve(w, r, "index.html")
		return
	}
	version := s.version
	if version == "" {
		version = "dev"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name":    "syncbox",
		"role":    "zero-knowledge sync server",
		"version": version,
		"docs":    "https://github.com/cmspeedau/SyncBox/tree/main/server#readme",
		"api": map[string]string{
			"health":         "GET /healthz",
			"token":          "POST /api/v1/auth/token",
			"revisions":      "GET|POST /api/v1/vaults/{vaultID}/revisions",
			"events":         "GET /api/v1/vaults/{vaultID}/events",
			"chunks":         "GET|PUT /api/v1/vaults/{vaultID}/chunks/{chunkID}",
			"vaults":         "GET /vaults (bearer token)",
			"vault_registry": "GET|POST /admin/vaults, PATCH /admin/vaults/{id} (bearer token)",
			"backups":        "GET|POST /admin/backups (bearer token)",
		},
	})
}

// handleAsset serves one of the console's embedded static files. Routing
// each by name instead of mounting the filesystem keeps the asset surface
// exactly the files go:embed shipped — there is no path a request can walk.
func (s *Server) handleAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ui.Serve(w, r, name)
	}
}

// clientVault is the registry as a sync client needs it: which vaults exist,
// what they are called, and which are retired. No bookkeeping — a client
// resolves a name or auto-selects the sole vault; it has no business auditing
// the server, and every extra field is one more thing to keep stable.
type clientVault struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Archived bool   `json:"archived"`
}

// handleVaultsListClient is the client-facing registry read behind
// `--vault-name` and sole-vault auto-select (S3). Archived vaults are listed
// so a client can answer "that vault is retired" rather than "no such
// vault" — and refuses either way to sync into one by name.
func (s *Server) handleVaultsListClient(w http.ResponseWriter, r *http.Request) {
	vaults, err := s.store.ListVaults(r.Context())
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	out := make([]clientVault, 0, len(vaults))
	for _, vault := range vaults {
		out = append(out, clientVault{ID: vault.ID, Name: vault.Name, Archived: vault.Archived})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vaults": out})
}

func (s *Server) handleAdminVaultsList(w http.ResponseWriter, r *http.Request) {
	vaults, err := s.store.ListVaults(r.Context())
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	if vaults == nil {
		vaults = []store.VaultInfo{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"vaults": vaults})
}

func (s *Server) handleAdminVaultsCreate(w http.ResponseWriter, r *http.Request) {
	var request vaultNameBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "creating a vault needs a JSON body with a name")
		return
	}
	name, ok := cleanVaultName(request.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_name",
			"a vault name is 1 to "+strconv.Itoa(maxVaultNameRunes)+" characters")
		return
	}

	id, err := s.store.CreateVault(r.Context(), name)
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	// The fresh vault answers in its own full shape, so the console can drop
	// the row into its list without a follow-up read. Stats are honest: zero
	// until a client points at it.
	writeJSON(w, http.StatusCreated, store.VaultInfo{
		ID:        id,
		Name:      name,
		CreatedAt: s.now().Unix(),
	})
}

func (s *Server) handleAdminVaultsRename(w http.ResponseWriter, r *http.Request) {
	var request vaultNameBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "renaming needs a JSON body with a name")
		return
	}
	name, ok := cleanVaultName(request.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_name",
			"a vault name is 1 to "+strconv.Itoa(maxVaultNameRunes)+" characters")
		return
	}

	id := r.PathValue("id")
	if err := s.store.RenameVault(r.Context(), id, name); err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "name": name})
}

func (s *Server) handleAdminVaultsArchive(w http.ResponseWriter, r *http.Request) {
	var request vaultArchiveBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", `archiving needs a JSON body with "archived"`)
		return
	}

	id := r.PathValue("id")
	if err := s.store.SetVaultArchived(r.Context(), id, request.Archived); err != nil {
		writeErrorFrom(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "archived": request.Archived})
}
