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
//	GET    /admin/vaults                          every vault with its bookkeeping
//	POST   /admin/vaults   {name, location, mode} register one; the server mints the id
//	PATCH  /admin/vaults/{id} {name?, location?}  rename, or point at a folder
//	POST   /admin/vaults/{id}/archive {archived}  retire, or bring back
//
// The location (S3c) is where the vault's files land on a client: a path
// relative to each client's home, so one server-side fact covers a laptop, a
// desktop and a NAS. It defaults to the vault's name and may be left empty for
// a vault whose clients are told where to put it by hand.
//
// The mode (M11 S1) is what the space is: `sync` — stored in the clear, so the
// server can index and serve it — or `vault` — encrypted on the client, so the
// server never sees a name or a byte. It is set once, at registration, and has
// no PATCH: changing it later would leave a space half ciphertext and half
// cleartext, which is neither of the two things it promises. A request that
// omits it gets the new-registration default, `sync`.

// maxVaultNameRunes bounds what an operator may type. Generous for a label,
// small enough that no one mistakes it for a document.
const maxVaultNameRunes = 120

// maxVaultLocationRunes bounds a location. A path, not a document, but deep
// enough for the folder trees people actually use.
const maxVaultLocationRunes = 1024

// vaultCreateBody is the create request. Mode is optional; empty means the
// server's default for a new registration, sync.
type vaultCreateBody struct {
	Name     string `json:"name"`
	Location string `json:"location"`
	Mode     string `json:"mode"`
}

// vaultPatchBody is the rename and/or locate request. Pointers so "absent" and
// "set to empty" stay different things: clearing a location is legitimate,
// leaving it out is not a change.
type vaultPatchBody struct {
	Name     *string `json:"name"`
	Location *string `json:"location"`
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

// cleanVaultLocation validates a location. Empty is allowed: it means the vault
// has no server-set folder and each client is told one by hand. Otherwise it is
// whatever the operator typed, used as typed, so `Syncbox/Photos`, `~/Photos`
// and `/srv/photos` are all equally valid.
func cleanVaultLocation(raw string) (string, bool) {
	location := strings.TrimSpace(raw)
	if utf8.RuneCountInString(location) > maxVaultLocationRunes {
		return "", false
	}
	return location, true
}

// newSpaceMode resolves the mode a registration asked for. Empty is the
// server's default for a new space — sync — and anything that is neither sync
// nor vault is refused, so a typo cannot leave the registry with a mode no
// reader knows how to interpret. There is deliberately no way to change a
// space's mode after creation: a space whose earlier revisions are ciphertext
// and later ones cleartext would be neither of the two things the mode
// promises.
func newSpaceMode(raw string) (store.Mode, bool) {
	mode := store.Mode(strings.TrimSpace(raw))
	if mode == "" {
		return store.ModeSync, true
	}
	if !mode.Valid() {
		return "", false
	}
	return mode, true
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
// what they are called, where each one's files land, which are retired, and
// whether the space is stored in the clear or encrypted. No bookkeeping — a
// client resolves a name or auto-selects the sole vault; it has no business
// auditing the server, and every extra field is one more thing to keep stable.
type clientVault struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Location string     `json:"location"`
	Mode     store.Mode `json:"mode"`
	Archived bool       `json:"archived"`
}

// handleVaultsListClient is the client-facing registry read behind
// `--vault-name` and sole-vault auto-select (S3). Archived vaults are listed
// so a client can answer "that vault is retired" rather than "no such
// vault" — and refuses either way to sync into one by name. The mode tells a
// client whether to encrypt (vault) or write cleartext names and bytes (sync).
func (s *Server) handleVaultsListClient(w http.ResponseWriter, r *http.Request) {
	vaults, err := s.store.ListVaults(r.Context())
	if err != nil {
		writeErrorFrom(w, err)
		return
	}
	out := make([]clientVault, 0, len(vaults))
	for _, vault := range vaults {
		out = append(out, clientVault{
			ID:       vault.ID,
			Name:     vault.Name,
			Location: vault.Location,
			Mode:     vault.Mode,
			Archived: vault.Archived,
		})
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
	var request vaultCreateBody
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
	location, ok := cleanVaultLocation(request.Location)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_location",
			"a location is at most "+strconv.Itoa(maxVaultLocationRunes)+" characters")
		return
	}
	if location == "" {
		location = name
	}
	mode, ok := newSpaceMode(request.Mode)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_mode",
			`a space's mode is "sync" (stored in the clear) or "vault" (encrypted)`)
		return
	}

	id, err := s.store.CreateVault(r.Context(), name, location, mode)
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
		Location:  location,
		Mode:      mode,
		CreatedAt: s.now().Unix(),
	})
}

// handleAdminVaultsPatch renames a vault and/or points it at a folder. Both are
// optional, but a request that changes neither is a mistake, not a no-op.
func (s *Server) handleAdminVaultsPatch(w http.ResponseWriter, r *http.Request) {
	var request vaultPatchBody
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"updating a vault needs a JSON body with a name and/or location")
		return
	}
	if request.Name == nil && request.Location == nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"updating a vault needs a name and/or location")
		return
	}

	id := r.PathValue("id")
	if request.Name != nil {
		name, ok := cleanVaultName(*request.Name)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_name",
				"a vault name is 1 to "+strconv.Itoa(maxVaultNameRunes)+" characters")
			return
		}
		if err := s.store.RenameVault(r.Context(), id, name); err != nil {
			writeErrorFrom(w, err)
			return
		}
	}
	if request.Location != nil {
		location, ok := cleanVaultLocation(*request.Location)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid_location",
				"a location is at most "+strconv.Itoa(maxVaultLocationRunes)+" characters")
			return
		}
		if err := s.store.SetVaultLocation(r.Context(), id, location); err != nil {
			writeErrorFrom(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id})
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
