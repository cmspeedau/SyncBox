package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

// commit sends one revision and returns the number the server assigned.
func (c *client) commit(parent uint64, name string) uint64 {
	c.t.Helper()
	body, err := json.Marshal(map[string]any{
		"parent": parent,
		"revision": map[string]any{
			"parent":      parent,
			"dir_id":      "DIRID",
			"cipher_name": name,
			"manifest":    "QUFB",
			"size":        1,
		},
	})
	if err != nil {
		c.t.Fatalf("marshal commit: %v", err)
	}
	response := c.do(http.MethodPost, "/api/v1/vaults/vault/revisions", body)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		c.t.Fatalf("commit %s = %s", name, response.Status)
	}
	var decoded struct {
		Revision uint64 `json:"revision"`
	}
	c.mustDecode(response, &decoded)
	return decoded.Revision
}

type eventsPage struct {
	Revisions []struct {
		Revision   uint64 `json:"revision"`
		CipherName string `json:"cipher_name"`
	} `json:"revisions"`
	Upto uint64 `json:"upto"`
}

func (c *client) events(since uint64, wait string) eventsPage {
	c.t.Helper()
	path := "/api/v1/vaults/vault/events?since=" + strconv.FormatUint(since, 10) + "&wait=" + wait
	response := c.do(http.MethodGet, path, nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		c.t.Fatalf("events = %s", response.Status)
	}
	var page eventsPage
	c.mustDecode(response, &page)
	return page
}

// A long-poll already up to date returns empty once its wait elapses, and reports
// the current head so the client learns it is settled.
func TestEventsTimesOutEmptyButCurrent(t *testing.T) {
	c := newClient(t, false)
	c.commit(0, "AAAA") // head = 1

	start := time.Now()
	page := c.events(1, "300ms")
	if len(page.Revisions) != 0 {
		t.Errorf("settled events returned %d revisions, want 0", len(page.Revisions))
	}
	if page.Upto != 1 {
		t.Errorf("upto = %d, want current head 1", page.Upto)
	}
	if time.Since(start) < 250*time.Millisecond {
		t.Error("events returned early instead of honouring the wait")
	}
}

// wait=0 makes the endpoint a single shot: it answers immediately even with nothing
// new, which is what a client uses to catch up without blocking.
func TestEventsImmediateWhenNothingNew(t *testing.T) {
	c := newClient(t, false)

	start := time.Now()
	page := c.events(0, "0s")
	if time.Since(start) > 200*time.Millisecond {
		t.Errorf("wait=0 blocked for %s", time.Since(start))
	}
	if len(page.Revisions) != 0 || page.Upto != 0 {
		t.Errorf("empty events = %+v, want no revisions head 0", page)
	}
}

// The heart of the endpoint: a waiter blocked on `since` is woken by a commit and
// comes back carrying the new revision, not just a signal.
func TestEventsWakesOnCommit(t *testing.T) {
	c := newClient(t, false)

	var wg sync.WaitGroup
	wg.Add(1)
	var page eventsPage
	go func() {
		defer wg.Done()
		page = c.events(0, "5s")
	}()

	// Give the waiter a moment to register its subscription, then commit.
	time.Sleep(50 * time.Millisecond)
	c.commit(0, "WAKEME")

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("events did not wake after a commit")
	}

	if len(page.Revisions) != 1 || page.Revisions[0].CipherName != "WAKEME" {
		t.Errorf("woken events = %+v, want the committed revision", page.Revisions)
	}
	if page.Upto != 1 {
		t.Errorf("upto = %d, want 1", page.Upto)
	}
}

// A client behind by several revisions gets them all in one wake, so the notification
// doubles as catch-up rather than requiring a follow-up request.
func TestEventsCarriesBacklog(t *testing.T) {
	c := newClient(t, false)
	c.commit(0, "A")
	c.commit(1, "B")

	page := c.events(0, "0s")
	if len(page.Revisions) != 2 || page.Upto != 2 {
		t.Errorf("backlog page = %+v upto %d, want 2 revisions upto 2", page.Revisions, page.Upto)
	}
}

func TestEventsRejectsBadWait(t *testing.T) {
	c := newClient(t, false)
	response := c.do(http.MethodGet, "/api/v1/vaults/vault/events?since=0&wait=banana", nil)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Errorf("bad wait = %s, want 400", response.Status)
	}
}
