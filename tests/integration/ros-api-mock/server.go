// ====== Module: ros-api-mock ======
//   RouterOS REST API mock server for integration tests.
//   Simulates MikroTik RouterOS address-list endpoints.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// AddressListEntry mirrors mikrotik.AddressListEntry for the mock response.
type AddressListEntry struct {
	ID       string `json:".id,omitempty"`
	Address  string `json:"address"`
	List     string `json:"list"`
	Timeout  string `json:"timeout,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Disabled string `json:"disabled,omitempty"`
}

// RecordedItem captures each PUT request for test verification.
type RecordedItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
	Timeout string `json:"timeout,omitempty"`
	AddedAt string `json:"added_at"`
}

type MockServer struct {
	mu       sync.RWMutex
	entries  []AddressListEntry
	nextID   atomic.Int64
	recorded []RecordedItem
}

func main() {
	mux := http.NewServeMux()
	s := &MockServer{}

	// RouterOS REST API endpoints (mounted under /rest/...).
	mux.HandleFunc("/rest/ip/firewall/address-list", s.handleAddressList)
	mux.HandleFunc("/rest/ip/firewall/address-list/", s.handleAddressListByID)

	// Test helpers — NOT part of RouterOS API.
	mux.HandleFunc("/recorded-items", s.handleRecordedItems)
	mux.HandleFunc("/reset", s.handleReset)

	log.Println("ros-api-mock listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func (s *MockServer) handleAddressList(w http.ResponseWriter, r *http.Request) {
	// Verify Basic Auth is present (any credentials accepted).
	if _, _, ok := r.BasicAuth(); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPut:
		s.handleAdd(w, r)
	case http.MethodGet:
		s.handleList(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *MockServer) handleAddressListByID(w http.ResponseWriter, r *http.Request) {
	// Verify Basic Auth is present.
	if _, _, ok := r.BasicAuth(); !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodDelete:
		s.handleDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *MockServer) handleAdd(w http.ResponseWriter, r *http.Request) {
	var entry AddressListEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		http.Error(w, "Bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Assign incremental ID.
	id := fmt.Sprintf("*%d", s.nextID.Add(1))
	entry.ID = id
	if entry.Disabled == "" {
		entry.Disabled = "no"
	}

	s.mu.Lock()
	s.entries = append(s.entries, entry)

	// Record for test verification.
	s.recorded = append(s.recorded, RecordedItem{
		IP:      entry.Address,
		Comment: entry.Comment,
		Timeout: entry.Timeout,
		AddedAt: time.Now().UTC().Format(time.RFC3339),
	})
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{".id": id})
}

func (s *MockServer) handleList(w http.ResponseWriter, r *http.Request) {
	listName := r.URL.Query().Get("list")

	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]AddressListEntry, 0)
	for _, e := range s.entries {
		if listName == "" || e.List == listName {
			result = append(result, e)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *MockServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL: /rest/ip/firewall/address-list/{id}
	path := strings.TrimPrefix(r.URL.Path, "/rest/ip/firewall/address-list/")
	id := strings.TrimPrefix(path, "/")
	if id == "" {
		http.Error(w, "Bad request: missing ID", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i, e := range s.entries {
		if e.ID == id {
			s.entries = append(s.entries[:i], s.entries[i+1:]...)
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// RouterOS returns 200 even if nothing was deleted.
	w.WriteHeader(http.StatusOK)
}

func (s *MockServer) handleRecordedItems(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.recorded)
}

func (s *MockServer) handleReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.entries = nil
	s.recorded = nil
	s.nextID.Store(0)
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"success":true}`))
}
