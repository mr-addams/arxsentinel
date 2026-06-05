// ====== Module: cf-api-mock ======
//   Cloudflare API mock server for integration tests.
//   Simulates Cloudflare IP Access Rules API (create/delete/list endpoints).

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

type MockItem struct {
	ID      string `json:"id"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type MockList struct {
	ID    string     `json:"id"`
	Name  string     `json:"name"`
	Kind  string     `json:"kind"`
	Items []MockItem `json:"-"`
}

type cfAPIResponse struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type MockServer struct {
	mu       sync.RWMutex
	lists    map[string]*MockList
	nextID   atomic.Int64
	requests []RecordedRequest
}

type RecordedRequest struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	IPs    []string `json:"ips,omitempty"`
}

type RecordedItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
	AddedAt string `json:"added_at"`
}

var recordedItems []RecordedItem
var recordedMu sync.Mutex

func main() {
	mux := http.NewServeMux()
	s := &MockServer{lists: make(map[string]*MockList)}
	s.nextID.Store(1000)

	mux.HandleFunc("/accounts/", s.handleAccounts)

	// GET /recorded-items — for test verification
	mux.HandleFunc("/recorded-items", func(w http.ResponseWriter, r *http.Request) {
		recordedMu.Lock()
		defer recordedMu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(recordedItems)
	})

	// GET /reset — clear recorded items (for test isolation)
	mux.HandleFunc("/reset", func(w http.ResponseWriter, r *http.Request) {
		recordedMu.Lock()
		recordedItems = nil
		recordedMu.Unlock()
		s.mu.Lock()
		s.lists = make(map[string]*MockList)
		s.requests = nil
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"success":true}`))
	})

	log.Println("cf-api-mock listening on :8091")
	if err := http.ListenAndServe(":8091", mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func (s *MockServer) handleAccounts(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/accounts/")
	parts := strings.Split(path, "/")
	// parts: [accountID, rules, lists, <listID>, items]
	if len(parts) < 3 || parts[1] != "rules" || parts[2] != "lists" {
		writeError(w, 404, "not found")
		return
	}

	accountID := parts[0]

	switch r.Method {
	case http.MethodGet:
		if len(parts) == 3 {
			// GET /accounts/{id}/rules/lists — list all lists
			s.handleListLists(w)
		} else if len(parts) == 5 && parts[4] == "items" {
			// GET /accounts/{id}/rules/lists/{id}/items — list items in a list
			s.handleListItems(w, parts[3])
		} else {
			writeError(w, 404, "not found")
		}

	case http.MethodPost:
		if len(parts) == 3 {
			// POST /accounts/{id}/rules/lists — create a list
			s.handleCreateList(w, r, accountID)
		} else if len(parts) == 5 && parts[4] == "items" {
			// POST /accounts/{id}/rules/lists/{id}/items — add items
			s.handleAddItems(w, r, parts[3])
		} else {
			writeError(w, 404, "not found")
		}

	case http.MethodDelete:
		if len(parts) == 5 && parts[4] == "items" {
			// DELETE /accounts/{id}/rules/lists/{id}/items — remove items
			s.handleDeleteItems(w, r, parts[3])
		} else {
			writeError(w, 404, "not found")
		}

	default:
		writeError(w, 405, "method not allowed")
	}
}

func (s *MockServer) handleListLists(w http.ResponseWriter) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type listRepr struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	result := make([]listRepr, 0, len(s.lists))
	for _, l := range s.lists {
		result = append(result, listRepr{ID: l.ID, Name: l.Name, Kind: l.Kind})
	}
	writeSuccess(w, result)
}

func (s *MockServer) handleCreateList(w http.ResponseWriter, r *http.Request, accountID string) {
	var body struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "bad request: "+err.Error())
		return
	}

	id := fmt.Sprintf("list-%d", s.nextID.Add(1))
	list := &MockList{
		ID:   id,
		Name: body.Name,
		Kind: body.Kind,
	}

	s.mu.Lock()
	s.lists[id] = list
	s.mu.Unlock()

	result := map[string]string{
		"id":   id,
		"name": body.Name,
		"kind": body.Kind,
	}
	writeSuccess(w, result)
}

func (s *MockServer) handleListItems(w http.ResponseWriter, listID string) {
	s.mu.RLock()
	list, exists := s.lists[listID]
	s.mu.RUnlock()

	if !exists {
		writeSuccess(w, []MockItem{})
		return
	}

	type itemRepr struct {
		ID string `json:"id"`
		IP string `json:"ip"`
	}
	result := make([]itemRepr, len(list.Items))
	for i, item := range list.Items {
		result[i] = itemRepr{ID: item.ID, IP: item.IP}
	}
	writeSuccess(w, result)
}

func (s *MockServer) handleAddItems(w http.ResponseWriter, r *http.Request, listID string) {
	var items []struct {
		IP      string `json:"ip"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		writeError(w, 400, "bad request: "+err.Error())
		return
	}

	s.mu.Lock()
	list, exists := s.lists[listID]
	if !exists {
		list = &MockList{ID: listID, Items: make([]MockItem, 0)}
		s.lists[listID] = list
	}
	s.mu.Unlock()

	result := make([]MockItem, len(items))
	for i, item := range items {
		id := fmt.Sprintf("mock-item-%d", s.nextID.Add(1))
		mockItem := MockItem{
			ID:      id,
			IP:      item.IP,
			Comment: item.Comment,
		}
		list.Items = append(list.Items, mockItem)
		result[i] = mockItem

		recordedMu.Lock()
		recordedItems = append(recordedItems, RecordedItem{
			IP:      item.IP,
			Comment: item.Comment,
		})
		recordedMu.Unlock()
	}

	writeSuccess(w, result)
}

func (s *MockServer) handleDeleteItems(w http.ResponseWriter, r *http.Request, listID string) {
	var body struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, 400, "bad request: "+err.Error())
		return
	}

	s.mu.Lock()
	if list, exists := s.lists[listID]; exists {
		idsToRemove := make(map[string]bool)
		for _, item := range body.Items {
			idsToRemove[item.ID] = true
		}
		filtered := make([]MockItem, 0, len(list.Items))
		for _, item := range list.Items {
			if !idsToRemove[item.ID] {
				filtered = append(filtered, item)
			}
		}
		list.Items = filtered
	}
	s.mu.Unlock()

	writeSuccess(w, map[string]string{"result": "deleted"})
}

func writeSuccess(w http.ResponseWriter, result any) {
	w.Header().Set("Content-Type", "application/json")
	resp := cfAPIResponse{Success: true}
	resp.Result, _ = json.Marshal(result)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	resp := cfAPIResponse{
		Success: false,
		Errors:  []cfAPIError{{Code: code, Message: msg}},
	}
	resp.Result, _ = json.Marshal(map[string]string{"error": msg})
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(resp)
}
