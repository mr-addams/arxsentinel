// ====== Module: ubus-api-mock ======
//
//	uhttpd-mod-ubus mock server for integration tests.
//	Emulates the JSON-RPC 2.0 /ubus endpoint used by the openwrt executor
//	(session.login, uci.add_list/del_list/commit/get, rc.init).
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
)

// rpcRequest is the JSON-RPC 2.0 envelope. Params layout for the ubus
// 'call' wrapper is [sessionID, object, method, args].
type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type MockServer struct {
	mu           sync.Mutex
	entries      []string
	loginCalls   atomic.Int64
	addListCalls atomic.Int64
	delListCalls atomic.Int64
	commitCalls  atomic.Int64
	getCalls     atomic.Int64
	reloadCalls  atomic.Int64
}

func main() {
	mux := http.NewServeMux()
	s := &MockServer{}

	mux.HandleFunc("/ubus", s.handleUbus)

	// Test helpers — NOT part of the real ubus/rpcd API.
	mux.HandleFunc("/recorded-items", s.handleRecordedItems)
	mux.HandleFunc("/reset", s.handleReset)

	log.Println("ubus-api-mock listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

// handleUbus dispatches a single JSON-RPC 2.0 call.
//  1. Decode request body into rpcRequest.
//  2. Validate len(req.Params) >= 4; extract object := Params[1].(string),
//     method := Params[2].(string), args, _ := Params[3].(map[string]any).
//  3. switch object/method:
//     - "session"/"login": s.loginCalls.Add(1); data = map[string]any{"ubus_rpc_session": "mocksession"}
//     - "uci"/"add_list": s.addListCalls.Add(1); lock, append args["values"].([]any) (each cast to string) to s.entries, unlock; data = map[string]any{}
//     - "uci"/"del_list": s.delListCalls.Add(1); lock, remove matching values from s.entries, unlock; data = map[string]any{}
//     - "uci"/"commit": s.commitCalls.Add(1); data = map[string]any{}
//     - "uci"/"get": s.getCalls.Add(1); lock, copy s.entries into snapshot, unlock; data = map[string]any{"value": snapshot}
//     - "rc"/"init": s.reloadCalls.Add(1); data = map[string]any{}
//     - default: http.Error(w, "unknown method", http.StatusNotFound); return
//  4. Write response: {"jsonrpc":"2.0","id":req.ID,"result":[]any{0, data}}, Content-Type application/json.
func (s *MockServer) handleUbus(w http.ResponseWriter, r *http.Request) {
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), http.StatusBadRequest)
		return
	}

	if len(req.Params) < 4 {
		http.Error(w, "bad request: params must have >= 4 elements", http.StatusBadRequest)
		return
	}

	object, ok := req.Params[1].(string)
	if !ok {
		http.Error(w, "bad request: object must be string", http.StatusBadRequest)
		return
	}
	method, ok := req.Params[2].(string)
	if !ok {
		http.Error(w, "bad request: method must be string", http.StatusBadRequest)
		return
	}
	args, _ := req.Params[3].(map[string]any)

	var data map[string]any

	switch {
	case object == "session" && method == "login":
		s.loginCalls.Add(1)
		data = map[string]any{"ubus_rpc_session": "mocksession"}

	case object == "uci" && method == "add_list":
		s.addListCalls.Add(1)
		if values, ok := args["values"].([]any); ok {
			s.mu.Lock()
			for _, v := range values {
				s.entries = append(s.entries, v.(string))
			}
			s.mu.Unlock()
		}
		data = map[string]any{}

	case object == "uci" && method == "del_list":
		s.delListCalls.Add(1)
		if values, ok := args["values"].([]any); ok {
			// Build a lookup set of values to remove.
			toRemove := make(map[string]struct{}, len(values))
			for _, v := range values {
				toRemove[v.(string)] = struct{}{}
			}
			s.mu.Lock()
			filtered := s.entries[:0]
			for _, e := range s.entries {
				if _, drop := toRemove[e]; !drop {
					filtered = append(filtered, e)
				}
			}
			s.entries = filtered
			s.mu.Unlock()
		}
		data = map[string]any{}

	case object == "uci" && method == "commit":
		s.commitCalls.Add(1)
		data = map[string]any{}

	case object == "uci" && method == "get":
		s.getCalls.Add(1)
		s.mu.Lock()
		snapshot := make([]string, len(s.entries))
		copy(snapshot, s.entries)
		s.mu.Unlock()
		data = map[string]any{"value": snapshot}

	case object == "rc" && method == "init":
		s.reloadCalls.Add(1)
		data = map[string]any{}

	default:
		http.Error(w, "unknown method", http.StatusNotFound)
		return
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      req.ID,
		"result":  []any{0, data},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleRecordedItems (GET /recorded-items) — return the snapshot of
// the uci state and every call counter so integration tests can assert
// on observable side-effects.
func (s *MockServer) handleRecordedItems(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	entriesCopy := make([]string, len(s.entries))
	copy(entriesCopy, s.entries)
	s.mu.Unlock()

	out := struct {
		Entries      []string `json:"entries"`
		LoginCalls   int64    `json:"login_calls"`
		AddListCalls int64    `json:"add_list_calls"`
		DelListCalls int64    `json:"del_list_calls"`
		CommitCalls  int64    `json:"commit_calls"`
		GetCalls     int64    `json:"get_calls"`
		ReloadCalls  int64    `json:"reload_calls"`
	}{
		Entries:      entriesCopy,
		LoginCalls:   s.loginCalls.Load(),
		AddListCalls: s.addListCalls.Load(),
		DelListCalls: s.delListCalls.Load(),
		CommitCalls:  s.commitCalls.Load(),
		GetCalls:     s.getCalls.Load(),
		ReloadCalls:  s.reloadCalls.Load(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// handleReset (POST /reset) — drop all in-memory state and zero every
// counter so the next scenario starts from a clean slate.
func (s *MockServer) handleReset(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.entries = nil
	s.mu.Unlock()

	s.loginCalls.Store(0)
	s.addListCalls.Store(0)
	s.delListCalls.Store(0)
	s.commitCalls.Store(0)
	s.getCalls.Store(0)
	s.reloadCalls.Store(0)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}
