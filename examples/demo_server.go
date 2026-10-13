package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	requestCount atomic.Int64
	slowEndpoint = os.Getenv("DEMO_SLOW") != ""
	// slowMillis makes every successful response take this long. It exists so
	// that a demo can saturate a *client* (few workers, slow service) and show
	// the coordinated-omission correction doing its actual job: the raw p99
	// measures service time, while the corrected p99 measures how long a user
	// who arrived on schedule had to wait behind the client's own backlog.
	slowMillis = envMillis("DEMO_SLOW_MS")
)

// envMillis parses a non-negative millisecond count from the environment,
// returning 0 for anything unset or unparseable so the default stays fast.
func envMillis(name string) time.Duration {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return 0
	}
	ms, err := time.ParseDuration(raw + "ms")
	if err != nil || ms < 0 {
		log.Printf("ignoring %s=%q: not a millisecond count", name, raw)
		return 0
	}
	return ms
}

func main() {
	addr := "127.0.0.1:8080"
	if len(os.Args) > 1 {
		addr = os.Args[1]
	}

	port := http.NewServeMux()
	port.HandleFunc("/health", handleHealth)
	port.HandleFunc("/api/login", handleLogin)
	port.HandleFunc("/api/profile", handleProfile)
	port.HandleFunc("/api/cart", handleCart)
	port.HandleFunc("/api/checkout", handleCheckout)
	port.HandleFunc("/fail", handleFail)

	log.Printf("demo target listening on %s (slow=%v)", addr, slowEndpoint)
	if err := http.ListenAndServe(addr, port); err != nil {
		log.Fatal(err)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if slowMillis > 0 {
		time.Sleep(slowMillis)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "ok")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Tenant   string `json:"tenant"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if req.Password != "pass"+strings.TrimPrefix(req.Username, "user") {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{
			"token": fmt.Sprintf("tok-%s", req.Username),
		},
	})
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if !validToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{"name": "test", "plan": "pro"},
	})
}

func handleCart(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if !validToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"data": map[string]interface{}{"cart_id": fmt.Sprintf("cart-%d", time.Now().UnixNano())},
	})
}

func handleCheckout(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if !validToken(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"ok": true})
}

func handleFail(w http.ResponseWriter, r *http.Request) {
	requestCount.Add(1)
	if slowEndpoint {
		time.Sleep(3 * time.Second)
	}
	w.WriteHeader(http.StatusInternalServerError)
}

func validToken(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok-user")
}

func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
