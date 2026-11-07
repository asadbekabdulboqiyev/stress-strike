package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestScanHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Set("Allow", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Set-Cookie", "PHPSESSID=abc123; Path=/")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	info, err := ScanHTTP(srv.URL)
	if err != nil {
		t.Fatalf("ScanHTTP: %v", err)
	}
	if info.Server != "nginx/1.24" {
		t.Errorf("Server = %q, want nginx/1.24", info.Server)
	}
	if info.XPoweredBy != "PHP/8.1" {
		t.Errorf("X-Powered-By = %q, want PHP/8.1", info.XPoweredBy)
	}
	if len(info.Cookies) == 0 {
		t.Error("Cookies = empty, want non-empty")
	}
	if info.CORS == nil {
		t.Fatal("CORS = nil")
	}
	if !info.CORS.IsPermissive {
		t.Error("CORS.IsPermissive = false, want true (Allow-Origin: *)")
	}
}

func TestScanHTTPDeadPort(t *testing.T) {
	_, err := ScanHTTP("http://127.0.0.1:1/")
	if err == nil {
		t.Error("ScanHTTP(dead port) = nil error, want error")
	}
}

func TestDetectTechnologies(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Server":       {"nginx/1.24"},
			"X-Powered-By": {"PHP/8.1"},
			"Set-Cookie":   {"PHPSESSID=abc123; Path=/"},
		},
	}
	techs := DetectTechnologies(resp)
	hasNginx := false
	hasPHP := false
	for _, t := range techs {
		if t == "Nginx" {
			hasNginx = true
		}
		if t == "PHP" {
			hasPHP = true
		}
	}
	if !hasNginx {
		t.Errorf("techs = %v, want Nginx", techs)
	}
	if !hasPHP {
		t.Errorf("techs = %v, want PHP", techs)
	}
}

func TestDetectTechnologiesEmpty(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{"Server": {"UnknownServer/1.0"}},
	}
	techs := DetectTechnologies(resp)
	if len(techs) != 0 {
		t.Errorf("techs = %v, want empty", techs)
	}
}

func TestContainsTech(t *testing.T) {
	techs := []string{"Nginx", "PHP", "Apache"}
	if !ContainsTech(techs, "nginx") {
		t.Error("ContainsTech(nginx) = false, want true (case-insensitive)")
	}
	if !ContainsTech(techs, "PHP") {
		t.Error("ContainsTech(PHP) = false, want true")
	}
	if ContainsTech(techs, "IIS") {
		t.Error("ContainsTech(IIS) = true, want false")
	}
	if ContainsTech(nil, "anything") {
		t.Error("ContainsTech(nil) = true, want false")
	}
}

func TestScanHTTPNoOPTIONS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			w.WriteHeader(204) // no Allow header
			return
		}
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	info, err := ScanHTTP(srv.URL)
	if err != nil {
		t.Fatalf("ScanHTTP: %v", err)
	}
	if len(info.Methods) != 0 {
		t.Errorf("Methods = %v, want empty (no Allow header)", info.Methods)
	}
}
