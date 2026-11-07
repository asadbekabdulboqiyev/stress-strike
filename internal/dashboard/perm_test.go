package dashboard

import (
	"net/http"
	"testing"
)

func TestPermForPath(t *testing.T) {
	cases := []struct {
		path, method, want string
	}{
		// GET matches first, so it always yields tests:view regardless of path.
		{"/api/run", http.MethodGet, "tests:view"},
		{"/api/admin/x", http.MethodGet, "tests:view"},
		{"/api/audit", http.MethodGet, "tests:view"},
		{"/api/anything", http.MethodGet, "tests:view"},
		// POST matches the run-case before the admin/audit cases.
		{"/api/run", http.MethodPost, "tests:run"},
		{"/api/audit", http.MethodPost, "tests:run"},
		// Non-GET/POST on admin → admin:access; on audit → audit:read.
		{"/api/admin/x", http.MethodDelete, "admin:access"},
		{"/api/admin/x", http.MethodPut, "admin:access"},
		{"/api/audit", http.MethodPut, "audit:read"},
		{"/api/audit", http.MethodDelete, "admin:access"}, // DELETE matches case 3
		{"/api/anything", http.MethodPatch, "tests:view"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.path+" "+tc.method, func(t *testing.T) {
			if got := permForPath(tc.path, tc.method); got != tc.want {
				t.Errorf("permForPath(%q,%q) = %q, want %q", tc.path, tc.method, got, tc.want)
			}
		})
	}
}
