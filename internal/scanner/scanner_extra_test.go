package scanner

import (
	"fmt"
	"testing"
	"time"
)

// --- auth.go AuthType.String -----------------------------------------------

func TestAuthTypeString(t *testing.T) {
	cases := []struct {
		t    AuthType
		want string
	}{
		{AuthNone, "none"},
		{AuthForm, "form"},
		{AuthCookie, "cookie"},
		{AuthHeader, "header"},
		{AuthType(99), "none"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("%d", tc.t), func(t *testing.T) {
			if got := tc.t.String(); got != tc.want {
				t.Errorf("AuthType.String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// --- auth.go NewAuthSession + Client/OK/Type -------------------------------

func TestAuthSessionCookie(t *testing.T) {
	sess, err := NewAuthSession(AuthConfig{Type: AuthCookie, Cookie: "k=v"}, time.Second)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if !sess.OK() {
		t.Error("OK() = false, want true")
	}
	if sess.Type() != AuthCookie {
		t.Errorf("Type() = %v, want AuthCookie", sess.Type())
	}
	if sess.Client() == nil {
		t.Error("Client() = nil, want non-nil")
	}
}

func TestAuthSessionHeader(t *testing.T) {
	sess, err := NewAuthSession(AuthConfig{Type: AuthHeader, HeaderName: "X", HeaderValue: "y"}, time.Second)
	if err != nil {
		t.Fatalf("NewAuthSession: %v", err)
	}
	if !sess.OK() {
		t.Error("OK() = false, want true")
	}
}

func TestAuthSessionFormMissingLoginURL(t *testing.T) {
	_, err := NewAuthSession(AuthConfig{Type: AuthForm}, time.Second)
	if err == nil {
		t.Error("NewAuthSession(form, no login URL) = nil error, want error")
	}
}

// --- guard.go Config --------------------------------------------------------

func TestGuardConfigZero(t *testing.T) {
	g := GuardConfig{}
	if g.RPS != 0 || g.MaxRequests != 0 || g.Timeout != 0 {
		t.Errorf("zero GuardConfig = %+v, want zeros", g)
	}
}

// --- owasp.go ProbeCoverage -------------------------------------------------

func TestProbeCoverage(t *testing.T) {
	c := &OWASPChecker{}
	got := c.ProbeCoverage()
	if len(got) != 0 {
		t.Errorf("ProbeCoverage() = %v, want empty", got)
	}
}

// --- checks_passive.go small helpers ---------------------------------------

func TestPassiveReferrerLeaky(t *testing.T) {
	if got := passiveReferrerLeaky(""); got {
		t.Errorf("passiveReferrerLeaky(empty) = true, want false")
	}
	if got := passiveReferrerLeaky("no-referrer"); got {
		t.Errorf("passiveReferrerLeaky(no-referrer) = true, want false")
	}
	if !passiveReferrerLeaky("unsafe-url") {
		t.Errorf("passiveReferrerLeaky(unsafe-url) = false, want true")
	}
	if !passiveReferrerLeaky("no-referrer-when-downgrade") {
		t.Errorf("passiveReferrerLeaky(no-referrer-when-downgrade) = false, want true")
	}
}

func TestPassiveHSTSHasDirective(t *testing.T) {
	if got := passiveHSTSHasDirective("max-age=31536000; includeSubDomains", "includeSubDomains"); !got {
		t.Errorf("passiveHSTSHasDirective(includeSubDomains) = false, want true")
	}
	if got := passiveHSTSHasDirective("max-age=31536000", "includeSubDomains"); got {
		t.Errorf("passiveHSTSHasDirective(no directive) = true, want false")
	}
	if got := passiveHSTSHasDirective("", "includeSubDomains"); got {
		t.Errorf("passiveHSTSHasDirective(empty) = true, want false")
	}
}
