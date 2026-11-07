package scanner

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func jwtB64(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

func jwtToken(header, payload any) string {
	return jwtB64(header) + "." + jwtB64(payload) + ".sig"
}

func TestAnalyzeJWT(t *testing.T) {
	// Not a 3-part JWT.
	res := AnalyzeJWT("not-a-jwt")
	if !strings.Contains(strings.Join(res.Issues, " "), "not a 3-part JWT") {
		t.Errorf("issues = %v, want not-a-jwt issue", res.Issues)
	}

	// Bad base64 header (exactly 3 parts, first part invalid base64).
	res = AnalyzeJWT("!!!..sig")
	if !strings.Contains(strings.Join(res.Issues, " "), "cannot decode header") {
		t.Errorf("issues = %v, want decode error", res.Issues)
	}

	// Valid token with alg=none.
	res = AnalyzeJWT(jwtToken(map[string]any{"alg": "none", "typ": "JWT"}, map[string]any{"sub": "u1", "exp": 9999999999.0, "iat": 1.0, "nbf": 1.0, "iss": "iss", "aud": "aud"}))
	if !res.AlgoConfusion {
		t.Errorf("AlgoConfusion = false, want true for alg=none")
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "algorithm 'none'") {
		t.Errorf("issues = %v, want algo confusion issue", res.Issues)
	}

	// Missing claims.
	res = AnalyzeJWT(jwtToken(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{}))
	if !strings.Contains(strings.Join(res.Issues, " "), "missing 'exp' claim") {
		t.Errorf("issues = %v, want missing exp issue", res.Issues)
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "missing 'iat' claim") {
		t.Errorf("issues = %v, want missing iat issue", res.Issues)
	}

	// Expired token.
	res = AnalyzeJWT(jwtToken(map[string]any{"alg": "HS256", "typ": "JWT"}, map[string]any{"sub": "u1", "exp": 1.0, "iat": 1.0, "nbf": 1.0, "iss": "iss", "aud": "aud"}))
	if !strings.Contains(strings.Join(res.Issues, " "), "token expired") {
		t.Errorf("issues = %v, want expired issue", res.Issues)
	}

	// Injection headers.
	res = AnalyzeJWT(jwtToken(map[string]any{"alg": "HS256", "typ": "JWT", "kid": "x", "jku": "y", "x5u": "z"}, map[string]any{"sub": "u1", "exp": 9999999999.0, "iat": 1.0, "nbf": 1.0, "iss": "iss", "aud": "aud"}))
	if !strings.Contains(strings.Join(res.Issues, " "), "kid header present") {
		t.Errorf("issues = %v, want kid issue", res.Issues)
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "jku header present") {
		t.Errorf("issues = %v, want jku issue", res.Issues)
	}
	if !strings.Contains(strings.Join(res.Issues, " "), "x5u header present") {
		t.Errorf("issues = %v, want x5u issue", res.Issues)
	}

	// Empty signature (3 parts, third part empty).
	res = AnalyzeJWT(jwtB64(map[string]any{"alg": "HS256", "typ": "JWT"}) + "." + jwtB64(map[string]any{"sub": "u1", "exp": 9999999999.0, "iat": 1.0, "nbf": 1.0, "iss": "iss", "aud": "aud"}) + ".")
	if !strings.Contains(strings.Join(res.Issues, " "), "empty signature") {
		t.Errorf("issues = %v, want empty signature issue", res.Issues)
	}
}

func TestDecodeJWTPart(t *testing.T) {
	// Valid JSON object.
	m, err := decodeJWTPart(jwtB64(map[string]any{"alg": "HS256"}))
	if err != nil {
		t.Fatalf("decodeJWTPart: %v", err)
	}
	if m["alg"] != "HS256" {
		t.Errorf("alg = %v, want HS256", m["alg"])
	}

	// Invalid base64.
	_, err = decodeJWTPart("!!!not-base64!!!")
	if err == nil {
		t.Error("decodeJWTPart(invalid) = nil error, want error")
	}

	// Valid base64 but not JSON.
	_, err = decodeJWTPart(jwtB64("not-a-json-object"))
	if err == nil {
		t.Error("decodeJWTPart(non-JSON) = nil error, want error")
	}
}

func TestGuessWeakSecret(t *testing.T) {
	if got := GuessWeakSecret("a.b.c", "secret"); got {
		t.Error("GuessWeakSecret = true, want false (structural check)")
	}
	if got := GuessWeakSecret("not-a-jwt", "secret"); got {
		t.Error("GuessWeakSecret(bad token) = true, want false")
	}
}
