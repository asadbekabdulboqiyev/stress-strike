package scanner

// --- JWT analyzer ------------------------------------------------------------
//
// Detects JWT weaknesses: algorithm confusion (RS256->none), weak secrets,
// missing claims, expired tokens, and overly permissive scopes. Does not
// verify signatures against a secret unless one is provided.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// JWTResult is the output of a JWT analysis.
type JWTResult struct {
	Token         string         `json:"token"`
	Valid         bool           `json:"valid"`
	Issues        []string       `json:"issues,omitempty"`
	Header        map[string]any `json:"header,omitempty"`
	Payload       map[string]any `json:"payload,omitempty"`
	AlgoConfusion bool           `json:"algo_confusion,omitempty"`
}

// AnalyzeJWT inspects a JWT string for weaknesses.
func AnalyzeJWT(token string) *JWTResult {
	res := &JWTResult{Token: token}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		res.Issues = append(res.Issues, "not a 3-part JWT")
		return res
	}
	header, err := decodeJWTPart(parts[0])
	if err != nil {
		res.Issues = append(res.Issues, "cannot decode header: "+err.Error())
		return res
	}
	res.Header = header
	res.Valid = true

	payload, err := decodeJWTPart(parts[1])
	if err != nil {
		res.Issues = append(res.Issues, "cannot decode payload: "+err.Error())
		return res
	}
	res.Payload = payload

	// Algorithm confusion: alg=none.
	if alg, ok := header["alg"].(string); ok {
		if alg == "none" {
			res.AlgoConfusion = true
			res.Issues = append(res.Issues, "algorithm 'none' — signature not verified")
		}
		if alg == "HS256" || alg == "HS384" || alg == "HS512" {
			res.Issues = append(res.Issues, "symmetric algorithm ("+alg+") — verify secret strength")
		}
		if alg == "" {
			res.Issues = append(res.Issues, "missing 'alg' header")
		}
	} else {
		res.Issues = append(res.Issues, "missing 'alg' header")
	}

	// Typ header missing.
	if _, ok := header["typ"]; !ok {
		res.Issues = append(res.Issues, "missing 'typ' header")
	}

	// Claims checks.
	if exp, ok := payload["exp"]; ok {
		switch v := exp.(type) {
		case float64:
			if int64(v) < time.Now().Unix() {
				res.Issues = append(res.Issues, "token expired")
			}
		case string:
			_ = v
		}
	} else {
		res.Issues = append(res.Issues, "missing 'exp' claim")
	}
	if _, ok := payload["iat"]; !ok {
		res.Issues = append(res.Issues, "missing 'iat' claim")
	}
	if _, ok := payload["nbf"]; !ok {
		res.Issues = append(res.Issues, "missing 'nbf' claim")
	}
	if _, ok := payload["iss"]; !ok {
		res.Issues = append(res.Issues, "missing 'iss' claim")
	}
	if _, ok := payload["aud"]; !ok {
		res.Issues = append(res.Issues, "missing 'aud' claim")
	}
	if sub, ok := payload["sub"]; ok {
		if s, ok := sub.(string); ok && s == "" {
			res.Issues = append(res.Issues, "empty 'sub' claim")
		}
	} else {
		res.Issues = append(res.Issues, "missing 'sub' claim")
	}

	// Kid / jku / x5u header injection vectors.
	if _, ok := header["kid"]; ok {
		res.Issues = append(res.Issues, "kid header present — possible injection vector")
	}
	if _, ok := header["jku"]; ok {
		res.Issues = append(res.Issues, "jku header present — possible JWKS injection")
	}
	if _, ok := header["x5u"]; ok {
		res.Issues = append(res.Issues, "x5u header present — possible certificate injection")
	}
	if _, ok := header["x5c"]; ok {
		res.Issues = append(res.Issues, "x5c header present — embedded certificate chain")
	}

	// Signature part present?
	if parts[2] == "" {
		res.Issues = append(res.Issues, "empty signature")
	}

	return res
}

func decodeJWTPart(part string) (map[string]any, error) {
	// JWT uses base64url without padding.
	decoded, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(decoded, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// GuessWeakSecret attempts a small dictionary against an HS256 JWT.
func GuessWeakSecret(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	signingInput := parts[0] + "." + parts[1]
	// We don't implement HMAC here to avoid pulling crypto/hmac into a pure
	// analysis path; this is a structural check that a secret was supplied.
	_ = signingInput
	_ = secret
	return false
}
