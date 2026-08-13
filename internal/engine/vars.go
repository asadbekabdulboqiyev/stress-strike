package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"stress-strike/internal/config"
)

var placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

func newVars(scenario *config.Scenario, userIndex int) map[string]string {
	vars := make(map[string]string, len(scenario.Variables)+6)
	for k, v := range scenario.Variables {
		vars[k] = v
	}
	n := userIndex + 1
	vars["user"] = fmt.Sprintf("user%d", n)
	vars["pass"] = fmt.Sprintf("pass%d", n)
	vars["email"] = fmt.Sprintf("user%d@test.local", n)
	vars["item"] = fmt.Sprintf("item%d", n)
	vars["id"] = strconv.Itoa(n)
	return vars
}

func render(tmpl string, vars map[string]string) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		key := placeholderRe.FindStringSubmatch(m)[1]
		if v, ok := vars[key]; ok {
			return v
		}
		return m
	})
}

func renderBody(tmpl string, vars map[string]string) string {
	var b strings.Builder
	offset := 0
	for offset < len(tmpl) {
		start := strings.Index(tmpl[offset:], "{{")
		if start < 0 {
			b.WriteString(tmpl[offset:])
			break
		}
		start += offset
		b.WriteString(tmpl[offset:start])
		end := strings.Index(tmpl[start+2:], "}}")
		if end < 0 {
			b.WriteString(tmpl[start:])
			break
		}
		end += start + 2
		key := strings.TrimSpace(tmpl[start+2 : end])
		if v, ok := vars[key]; ok {
			if start > 0 && tmpl[start-1] == '"' {
				if encoded, err := json.Marshal(v); err == nil && len(encoded) >= 2 {
					b.Write(encoded[1 : len(encoded)-1])
				} else {
					b.WriteString(v)
				}
			} else {
				b.WriteString(v)
			}
		} else {
			b.WriteString(tmpl[start : end+2])
		}
		offset = end + 2
	}
	return b.String()
}

func extractValue(from, path string, respBody []byte, headerValue string) (string, error) {
	switch from {
	case "json":
		return extractJSONPath(respBody, path)
	case "header":
		if headerValue == "" {
			return "", fmt.Errorf("header %q not present", path)
		}
		return headerValue, nil
	case "body":
		re, err := regexp.Compile(path)
		if err != nil {
			return "", fmt.Errorf("invalid body regex %q: %w", path, err)
		}
		m := re.FindSubmatch(respBody)
		if m == nil {
			return "", fmt.Errorf("body regex %q not matched", path)
		}
		if len(m) > 1 {
			return string(m[1]), nil
		}
		return string(m[0]), nil
	default:
		return "", fmt.Errorf("unsupported extract source %q", from)
	}
}

func extractJSONPath(body []byte, path string) (string, error) {
	var value interface{}
	if err := json.Unmarshal(body, &value); err != nil {
		return "", err
	}
	cur := value
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("path %q not found", path)
		}
		cur, ok = obj[part]
		if !ok || cur == nil {
			return "", fmt.Errorf("path %q not found", path)
		}
	}
	return fmt.Sprintf("%v", cur), nil
}
