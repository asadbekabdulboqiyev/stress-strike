package engine

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
)

var placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}`)

// varsPool recycles the per-iteration variable maps.
//
// Every iteration needs a fresh map because steps write extracted values into
// it, but the map is dead once the iteration returns: nothing retains it past
// runIteration, and no goroutine captures it. Allocating one per request cost
// twelve allocations, which at 100k req/s is over a million allocations per
// second spent entirely on map bookkeeping. Reusing the buckets removes that.
var varsPool = sync.Pool{
	New: func() any { return make(map[string]string, 16) },
}

func newVars(scenario *config.Scenario, userIndex int) map[string]string {
	vars := varsPool.Get().(map[string]string)
	// Clear rather than allocate a new map — clearing keeps the existing
	// buckets, so a map that has been grown by a wide scenario stays grown.
	for k := range vars {
		delete(vars, k)
	}
	for k, v := range scenario.Variables {
		vars[k] = v
	}
	n := userIndex + 1
	// strconv.AppendInt into a small stack buffer instead of fmt.Sprintf:
	// these five values are built on every single request.
	buf := make([]byte, 0, 32)
	buf = append(buf, "user"...)
	buf = strconv.AppendInt(buf, int64(n), 10)
	vars["user"] = string(buf)

	buf = append(buf[:0], "pass"...)
	buf = strconv.AppendInt(buf, int64(n), 10)
	vars["pass"] = string(buf)

	buf = append(buf[:0], "user"...)
	buf = strconv.AppendInt(buf, int64(n), 10)
	buf = append(buf, "@test.local"...)
	vars["email"] = string(buf)

	buf = append(buf[:0], "item"...)
	buf = strconv.AppendInt(buf, int64(n), 10)
	vars["item"] = string(buf)

	buf = strconv.AppendInt(buf[:0], int64(n), 10)
	vars["id"] = string(buf)
	return vars
}

// putVars returns an iteration's map to the pool. It must only be called once
// the iteration is finished with the map.
func putVars(vars map[string]string) {
	varsPool.Put(vars)
}

// render substitutes {{ name }} placeholders in a template.
//
// This is a hand-written scan rather than a regexp pass because it runs once
// per step per request. The regexp version cost two passes over every match —
// one to find it and one to extract the key from a fresh submatch allocation —
// which measured 2.8µs and nine allocations for a five-placeholder URL. The
// scan below visits each byte once and writes into a single buffer, and it
// grows the buffer from an estimate of the template length.
//
// The accepted grammar is unchanged from the regexp it replaces: "{{", optional
// whitespace, one or more of [A-Za-z0-9_.-], optional whitespace, "}}". A
// placeholder whose key is not in vars is left in the output verbatim, and a
// "{{" that does not start a valid placeholder is copied through so the scan
// resumes after it, matching the regexp's leftmost-match behavior.
func render(tmpl string, vars map[string]string) string {
	if !strings.Contains(tmpl, "{{") {
		return tmpl
	}
	// Most templates are a URL with a few short substitutions, so the result
	// is not much longer than the input. A single Grow avoids regrowing on
	// every placeholder.
	var b strings.Builder
	b.Grow(len(tmpl) + 16)
	offset := 0
	for offset < len(tmpl) {
		start := strings.Index(tmpl[offset:], "{{")
		if start < 0 {
			b.WriteString(tmpl[offset:])
			break
		}
		start += offset
		end, key, ok := scanPlaceholder(tmpl, start)
		if !ok {
			// Not a well-formed placeholder. Emit the pending text plus
			// exactly one byte, then resume from the next one, so an
			// overlapping "{{" is still found: in "{{{user}}}" the failed
			// attempt at index 0 consumes only the first brace, leaving the
			// match at index 1. Consuming both braces would skip it, and
			// emitting less than offset..start would drop the text before it.
			b.WriteString(tmpl[offset : start+1])
			offset = start + 1
			continue
		}
		b.WriteString(tmpl[offset:start])
		if v, found := vars[key]; found {
			b.WriteString(v)
		} else {
			b.WriteString(tmpl[start:end])
		}
		offset = end
	}
	return b.String()
}

// scanPlaceholder parses a placeholder beginning at tmpl[start], which must be
// "{{". It returns the index just past the closing "}}", the key, and whether
// the placeholder was well formed.
func scanPlaceholder(tmpl string, start int) (end int, key string, ok bool) {
	i := start + 2
	// Leading whitespace is allowed between "{{" and the key.
	for i < len(tmpl) && isPlaceholderSpace(tmpl[i]) {
		i++
	}
	keyStart := i
	for i < len(tmpl) && isPlaceholderKey(tmpl[i]) {
		i++
	}
	if i == keyStart {
		// The key must have at least one character.
		return 0, "", false
	}
	key = tmpl[keyStart:i]
	for i < len(tmpl) && isPlaceholderSpace(tmpl[i]) {
		i++
	}
	if i+1 >= len(tmpl) || tmpl[i] != '}' || tmpl[i+1] != '}' {
		return 0, "", false
	}
	return i + 2, key, true
}

func isPlaceholderSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'
}

func isPlaceholderKey(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '_' || c == '.' || c == '-':
		return true
	}
	return false
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

// bodyRegexpCache memoizes compiled body-extraction patterns.
//
// A body extraction is recompiled for every response it is applied to, and a
// multi-step scenario runs the same extraction on every request. Compiling is
// by far the dominant cost — 1.1µs and twenty-three allocations against a
// sub-microsecond match — and the pattern set is bounded by the scenario's own
// step count, so caching it turns a per-request compile into a map lookup.
//
// Invalid patterns are cached too. Returning the same error every time avoids
// recompiling a pattern that cannot succeed, and a scenario containing a typo
// should report it rather than silently skip the extraction.
var bodyRegexpCache sync.Map // map[string]*bodyRegexpEntry

type bodyRegexpEntry struct {
	re  *regexp.Regexp
	err error
}

func bodyRegexp(path string) (*regexp.Regexp, error) {
	if cached, ok := bodyRegexpCache.Load(path); ok {
		e := cached.(*bodyRegexpEntry)
		return e.re, e.err
	}
	re, err := regexp.Compile(path)
	if err != nil {
		err = fmt.Errorf("invalid body regex %q: %w", path, err)
	}
	bodyRegexpCache.Store(path, &bodyRegexpEntry{re: re, err: err})
	return re, err
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
		re, err := bodyRegexp(path)
		if err != nil {
			return "", err
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
