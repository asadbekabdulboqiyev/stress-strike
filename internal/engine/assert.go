package engine

import (
	"fmt"
	"regexp"
	"strings"

	"stress-strike/internal/config"
)

// checkAssertions validates all configured assertions against a step result.
// It returns an error describing the first failing assertion.
func checkAssertions(assertions []config.Assertion, status int, body []byte) error {
	for _, a := range assertions {
		if err := checkAssertion(a, status, body); err != nil {
			return err
		}
	}
	return nil
}

func checkAssertion(a config.Assertion, status int, body []byte) error {
	switch a.Type {
	case "status":
		ok, err := matchStatus(a.Value, status)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("status assertion %q failed: got %d", a.Value, status)
		}
	case "json_path":
		if _, err := extractJSONPath(body, a.Value); err != nil {
			return fmt.Errorf("json_path assertion %q failed: %v", a.Value, err)
		}
	case "regex":
		re, err := regexp.Compile(a.Value)
		if err != nil {
			return fmt.Errorf("invalid regex assertion %q: %v", a.Value, err)
		}
		if !re.Match(body) {
			return fmt.Errorf("regex assertion %q failed: pattern not found in body", a.Value)
		}
	default:
		return fmt.Errorf("unsupported assertion type %q", a.Type)
	}
	return nil
}

// matchStatus reports whether want matches got. want may be an exact code such
// as "200", a status family such as "2xx", or a narrower tens-family such as
// "20x".
func matchStatus(want string, got int) (bool, error) {
	want = strings.TrimSpace(want)
	if len(want) == 3 && want[2] == 'x' && want[0] >= '0' && want[0] <= '5' {
		if want[1] == 'x' {
			return got/100 == int(want[0]-'0'), nil
		}
		if want[1] >= '0' && want[1] <= '9' {
			return got/100 == int(want[0]-'0') && (got%100)/10 == int(want[1]-'0'), nil
		}
	}
	var n int
	if _, err := fmt.Sscanf(want, "%d", &n); err != nil {
		return false, fmt.Errorf("invalid status assertion %q", want)
	}
	return got == n, nil
}
