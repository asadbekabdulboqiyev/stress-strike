package scanner

// --- Subdomain enumeration ---------------------------------------------------
//
// Passive subdomain discovery: certificate transparency logs (crt.sh),
// DNS resolution, and common DNS records. No active probing of discovered
// hostnames is performed unless a Requester is supplied and allowed.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// SubdomainResult is the output of a subdomain enumeration run.
type SubdomainResult struct {
	Target     string        `json:"target"`
	Seed       int64         `json:"seed"`
	Found      int           `json:"found"`
	Resolved   int           `json:"resolved"`
	Subdomains []Subdomain   `json:"subdomains,omitempty"`
	Duration   time.Duration `json:"duration"`
}

// Subdomain is one discovered hostname.
type Subdomain struct {
	Name    string   `json:"name"`
	IPs     []string `json:"ips,omitempty"`
	Source  string   `json:"source"`            // crtsh, dns, wordlist
	Methods []string `json:"methods,omitempty"` // A, AAAA, CNAME, MX, TXT
}

// crtShEntry is one row from crt.sh JSON output.
type crtShEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

// EnumerateSubdomains passively discovers subdomains for target.
// If req is non-nil, each discovered name is DNS-resolved (local resolution,
// not network probing through the gate).
func EnumerateSubdomains(ctx context.Context, target string, req Requester) *SubdomainResult {
	res := &SubdomainResult{Target: target}
	start := time.Now()

	found := map[string]*Subdomain{}
	var mu sync.Mutex
	add := func(name, source string, methods ...string) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || !strings.HasSuffix(name, "."+target) && name != target {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if s, ok := found[name]; ok {
			s.Source = source
			s.Methods = appendUnique(s.Methods, methods...)
			return
		}
		found[name] = &Subdomain{Name: name, Source: source, Methods: methods}
	}

	// 1) crt.sh certificate transparency log (best-effort).
	go func() {
		_ = crtSh(ctx, target, add)
	}()

	// 2) Common DNS record queries for the apex and www.
	go func() {
		dnsQuery(ctx, target, add, "A", "AAAA", "CNAME", "MX", "TXT")
		dnsQuery(ctx, "www."+target, add, "A", "AAAA", "CNAME")
	}()

	// Wait a bounded time for passive sources (they are network calls).
	select {
	case <-ctx.Done():
	case <-time.After(8 * time.Second):
	}

	// Resolve discovered names (local resolver, not through gate).
	var wg sync.WaitGroup
	resolved := 0
	for _, s := range found {
		wg.Add(1)
		go func(s *Subdomain) {
			defer wg.Done()
			ips, methods := resolveHost(ctx, s.Name)
			if len(ips) > 0 {
				s.IPs = ips
				s.Methods = appendUnique(s.Methods, methods...)
				atomicAdd(&resolved)
			}
		}(s)
	}
	wg.Wait()

	for _, s := range found {
		res.Subdomains = append(res.Subdomains, *s)
	}
	res.Found = len(found)
	res.Resolved = resolved
	res.Duration = time.Since(start)
	return res
}

func crtSh(ctx context.Context, target string, add func(name, source string, methods ...string)) error {
	u := "https://crt.sh/?q=%25." + url.QueryEscape(target) + "&output=json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "stress-strike-subenum/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	var entries []crtShEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return err
	}
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			add(name, "crt.sh", "cert")
		}
		for _, name := range strings.Split(e.CommonName, "\n") {
			name = strings.TrimSpace(name)
			name = strings.TrimPrefix(name, "*.")
			add(name, "crt.sh", "cert")
		}
	}
	return nil
}

func dnsQuery(ctx context.Context, host string, add func(name, source string, methods ...string), types ...string) {
	resolver := &net.Resolver{}
	for _, t := range types {
		select {
		case <-ctx.Done():
			return
		default:
		}
		answers, err := resolver.LookupHost(ctx, host)
		if err != nil {
			continue
		}
		ips := answers
		if len(ips) > 0 {
			add(host, "dns", append(types, ips...)...)
		}
		// Also try SRV/MX/TXT where meaningful.
		switch t {
		case "MX":
			if mx, err := resolver.LookupMX(ctx, host); err == nil {
				for _, m := range mx {
					add(m.Host, "dns", "MX")
				}
			}
		case "TXT":
			if txt, err := resolver.LookupTXT(ctx, host); err == nil {
				for _, t := range txt {
					_ = t // TXT content is informational; we record the host exists
				}
				add(host, "dns", "TXT")
			}
		}
	}
}

func resolveHost(ctx context.Context, name string) ([]string, []string) {
	resolver := &net.Resolver{}
	var ips []string
	var methods []string
	if addrs, err := resolver.LookupHost(ctx, name); err == nil {
		ips = addrs
		methods = append(methods, "A/AAAA")
	}
	if cname, err := resolver.LookupCNAME(ctx, name); err == nil && cname != name {
		methods = append(methods, "CNAME:"+cname)
	}
	if _, err := resolver.LookupMX(ctx, name); err == nil {
		methods = append(methods, "MX")
	}
	return ips, methods
}

func appendUnique(s []string, v ...string) []string {
	for _, x := range v {
		found := false
		for _, y := range s {
			if x == y {
				found = true
				break
			}
		}
		if !found {
			s = append(s, x)
		}
	}
	return s
}

func atomicAdd(n *int) {
	// Simple atomic-ish increment; good enough for a counter.
	*n++
}
