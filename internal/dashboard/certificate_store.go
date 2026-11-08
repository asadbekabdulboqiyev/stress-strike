package dashboard

// Certificate storage: issued certificates are persisted as JSON lines in
// $STRESS_STRIKE_HOME/certificates.jsonl so they survive restarts and can be
// downloaded / verified later. Each line is one full Certificate JSON.
//
// Hash chain integrity: every certificate stores the SHA-256 of the previous
// certificate line in its PreviousCertificateHash field. Appending is atomic
// (get last hash + write under one lock) so two concurrent issues cannot
// receive the same predecessor hash.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/authz"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/certificate"
)

var (
	certStoreMu   sync.Mutex
	certStorePath string
	certStore     []certificate.Certificate // newest first
	certStoreByID map[string]certificate.Certificate
	certStoreHash []string // sha256 of each line, newest first (index 0 = newest)
	certStoreErr  error    // persistent init error, if any
	certStoreInit sync.Once
)

func certStoreEnsure() {
	certStoreInit.Do(func() {
		certStoreErr = certStoreInitOnce()
	})
}

func certStoreInitOnce() error {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	home := authz.ConfigHome()
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	certStorePath = filepath.Join(home, "certificates.jsonl")
	certStore = nil
	certStoreByID = make(map[string]certificate.Certificate)
	certStoreHash = nil

	f, err := os.Open(certStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // empty store is valid
		}
		return err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	rawLines := []string{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c certificate.Certificate
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue // skip corrupt lines rather than failing the whole store
		}
		h := sha256.Sum256([]byte(line))
		rawLines = append(rawLines, line)
		certStore = append(certStore, c)
		certStoreByID[c.CertificateID] = c
		certStoreHash = append(certStoreHash, hex.EncodeToString(h[:]))
	}
	if sc.Err() != nil {
		return sc.Err()
	}

	// Reverse to newest-first
	for i, j := 0, len(certStore)-1; i < j; i, j = i+1, j-1 {
		certStore[i], certStore[j] = certStore[j], certStore[i]
		certStoreHash[i], certStoreHash[j] = certStoreHash[j], certStoreHash[i]
	}
	_ = rawLines
	return nil
}

// certStoreIssue atomically appends a certificate and returns the stored
// certificate (with PreviousCertificateHash set to the hash of the previous
// newest line) plus the hash of the line that was just written. Two concurrent
// issues cannot receive the same predecessor hash because the lock is held for
// the entire read-modify-write cycle.
func certStoreIssue(c certificate.Certificate) (*certificate.Certificate, string, error) {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()

	prevHash := ""
	if len(certStoreHash) > 0 {
		prevHash = certStoreHash[0] // newest line's hash
	}
	c.PreviousCertificateHash = prevHash

	line, err := json.Marshal(c)
	if err != nil {
		return nil, "", err
	}

	f, err := os.OpenFile(certStorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return nil, "", err
	}

	h := sha256.Sum256(line)
	hStr := hex.EncodeToString(h[:])

	// Prepend to in-memory store (newest first)
	certStore = append([]certificate.Certificate{c}, certStore...)
	certStoreByID[c.CertificateID] = c
	certStoreHash = append([]string{hStr}, certStoreHash...)

	return &c, hStr, nil
}

func certStoreGet(id string) (certificate.Certificate, bool) {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	c, ok := certStoreByID[id]
	return c, ok
}

func certStoreList() []certificate.Certificate {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	out := make([]certificate.Certificate, len(certStore))
	copy(out, certStore)
	return out
}

// certStoreLastHash returns the sha256 of the most recent certificate line, or
// "" if none exist. Kept for external callers; prefer certStoreIssue for writes.
func certStoreLastHash() string {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	if len(certStoreHash) == 0 {
		return ""
	}
	return certStoreHash[0]
}

// certStoreVerifyChain walks newest→oldest and checks that each certificate's
// PreviousCertificateHash matches the sha256 of the certificate below it.
// Returns the index of the first break (0 = newest link), or -1 if intact.
func certStoreVerifyChain() int {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	for i := 0; i+1 < len(certStore); i++ {
		expected := certStoreHash[i+1]
		if certStore[i].PreviousCertificateHash != expected {
			return i
		}
	}
	return -1
}

// CertificateSummary is a lightweight view for the history list.
type CertificateSummary struct {
	CertificateID          string `json:"certificate_id"`
	Target                 string `json:"target"`
	Grade                  string `json:"grade"`
	Verdict                string `json:"verdict"`
	RiskScore              int    `json:"risk_score"`
	SignedAt               string `json:"signed_at"`
	ExperimentReference    string `json:"experiment_reference"`
	PreviousCertificateHash string `json:"previous_certificate_hash"`
}

func certStoreSummaries() []CertificateSummary {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	out := make([]CertificateSummary, len(certStore))
	for i, c := range certStore {
		out[i] = CertificateSummary{
			CertificateID:           c.CertificateID,
			Target:                  c.Assessment.Target,
			Grade:                   c.Assessment.Grade,
			Verdict:                 c.Assessment.Verdict,
			RiskScore:               c.Assessment.RiskScore,
			SignedAt:                c.SignedAt,
			ExperimentReference:     c.ExperimentReference,
			PreviousCertificateHash: c.PreviousCertificateHash,
		}
	}
	// Sort newest first by SignedAt (defensive; in-memory is already ordered)
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].SignedAt > out[j].SignedAt
	})
	return out
}

// certTimestamp returns an RFC3339 UTC string.
func certTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
