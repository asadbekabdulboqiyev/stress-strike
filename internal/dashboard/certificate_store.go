package dashboard

// Certificate storage: issued certificates are persisted as JSON lines in
// $STRESS_STRIKE_HOME/certificates.jsonl so they survive restarts and can be
// downloaded / verified later. Each line is one full Certificate JSON.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
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
	certStoreHash []string // sha256 of each line, newest first
)

func certStoreInit() error {
	certStoreMu.Lock()
	defer certStoreMu.Unlock()
	if certStorePath != "" {
		return nil
	}
	certStorePath = filepath.Join(authz.ConfigHome(), "certificates.jsonl")
	certStore = nil
	certStoreByID = make(map[string]certificate.Certificate)
	certStoreHash = nil
	return certStoreLoad()
}

func certStoreLoad() error {
	f, err := os.Open(certStorePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c certificate.Certificate
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		h := sha256.Sum256([]byte(line))
		certStore = append(certStore, c)
		certStoreByID[c.CertificateID] = c
		certStoreHash = append(certStoreHash, hex.EncodeToString(h[:]))
	}
	// newest first
	for i, j := 0, len(certStore)-1; i < j; i, j = i+1, j-1 {
		certStore[i], certStore[j] = certStore[j], certStore[i]
		certStoreHash[i], certStoreHash[j] = certStoreHash[j], certStoreHash[i]
	}
	return sc.Err()
}

func certStoreAppend(c certificate.Certificate) error {
	line, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certStorePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	certStore = append([]certificate.Certificate{c}, certStore...)
	certStoreByID[c.CertificateID] = c
	h := sha256.Sum256(line)
	certStoreHash = append([]string{hex.EncodeToString(h[:])}, certStoreHash...)
	return nil
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
// "" if none exist. Used to build the hash chain.
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
// Returns the first break position (0 = newest, -1 = intact).
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
	CertificateID          string    `json:"certificate_id"`
	Target                 string    `json:"target"`
	Grade                  string    `json:"grade"`
	Verdict                string    `json:"verdict"`
	RiskScore              int       `json:"risk_score"`
	SignedAt               string    `json:"signed_at"`
	ExperimentReference    string    `json:"experiment_reference"`
	PreviousCertificateHash string   `json:"previous_certificate_hash"`
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
	return out
}

// ensure initialized once
var certStoreOnce = sync.Once{}

func certStoreEnsure() {
	certStoreOnce.Do(func() {
		_ = certStoreInit()
	})
}

// certTimestamp returns an RFC3339 UTC string.
func certTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
