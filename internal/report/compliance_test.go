package report

import (
	"strings"
	"testing"
)

func compSQLiFinding() PentestFinding {
	return PentestFinding{
		ID:            1,
		Title:         "SQL Injection in Login Form",
		Severity:      "Critical",
		CVSS:          9.1,
		CWE:           "CWE-89",
		OWASPCategory: owaspCatInjection,
		Description:   "The username parameter is vulnerable to SQL injection.",
	}
}

// ─── Mapping correctness ─────────────────────────────────────────────────────

func TestCompSQLIFailsPCI624(t *testing.T) {
	res := AssessCompliance(CompPCI, []PentestFinding{compSQLiFinding()}, nil)
	if res == nil {
		t.Fatal("AssessCompliance returned nil for PCI")
	}
	var ctl *ControlResult
	for i := range res.Controls {
		if res.Controls[i].ID == "PCI-6.2.4" {
			ctl = &res.Controls[i]
			break
		}
	}
	if ctl == nil {
		t.Fatal("PCI-6.2.4 control not found in result")
	}
	if ctl.Status != CompStatusFail {
		t.Errorf("PCI-6.2.4 status = %q, want FAIL", ctl.Status)
	}
	if len(ctl.Findings) != 1 || ctl.Findings[0] != "SQL Injection in Login Form" {
		t.Errorf("PCI-6.2.4 findings = %v, want [SQL Injection in Login Form]", ctl.Findings)
	}
}

func TestCompSQLIFailsAcrossFrameworks(t *testing.T) {
	f := compSQLiFinding()
	want := map[ComplianceFramework][]string{
		CompPCI:  {"PCI-6.2.4"},
		CompSOC2: {"SOC2-CC7.1"},
		CompISO:  {"ISO-A.8.26"},
	}
	for fw, ids := range want {
		res := AssessCompliance(fw, []PentestFinding{f}, nil)
		failed := map[string]bool{}
		for _, c := range res.Controls {
			if c.Status == CompStatusFail {
				failed[c.ID] = true
			}
		}
		for _, id := range ids {
			if !failed[id] {
				t.Errorf("%s: expected %s to FAIL, failed controls: %v", fw, id, failed)
			}
		}
		if len(failed) > len(ids) {
			t.Errorf("%s: unexpected extra failures: %v", fw, failed)
		}
	}
}

func TestCompEmptyFindingsAllPass(t *testing.T) {
	for _, fw := range SupportedFrameworks() {
		res := AssessCompliance(fw, nil, nil)
		if res == nil {
			t.Fatalf("%s: AssessCompliance returned nil", fw)
		}
		if res.Fail != 0 || res.Attention != 0 {
			t.Errorf("%s: Fail=%d Attention=%d with no findings", fw, res.Fail, res.Attention)
		}
		if len(res.Controls) < 7 {
			t.Errorf("%s: only %d controls defined, want >= 7", fw, len(res.Controls))
		}
		for _, c := range res.Controls {
			if c.Status != CompStatusPass {
				t.Errorf("%s/%s status = %q, want PASS with empty findings", fw, c.ID, c.Status)
			}
		}
		if res.Score != 100 {
			t.Errorf("%s: Score = %d, want 100", fw, res.Score)
		}
	}
}

func TestCompScoreMath(t *testing.T) {
	res := AssessCompliance(CompPCI, []PentestFinding{compSQLiFinding()}, nil)
	total := len(res.Controls)
	if res.Pass+res.Fail+res.Attention != total {
		t.Errorf("counts %d+%d+%d do not sum to %d controls", res.Pass, res.Fail, res.Attention, total)
	}
	// 8 controls: 6.2.4 FAIL (CWE-89), 11.3.1 ATTENTION (findings exist), rest PASS.
	if total != 8 {
		t.Fatalf("PCI has %d controls, want 8", total)
	}
	if res.Pass != 6 || res.Fail != 1 || res.Attention != 1 {
		t.Errorf("PCI counts Pass=%d Fail=%d Attention=%d, want 6/1/1", res.Pass, res.Fail, res.Attention)
	}
	wantScore := int(float64(res.Pass)/float64(total)*100 + 0.5)
	if res.Score != wantScore || res.Score != 75 {
		t.Errorf("Score = %d, want %d", res.Score, wantScore)
	}
}

func TestCompAttentionPath(t *testing.T) {
	findings := []PentestFinding{compSQLiFinding(), compSQLiFinding()}
	res := AssessCompliance(CompPCI, findings, nil)
	var evidence *ControlResult
	for i := range res.Controls {
		if res.Controls[i].ID == "PCI-11.3.1" {
			evidence = &res.Controls[i]
			break
		}
	}
	if evidence == nil {
		t.Fatal("PCI-11.3.1 not found")
	}
	if evidence.Status != CompStatusAttention {
		t.Errorf("PCI-11.3.1 status = %q, want ATTENTION", evidence.Status)
	}
	if len(evidence.Findings) != len(findings) {
		t.Errorf("PCI-11.3.1 finding count = %d, want %d", len(evidence.Findings), len(findings))
	}
	if res.Attention != 1 {
		t.Errorf("framework Attention = %d, want 1", res.Attention)

	}

	// No findings -> evidence control passes.
	clean := AssessCompliance(CompPCI, nil, nil)
	for _, c := range clean.Controls {
		if c.ID == "PCI-11.3.1" && c.Status != CompStatusPass {
			t.Errorf("PCI-11.3.1 with zero findings should PASS, got %q", c.Status)
		}
	}
}

func TestCompOWASPCategoryTriggersFail(t *testing.T) {
	owasp := map[string]bool{
		"A01:2021 - Broken Access Control":                      false,
		"A02:2021 - Cryptographic Failures":                     true,
		"A03:2021 - Injection":                                  true,
		"A04:2021 - Insecure Design":                            true,
		"A05:2021 - Security Misconfiguration":                  false,
		"A06:2021 - Vulnerable and Outdated Components":         true,
		"A07:2021 - Identification and Authentication Failures": true,
		"A08:2021 - Software and Data Integrity Failures":       true,
		"A09:2021 - Security Logging and Monitoring Failures":   true,
		"A10:2021 - Server-Side Request Forgery":                true,
	}
	res := AssessCompliance(CompSOC2, nil, owasp)
	expectFail := map[string]bool{"SOC2-CC6.1": false, "SOC2-CC6.6": false, "SOC2-CC9.1": false}
	for _, c := range res.Controls {
		if _, tracked := expectFail[c.ID]; tracked {
			if c.Status != CompStatusFail {
				t.Errorf("%s should FAIL from OWASP category, got %q", c.ID, c.Status)
			}
		} else if c.Status != CompStatusPass {
			t.Errorf("%s unexpectedly %q; only A01/A05 failing categories should fail mapped controls", c.ID, c.Status)
		}
	}
}

func TestCompKeywordTriggersFail(t *testing.T) {
	f := PentestFinding{
		Title:       "Outdated jQuery Library Detected",
		Severity:    "Low",
		CWE:         "CWE-1395",
		Description: "An outdated component with a known CVE-2020-11023 is loaded.",
	}
	res := AssessCompliance(CompISO, []PentestFinding{f}, nil)
	var hit bool
	for _, c := range res.Controls {
		if c.ID == "ISO-A.8.8" {
			hit = true
			if c.Status != CompStatusFail {
				t.Errorf("ISO-A.8.8 should FAIL on outdated keyword, got %q", c.Status)
			}
			if len(c.Findings) != 1 {
				t.Errorf("ISO-A.8.8 related findings = %d, want 1", len(c.Findings))
			}
		}
	}
	if !hit {
		t.Error("ISO-A.8.8 not found")
	}
}

func TestCompSupportedAndUnknownFrameworks(t *testing.T) {
	got := SupportedFrameworks()
	if len(got) != 3 {
		t.Fatalf("SupportedFrameworks returned %d frameworks, want 3", len(got))
	}
	want := map[ComplianceFramework]bool{CompPCI: false, CompSOC2: false, CompISO: false}
	for _, fw := range got {
		if _, ok := want[fw]; !ok {
			t.Errorf("unexpected framework %q", fw)
		} else {
			want[fw] = true
		}
	}
	for fw, seen := range want {
		if !seen {
			t.Errorf("framework %q missing", string(fw))
		}
	}
	if res := AssessCompliance("NOT-A-FRAMEWORK", nil, nil); res != nil {
		t.Errorf("unknown framework should return nil, got %+v", res)
	}
}

// ─── Rendering ───────────────────────────────────────────────────────────────

func compSampleResults() []ComplianceResult {
	findings := []PentestFinding{compSQLiFinding()}
	out := make([]ComplianceResult, 0, 3)
	for _, fw := range SupportedFrameworks() {
		out = append(out, *AssessCompliance(fw, findings, nil))
	}
	return out
}

func TestCompHTMLSection(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = compSampleResults()
	html := string(GenerateHTML(r))

	for _, want := range []string{
		`id="compliance-impact"`,
		"Compliance Impact",
		"PCI DSS v4.0",
		"SOC 2",
		"ISO 27001:2022",
		"PCI-6.2.4",
		"SOC2-CC7.1",
		"ISO-A.8.26",
		`<span class="cross">&#10007; FAIL</span>`,
		`<span class="check">&#10003; PASS</span>`,
		"ATTENTION",
		"Score 75%",
		"Related Findings",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML missing compliance marker %q", want)
		}
	}
}

func TestCompHTMLAbsentWhenNil(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = nil
	html := string(GenerateHTML(r))
	if strings.Contains(html, "Compliance Impact") {
		t.Error("HTML should not render Compliance Impact when Compliance is nil")
	}
	if strings.Contains(html, "compliance-impact") {
		t.Error("HTML should not contain compliance anchor when Compliance is nil")
	}
}

func TestCompMarkdownSection(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = compSampleResults()
	md := string(GenerateMarkdown(r))

	for _, want := range []string{
		"## Compliance Impact",
		"### PCI DSS v4.0",
		"### SOC 2",
		"### ISO 27001:2022",
		"| PCI-6.2.4 ",
		"FAIL",
		"PASS",
		"ATTENTION",
		"**Score:** 75%",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("Markdown missing compliance marker %q", want)
		}
	}
}

func TestCompMarkdownAbsentWhenNil(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = nil
	md := string(GenerateMarkdown(r))
	if strings.Contains(md, "Compliance Impact") {
		t.Error("Markdown should not render Compliance Impact when Compliance is nil")
	}
}

func TestCompPDFSection(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = compSampleResults()
	data := GeneratePDF(r)
	pdf := string(data)

	if !strings.HasPrefix(pdf, "%PDF-") {
		t.Fatalf("GeneratePDF output is not a PDF document")
	}
	for _, want := range []string{
		"Compliance Impact",
		"(PCI DSS v4.0)",
		"(SOC 2)",
		"(ISO 27001:2022)",
		"PCI-6.2.4",
		"(FAIL)",
		"(PASS)",
		"(ATTENTION)",
	} {
		if !strings.Contains(pdf, want) {
			t.Errorf("PDF missing compliance marker %q", want)
		}
	}
}

func TestCompPDFAbsentWhenNil(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = nil
	pdf := string(GeneratePDF(r))
	if strings.Contains(pdf, "Compliance Impact") {
		t.Error("PDF should not render Compliance Impact when Compliance is nil")
	}
}

func TestCompPDFManyFindingsStayWithinPages(t *testing.T) {
	r := samplePentestReport()
	r.Compliance = compSampleResults()
	data := GeneratePDF(r)
	if got := strings.Count(string(data), "/Type /Page "); got < 2 {
		t.Errorf("expected multi-page PDF, got %d pages", got)
	}
	if !strings.Contains(string(data), "%%EOF") {
		t.Error("PDF missing EOF marker after adding compliance section")
	}
}
