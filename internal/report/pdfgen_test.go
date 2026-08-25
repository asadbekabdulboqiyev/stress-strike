package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGeneratePDFMagicBytes(t *testing.T) {
	data := GeneratePDF(samplePentestReport())
	if !bytes.HasPrefix(data, []byte("%PDF-1.")) {
		t.Fatalf("missing PDF version header, got prefix %q", data[:min(16, len(data))])
	}
	if !strings.Contains(string(data), "%%EOF") {
		t.Error("PDF missing EOF marker")
	}
	if !bytes.HasSuffix(data, []byte("%%EOF\n")) {
		t.Error("PDF does not end with EOF marker")
	}
}

func TestGeneratePDFCoreSections(t *testing.T) {
	s := string(GeneratePDF(samplePentestReport()))
	for _, want := range []string{
		"Penetration Test Report",
		"CONFIDENTIAL",
		"Acme Corporation",
		"Security Team Alpha",
		"Executive Summary",
		"Risk Assessment",
		"HIGH RISK",
		"38 / 100",
		"Findings Summary",
		"Detailed Findings",
		"OWASP Top 10",
		"Compliance Matrix",
		"Timeline",
		"Disclaimer",
		"SQL Injection in Login Form",
		"Missing Security Headers",
		"CWE-434",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("PDF missing %q", want)
		}
	}
}

func TestGeneratePDFMultiPage(t *testing.T) {
	s := string(GeneratePDF(samplePentestReport()))
	if n := strings.Count(s, "/Type /Page "); n < 2 {
		t.Errorf("expected multi-page PDF for sample report, got %d page(s)", n)
	}
}

// validatePDFLayout checks the xref table offsets actually point at their objects
// and that startxref points at the xref keyword.
func validatePDFLayout(t *testing.T, data []byte) {
	t.Helper()
	s := string(data)
	i := strings.LastIndex(s, "startxref")
	if i < 0 {
		t.Fatal("missing startxref")
	}
	fields := strings.Fields(s[i+len("startxref"):])
	if len(fields) == 0 {
		t.Fatal("no offset after startxref")
	}
	off, err := strconv.Atoi(fields[0])
	if err != nil || off < 0 || off >= len(data) {
		t.Fatalf("startxref offset out of range: %v", err)
	}
	if string(data[off:off+4]) != "xref" {
		t.Fatalf("startxref offset %d does not point at 'xref' keyword (got %q)", off, data[off:min(off+10, len(data))])
	}

	lines := strings.Split(s[off:], "\n")
	if lines[0] != "xref" {
		t.Fatalf("expected xref section header, got %q", lines[0])
	}
	hdr := strings.Fields(lines[1])
	n, err := strconv.Atoi(hdr[1])
	if err != nil {
		t.Fatalf("bad xref count: %v", err)
	}
	for j := 0; j < n; j++ {
		ent := lines[2+j]
		// Entries are 19 chars here (newline stripped by Split): oooooo ggggg n<space>
		if len(ent) < 19 || ent[10] != ' ' || ent[16] != ' ' {
			t.Fatalf("malformed xref entry %d: %q", j, ent)
		}
		typ := ent[17]
		if typ != 'n' && typ != 'f' {
			t.Fatalf("xref entry %d bad type %q", j, ent)
		}
		if j == 0 {
			continue // free head object
		}
		o, err := strconv.Atoi(ent[:10])
		if err != nil {
			t.Fatalf("xref entry %d bad offset: %v", j, err)
		}
		want := fmt.Sprintf("%d 0 obj", j)
		if o+len(want) > len(s) || s[o:o+len(want)] != want {
			t.Errorf("xref offset for object %d points to %q, want %q", j, s[o:min(o+15, len(s))], want)
		}
	}
}

func TestGeneratePDFXrefOffsetsPlausible(t *testing.T) {
	data := GeneratePDF(samplePentestReport())
	validatePDFLayout(t, data)
}

func TestGeneratePDFEscaping(t *testing.T) {
	r := samplePentestReport()
	r.Title = `Odd (Title) \Slash\ — Em`
	data := string(GeneratePDF(r))
	if !strings.Contains(data, `\(Title\)`) {
		t.Error("parentheses not escaped in PDF strings")
	}
	if !strings.Contains(data, `\\Slash\\`) {
		t.Error("backslashes not escaped in PDF strings")
	}
	for _, runeStr := range []string{"—", "é", "\t"} {
		if strings.Contains(data, runeStr) {
			t.Errorf("non-ASCII/control char %q leaked into PDF", runeStr)
		}
	}
}

func TestGeneratePDFFindingsAllPresent(t *testing.T) {
	r := samplePentestReport()
	s := string(GeneratePDF(r))
	for _, f := range r.Findings {
		clean := pdfClean(f.Title)
		if !strings.Contains(s, clean) && !strings.Contains(s, pdfEscapeStr(clean)) {
			t.Errorf("PDF missing finding title %q", f.Title)
		}
	}
}

func TestGeneratePDFEmptyReport(t *testing.T) {
	data := GeneratePDF(&PentestReport{
		Title:       "Solo Report",
		ClientName:  "Client X",
		Assessor:    "QA",
		Version:     "1.0",
		ReportDate:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		RiskRating:  "",
		Grade:       "",
		TotalChecks: 5,
	})
	s := string(data)
	if !bytes.HasPrefix(data, []byte("%PDF-")) || !strings.Contains(s, "%%EOF") {
		t.Fatal("empty report did not produce valid PDF markers")
	}
	pageObjs := strings.Count(s, "/Type /Page ")
	countRe := regexp.MustCompile(`/Count (\d+)`)
	m := countRe.FindStringSubmatch(s)
	if m == nil {
		t.Fatal("Pages /Count missing")
	}
	if cnt, _ := strconv.Atoi(m[1]); cnt != pageObjs || pageObjs < 1 {
		t.Errorf("Pages /Count %s inconsistent with %d page objects", m[1], pageObjs)
	}
	validatePDFLayout(t, data)
}

func TestGeneratePDFManyFindingsPaginate(t *testing.T) {
	r := samplePentestReport()
	for i := 0; i < 40; i++ {
		r.Findings = append(r.Findings, PentestFinding{
			ID:          100 + i,
			Title:       fmt.Sprintf("Synthetic Finding Number %d With A Fairly Long Descriptive Title", i),
			Severity:    "Medium",
			CVSS:        5.5,
			CWE:         "CWE-000",
			Description: strings.Repeat("This is a deliberately long description sentence to force wrapping. ", 12),
			AffectedURL: fmt.Sprintf("https://app.example.com/path/%d/with/a/very/long/segment/that/wraps", i),
			Evidence:    strings.Repeat("GET /endpoint HTTP/1.1\nHost: app.example.com\n\nHTTP/1.1 200 OK\n", 6),
			Impact:      "Moderate impact.",
			Remediation: "Fix it.",
		})
	}
	data := GeneratePDF(r)
	s := string(data)
	if n := strings.Count(s, "/Type /Page "); n < 8 {
		t.Errorf("expected at least 8 pages for heavy report, got only %d page object(s)", n)
	}
	validatePDFLayout(t, data)
}

func TestSaveReportPDFWritesRealPDFFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-report.pdf")

	if err := SaveReport(samplePentestReport(), "pdf", path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("PDF file is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Errorf("file first bytes are %q, want PDF signature prefix", data[:min(8, len(data))])
	}
	if !bytes.HasSuffix(data, []byte("%%EOF\n")) {
		t.Error("saved PDF does not end with EOF marker")
	}
	validatePDFLayout(t, data)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("report file permissions not private: %o", fi.Mode().Perm())
	}
}

func TestSaveReportHTMLAndMarkdownUnchanged(t *testing.T) {
	dir := t.TempDir()
	r := samplePentestReport()

	htmlPath := filepath.Join(dir, "r.html")
	if err := SaveReport(r, "htm", htmlPath); err != nil {
		t.Fatal(err)
	}
	hb, err := os.ReadFile(htmlPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hb), "<!DOCTYPE html>") {
		t.Error("htm alias no longer produces HTML")
	}

	mdPath := filepath.Join(dir, "r.markdown")
	if err := SaveReport(r, "markdown", mdPath); err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(mb), "# ") {
		t.Error("markdown alias no longer produces Markdown")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
