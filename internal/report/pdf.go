package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PentestReport is a comprehensive security assessment report.
type PentestReport struct {
	Title          string
	ClientName     string
	AssessmentDate time.Time
	ReportDate     time.Time
	Assessor       string
	Version        string

	ExecutiveSummary string
	RiskRating       string
	OverallScore     int
	Grade            string

	TargetURLs  []string
	IPAddresses []string
	Exclusions  []string

	Findings []PentestFinding

	TotalChecks   int
	TotalFound    int
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int

	ScanDuration    time.Duration
	OWASPCompliance map[string]bool
}

// PentestFinding is a detailed vulnerability finding.
type PentestFinding struct {
	ID                int
	Title             string
	Severity          string
	CVSS              float64
	CWE               string
	OWASPCategory     string
	Description       string
	AffectedURL       string
	Parameter         string
	StepsToReproduce  []string
	Evidence          string
	Impact            string
	Remediation       string
	RemediationEffort string
	References        []string
}

func severityColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "#dc3545"
	case "high":
		return "#fd7e14"
	case "medium":
		return "#ffc107"
	case "low":
		return "#28a745"
	case "info":
		return "#17a2b8"
	default:
		return "#6c757d"
	}
}

func severityTextColor(sev string) string {
	if strings.ToLower(sev) == "medium" {
		return "#212529"
	}
	return "#ffffff"
}

func gradeColor(grade string) string {
	switch strings.ToUpper(grade) {
	case "A":
		return "#28a745"
	case "B":
		return "#6cb33f"
	case "C":
		return "#ffc107"
	case "D":
		return "#fd7e14"
	case "F":
		return "#dc3545"
	default:
		return "#6c757d"
	}
}

func riskGaugeColor(rating string) string {
	switch strings.ToLower(rating) {
	case "critical":
		return "#dc3545"
	case "high":
		return "#fd7e14"
	case "medium":
		return "#ffc107"
	case "low":
		return "#28a745"
	default:
		return "#6c757d"
	}
}

func gaugePercentage(score int) float64 {
	return float64(score) * 2.7
}

func owaspOrder() []string {
	return []string{
		"A01:2021 - Broken Access Control",
		"A02:2021 - Cryptographic Failures",
		"A03:2021 - Injection",
		"A04:2021 - Insecure Design",
		"A05:2021 - Security Misconfiguration",
		"A06:2021 - Vulnerable and Outdated Components",
		"A07:2021 - Identification and Authentication Failures",
		"A08:2021 - Software and Data Integrity Failures",
		"A09:2021 - Security Logging and Monitoring Failures",
		"A10:2021 - Server-Side Request Forgery",
	}
}

// GenerateHTML produces a self-contained HTML pentest report.
func GenerateHTML(report *PentestReport) []byte {
	var b strings.Builder

	// ── Head ──
	b.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">`)
	fmt.Fprintf(&b, "<title>%s</title>", esc(report.Title))
	b.WriteString(`<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg: #f8f9fa; --surface: #ffffff; --text: #212529; --muted: #6c757d;
  --border: #dee2e6; --accent: #0d6efd; --critical: #dc3545; --high: #fd7e14;
  --medium: #ffc107; --low: #28a745; --info: #17a2b8;
}
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; font-size: 14px; }
.container { max-width: 960px; margin: 0 auto; padding: 24px; }
.header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%); color: white; padding: 48px 40px; border-radius: 12px; margin-bottom: 32px; }
.header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
.header .subtitle { font-size: 14px; opacity: 0.8; }
.header .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-top: 24px; }
.header .meta-item { background: rgba(255,255,255,0.08); border-radius: 8px; padding: 12px 16px; }
.header .meta-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; opacity: 0.6; margin-bottom: 4px; }
.header .meta-value { font-size: 15px; font-weight: 600; }

.toc { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 24px 32px; margin-bottom: 32px; }
.toc h2 { font-size: 16px; margin-bottom: 12px; }
.toc ol { padding-left: 20px; }
.toc li { margin-bottom: 6px; }
.toc a { color: var(--accent); text-decoration: none; }
.toc a:hover { text-decoration: underline; }

.section { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 28px 32px; margin-bottom: 24px; }
.section h2 { font-size: 20px; font-weight: 700; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 2px solid var(--accent); }
.section h3 { font-size: 16px; font-weight: 600; margin: 16px 0 8px; }

.risk-gauge { display: flex; align-items: center; gap: 24px; margin: 20px 0; }
.gauge-ring { position: relative; width: 120px; height: 120px; flex-shrink: 0; }
.gauge-ring svg { width: 120px; height: 120px; transform: rotate(-90deg); }
.gauge-ring .track { fill: none; stroke: #e9ecef; stroke-width: 10; }
.gauge-ring .fill { fill: none; stroke-width: 10; stroke-linecap: round; transition: stroke-dashoffset 0.6s ease; }
.gauge-label { position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center; }
.gauge-label .score { font-size: 32px; font-weight: 800; line-height: 1; }
.gauge-label .grade { font-size: 16px; font-weight: 700; margin-top: 2px; }
.gauge-info .rating-badge { display: inline-block; padding: 4px 16px; border-radius: 20px; font-size: 14px; font-weight: 700; color: white; margin-bottom: 8px; }
.gauge-info .summary { font-size: 13px; color: var(--muted); line-height: 1.5; max-width: 500px; }

.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin: 16px 0; }
.stat-card { background: var(--bg); border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .value { font-size: 28px; font-weight: 800; }
.stat-card .label { font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }

.severity-pie { display: flex; justify-content: center; margin: 20px 0; }
.pie-chart { width: 200px; height: 200px; border-radius: 50%; position: relative; }

.findings-list { display: flex; flex-direction: column; gap: 16px; }
.finding-card { border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }
.finding-header { display: flex; align-items: center; gap: 12px; padding: 14px 20px; border-bottom: 1px solid var(--border); }
.severity-badge { display: inline-block; padding: 3px 12px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: white; }
.finding-title { font-size: 15px; font-weight: 600; }
.cvss-tag { margin-left: auto; background: var(--bg); padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; color: var(--muted); }
.finding-body { padding: 16px 20px; }
.finding-body p { margin-bottom: 10px; font-size: 13px; }
.finding-body .label { font-weight: 600; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.finding-body .steps { list-style: decimal; padding-left: 20px; }
.finding-body .steps li { margin-bottom: 4px; font-size: 13px; }
.evidence-box { background: #1a1a2e; color: #e0e0e0; padding: 12px 16px; border-radius: 6px; font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace; font-size: 12px; overflow-x: auto; white-space: pre-wrap; margin: 8px 0; }

.scope-list { list-style: none; padding: 0; }
.scope-list li { padding: 8px 0; border-bottom: 1px solid #f0f0f0; font-size: 13px; }
.scope-list li:last-child { border-bottom: none; }

.owasp-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.owasp-table th { text-align: left; padding: 10px 12px; background: var(--bg); font-weight: 600; border-bottom: 2px solid var(--border); }
.owasp-table td { padding: 10px 12px; border-bottom: 1px solid #f0f0f0; }
.owasp-table .check { color: var(--low); font-weight: 700; }
.owasp-table .cross { color: var(--critical); font-weight: 700; }

.footer { text-align: center; padding: 24px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); margin-top: 24px; }

@media print {
  body { background: white; }
  .container { padding: 0; }
  .section { break-inside: avoid; box-shadow: none; border: 1px solid #ddd; }
  .finding-card { break-inside: avoid; }
}
</style>
</head>
<body>
<div class="container">`)

	// ── Header ──
	b.WriteString(`<div class="header">`)
	fmt.Fprintf(&b, `<h1>%s</h1>`, esc(report.Title))
	b.WriteString(`<div class="subtitle">CONFIDENTIAL — SECURITY ASSESSMENT REPORT</div>`)
	b.WriteString(`<div class="meta">`)
	metaItem(&b, "Client", report.ClientName)
	metaItem(&b, "Assessor", report.Assessor)
	metaItem(&b, "Version", report.Version)
	metaItem(&b, "Assessment Date", report.AssessmentDate.Format("02 Jan 2006"))
	metaItem(&b, "Report Date", report.ReportDate.Format("02 Jan 2006"))
	metaItem(&b, "Duration", report.ScanDuration.Round(time.Second).String())
	b.WriteString(`</div></div>`)

	// ── Table of Contents ──
	b.WriteString(`<div class="toc"><h2>Table of Contents</h2><ol>`)
	tocItems := []struct{ label, anchor string }{
		{"Executive Summary", "executive-summary"},
		{"Risk Assessment", "risk-assessment"},
		{"Scope", "scope"},
		{"Findings Summary", "findings-summary"},
		{"Detailed Findings", "detailed-findings"},
		{"Timeline", "timeline"},
		{"Disclaimer", "disclaimer"},
	}
	for _, item := range tocItems {
		fmt.Fprintf(&b, `<li><a href="#%s">%s</a></li>`, item.anchor, item.label)
	}
	b.WriteString(`</ol></div>`)

	// ── Executive Summary ──
	b.WriteString(`<div class="section" id="executive-summary"><h2>Executive Summary</h2>`)
	fmt.Fprintf(&b, `<p>%s</p>`, esc(report.ExecutiveSummary))
	b.WriteString(`</div>`)

	// ── Risk Assessment ──
	b.WriteString(`<div class="section" id="risk-assessment"><h2>Risk Assessment</h2>`)
	b.WriteString(`<div class="risk-gauge">`)

	// SVG gauge ring
	circ := 2.0 * 3.14159265 * 48.0
	filled := circ - (circ * float64(report.OverallScore) / 100.0)
	gaugeClr := riskGaugeColor(report.RiskRating)
	b.WriteString(`<div class="gauge-ring">`)
	fmt.Fprintf(&b, `<svg viewBox="0 0 120 120"><circle class="track" cx="60" cy="60" r="48"/>`)
	fmt.Fprintf(&b, `<circle class="fill" cx="60" cy="60" r="48" stroke="%s" stroke-dasharray="%.1f" stroke-dashoffset="%.1f"/>`, gaugeClr, circ, filled)
	b.WriteString(`</svg>`)
	b.WriteString(`<div class="gauge-label">`)
	fmt.Fprintf(&b, `<span class="score">%d</span>`, report.OverallScore)
	fmt.Fprintf(&b, `<span class="grade" style="color:%s">%s</span>`, gradeColor(report.Grade), esc(report.Grade))
	b.WriteString(`</div></div>`)

	// Info
	b.WriteString(`<div class="gauge-info">`)
	fmt.Fprintf(&b, `<div class="rating-badge" style="background:%s">%s Risk</div>`, gaugeClr, strings.ToUpper(esc(report.RiskRating)))
	fmt.Fprintf(&b, `<p class="summary">Overall security posture rated <strong>%s</strong> based on %d total findings across %d checks performed.</p>`,
		strings.ToUpper(report.RiskRating), report.TotalFound, report.TotalChecks)
	b.WriteString(`</div>`)
	b.WriteString(`</div>`) // risk-gauge

	// Stats grid
	b.WriteString(`<div class="stats-grid">`)
	statCard(&b, "#dc3545", report.CriticalCount, "Critical")
	statCard(&b, "#fd7e14", report.HighCount, "High")
	statCard(&b, "#ffc107", report.MediumCount, "Medium")
	statCard(&b, "#28a745", report.LowCount, "Low")
	statCard(&b, "#17a2b8", report.InfoCount, "Info")
	statCard(&b, "#0d6efd", report.TotalChecks, "Checks Run")
	b.WriteString(`</div>`)
	b.WriteString(`</div>`)

	// ── Scope ──
	b.WriteString(`<div class="section" id="scope"><h2>Scope</h2>`)
	if len(report.TargetURLs) > 0 {
		b.WriteString(`<h3>Target URLs</h3><ul class="scope-list">`)
		for _, u := range report.TargetURLs {
			fmt.Fprintf(&b, `<li>%s</li>`, esc(u))
		}
		b.WriteString(`</ul>`)
	}
	if len(report.IPAddresses) > 0 {
		b.WriteString(`<h3>IP Addresses</h3><ul class="scope-list">`)
		for _, ip := range report.IPAddresses {
			fmt.Fprintf(&b, `<li>%s</li>`, esc(ip))
		}
		b.WriteString(`</ul>`)
	}
	if len(report.Exclusions) > 0 {
		b.WriteString(`<h3>Exclusions</h3><ul class="scope-list">`)
		for _, ex := range report.Exclusions {
			fmt.Fprintf(&b, `<li>%s</li>`, esc(ex))
		}
		b.WriteString(`</ul>`)
	}
	b.WriteString(`</div>`)

	// ── Findings Summary (pie chart) ──
	b.WriteString(`<div class="section" id="findings-summary"><h2>Findings Summary</h2>`)
	b.WriteString(`<div class="severity-pie">`)
	if report.TotalFound > 0 {
		b.WriteString(`<div class="pie-chart" style="background:conic-gradient(`)
		parts := []struct {
			cnt   int
			color string
		}{
			{report.CriticalCount, "#dc3545"},
			{report.HighCount, "#fd7e14"},
			{report.MediumCount, "#ffc107"},
			{report.LowCount, "#28a745"},
			{report.InfoCount, "#17a2b8"},
		}
		offset := 0
		for _, p := range parts {
			if p.cnt == 0 {
				continue
			}
			pct := float64(p.cnt) / float64(report.TotalFound) * 100.0
			fmt.Fprintf(&b, "%s %.1f%% ", p.color, pct)
			fmt.Fprintf(&b, "%d%% ", offset)
			offset += int(pct)
		}
		b.WriteString(`)"></div>`)
	} else {
		b.WriteString(`<p style="color:var(--muted)">No findings recorded.</p>`)
	}
	b.WriteString(`</div>`)

	// Severity breakdown table
	b.WriteString(`<table class="owasp-table"><thead><tr><th>Severity</th><th>Count</th><th>Percentage</th></tr></thead><tbody>`)
	for _, row := range []struct {
		label, color string
		cnt          int
	}{
		{"Critical", "#dc3545", report.CriticalCount},
		{"High", "#fd7e14", report.HighCount},
		{"Medium", "#ffc107", report.MediumCount},
		{"Low", "#28a745", report.LowCount},
		{"Info", "#17a2b8", report.InfoCount},
	} {
		pct := 0.0
		if report.TotalFound > 0 {
			pct = float64(row.cnt) / float64(report.TotalFound) * 100
		}
		fmt.Fprintf(&b, `<tr><td><span class="severity-badge" style="background:%s">%s</span></td><td>%d</td><td>%.1f%%</td></tr>`,
			row.color, row.label, row.cnt, pct)
	}
	b.WriteString(`</tbody></table></div>`)

	// ── Detailed Findings ──
	b.WriteString(`<div class="section" id="detailed-findings"><h2>Detailed Findings</h2>`)
	if len(report.Findings) > 0 {
		b.WriteString(`<div class="findings-list">`)
		for _, f := range report.Findings {
			writeFindingCard(&b, &f)
		}
		b.WriteString(`</div>`)
	} else {
		b.WriteString(`<p style="color:var(--muted)">No findings to display.</p>`)
	}
	b.WriteString(`</div>`)

	// ── OWASP Compliance Matrix ──
	if report.OWASPCompliance != nil && len(report.OWASPCompliance) > 0 {
		b.WriteString(`<div class="section" id="owasp-compliance"><h2>OWASP Top 10 (2021) Compliance Matrix</h2>`)
		b.WriteString(`<table class="owasp-table"><thead><tr><th>Category</th><th>Status</th></tr></thead><tbody>`)
		for _, cat := range owaspOrder() {
			status := "Pass"
			symbol := `<span class="check">&#10003;</span>`
			if !report.OWASPCompliance[cat] {
				status = "Fail"
				symbol = `<span class="cross">&#10007;</span>`
			}
			fmt.Fprintf(&b, `<tr><td>%s</td><td>%s %s</td></tr>`, cat, symbol, status)
		}
		b.WriteString(`</tbody></table></div>`)
	}

	// ── Timeline ──
	b.WriteString(`<div class="section" id="timeline"><h2>Timeline</h2>`)
	b.WriteString(`<ul class="scope-list">`)
	fmt.Fprintf(&b, `<li><strong>Assessment Start:</strong> %s</li>`, report.AssessmentDate.Format("02 Jan 2006 15:04 MST"))
	fmt.Fprintf(&b, `<li><strong>Assessment End:</strong> %s</li>`, report.AssessmentDate.Add(report.ScanDuration).Format("02 Jan 2006 15:04 MST"))
	fmt.Fprintf(&b, `<li><strong>Scan Duration:</strong> %s</li>`, report.ScanDuration.Round(time.Second).String())
	fmt.Fprintf(&b, `<li><strong>Report Generated:</strong> %s</li>`, report.ReportDate.Format("02 Jan 2006 15:04 MST"))
	b.WriteString(`</ul></div>`)

	// ── Disclaimer ──
	b.WriteString(`<div class="section" id="disclaimer"><h2>Disclaimer</h2>`)
	b.WriteString(`<p style="font-size:12px;color:var(--muted)">This report is provided as-is for informational purposes. The assessment was performed within the agreed scope and time frame. Results reflect the state of the target systems at the time of testing and may not represent their current security posture. This report is confidential and intended solely for the named recipient. Unauthorized distribution is prohibited. The assessor assumes no liability for damages arising from the use of this report.</p>`)
	b.WriteString(`</div>`)

	// ── Footer ──
	b.WriteString(`<div class="footer">`)
	fmt.Fprintf(&b, `<p>%s &bull; Report v%s &bull; Generated %s</p>`, esc(report.Assessor), esc(report.Version), report.ReportDate.Format("02 Jan 2006 15:04 MST"))
	b.WriteString(`<p>STRESS-STRIKE Penetration Testing Framework</p></div>`)

	b.WriteString(`</div></body></html>`)
	return []byte(b.String())
}

func writeFindingCard(b *strings.Builder, f *PentestFinding) {
	clr := severityColor(f.Severity)
	fmt.Fprintf(b, `<div class="finding-card"><div class="finding-header">`)
	fmt.Fprintf(b, `<span class="severity-badge" style="background:%s">%s</span>`, clr, strings.ToUpper(f.Severity))
	fmt.Fprintf(b, `<span class="finding-title">%s</span>`, esc(f.Title))
	fmt.Fprintf(b, `<span class="cvss-tag">CVSS %.1f</span>`, f.CVSS)
	b.WriteString(`</div><div class="finding-body">`)

	if f.CWE != "" || f.OWASPCategory != "" {
		b.WriteString(`<p>`)
		if f.CWE != "" {
			fmt.Fprintf(b, `<span class="label">CWE:</span> %s &nbsp; `, esc(f.CWE))
		}
		if f.OWASPCategory != "" {
			fmt.Fprintf(b, `<span class="label">OWASP:</span> %s`, esc(f.OWASPCategory))
		}
		b.WriteString(`</p>`)
	}

	if f.Description != "" {
		b.WriteString(`<div class="label">Description</div>`)
		fmt.Fprintf(b, `<p>%s</p>`, esc(f.Description))
	}
	if f.AffectedURL != "" {
		fmt.Fprintf(b, `<p><span class="label">Affected URL:</span> %s</p>`, esc(f.AffectedURL))
	}
	if f.Parameter != "" {
		fmt.Fprintf(b, `<p><span class="label">Parameter:</span> %s</p>`, esc(f.Parameter))
	}
	if len(f.StepsToReproduce) > 0 {
		b.WriteString(`<div class="label">Steps to Reproduce</div><ol class="steps">`)
		for _, s := range f.StepsToReproduce {
			fmt.Fprintf(b, `<li>%s</li>`, esc(s))
		}
		b.WriteString(`</ol>`)
	}
	if f.Evidence != "" {
		b.WriteString(`<div class="label">Evidence</div>`)
		fmt.Fprintf(b, `<div class="evidence-box">%s</div>`, esc(f.Evidence))
	}
	if f.Impact != "" {
		b.WriteString(`<div class="label">Impact</div>`)
		fmt.Fprintf(b, `<p>%s</p>`, esc(f.Impact))
	}
	if f.Remediation != "" {
		b.WriteString(`<div class="label">Remediation</div>`)
		fmt.Fprintf(b, `<p>%s</p>`, esc(f.Remediation))
	}
	if f.RemediationEffort != "" {
		fmt.Fprintf(b, `<p><span class="label">Effort:</span> %s</p>`, esc(f.RemediationEffort))
	}
	if len(f.References) > 0 {
		b.WriteString(`<div class="label">References</div><ul class="scope-list">`)
		for _, ref := range f.References {
			fmt.Fprintf(b, `<li>%s</li>`, esc(ref))
		}
		b.WriteString(`</ul>`)
	}

	b.WriteString(`</div></div>`)
}

func metaItem(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, `<div class="meta-item"><div class="meta-label">%s</div><div class="meta-value">%s</div></div>`, label, esc(value))
}

func statCard(b *strings.Builder, color string, value int, label string) {
	fmt.Fprintf(b, `<div class="stat-card"><div class="value" style="color:%s">%d</div><div class="label">%s</div></div>`, color, value, label)
}

// GenerateMarkdown produces a markdown pentest report.
func GenerateMarkdown(report *PentestReport) []byte {
	var b strings.Builder

	fmt.Fprintf(&b, "# %s\n\n", report.Title)
	fmt.Fprintf(&b, "**Client:** %s\n", report.ClientName)
	fmt.Fprintf(&b, "**Assessor:** %s\n", report.Assessor)
	fmt.Fprintf(&b, "**Version:** %s\n", report.Version)
	fmt.Fprintf(&b, "**Assessment Date:** %s\n", report.AssessmentDate.Format("02 Jan 2006"))
	fmt.Fprintf(&b, "**Report Date:** %s\n", report.ReportDate.Format("02 Jan 2006"))
	fmt.Fprintf(&b, "**Duration:** %s\n\n", report.ScanDuration.Round(time.Second).String())
	b.WriteString("---\n\n")

	b.WriteString("## Table of Contents\n\n")
	b.WriteString("1. [Executive Summary](#executive-summary)\n")
	b.WriteString("2. [Risk Assessment](#risk-assessment)\n")
	b.WriteString("3. [Scope](#scope)\n")
	b.WriteString("4. [Findings Summary](#findings-summary)\n")
	b.WriteString("5. [Detailed Findings](#detailed-findings)\n")
	tocN := 6
	if report.OWASPCompliance != nil && len(report.OWASPCompliance) > 0 {
		fmt.Fprintf(&b, "%d. [OWASP Compliance Matrix](#owasp-compliance)\n", tocN)
		tocN++
	}
	fmt.Fprintf(&b, "%d. [Timeline](#timeline)\n", tocN)
	tocN++
	fmt.Fprintf(&b, "%d. [Disclaimer](#disclaimer)\n\n", tocN)

	b.WriteString("---\n\n")

	b.WriteString("## Executive Summary\n\n")
	b.WriteString(report.ExecutiveSummary + "\n\n")

	b.WriteString("## Risk Assessment\n\n")
	b.WriteString(fmt.Sprintf("**Risk Rating:** %s | **Overall Score:** %d/100 | **Grade:** %s\n\n",
		strings.ToUpper(report.RiskRating), report.OverallScore, report.Grade))
	b.WriteString(fmt.Sprintf("Based on **%d** total findings across **%d** checks performed.\n\n", report.TotalFound, report.TotalChecks))

	b.WriteString("## Scope\n\n")
	if len(report.TargetURLs) > 0 {
		b.WriteString("**Target URLs:**\n")
		for _, u := range report.TargetURLs {
			fmt.Fprintf(&b, "- %s\n", u)
		}
		b.WriteString("\n")
	}
	if len(report.IPAddresses) > 0 {
		b.WriteString("**IP Addresses:**\n")
		for _, ip := range report.IPAddresses {
			fmt.Fprintf(&b, "- %s\n", ip)
		}
		b.WriteString("\n")
	}
	if len(report.Exclusions) > 0 {
		b.WriteString("**Exclusions:**\n")
		for _, ex := range report.Exclusions {
			fmt.Fprintf(&b, "- %s\n", ex)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Findings Summary\n\n")
	b.WriteString("| Severity | Count | Percentage |\n")
	b.WriteString("|----------|-------|------------|\n")
	for _, row := range []struct {
		label string
		cnt   int
	}{
		{"Critical", report.CriticalCount},
		{"High", report.HighCount},
		{"Medium", report.MediumCount},
		{"Low", report.LowCount},
		{"Info", report.InfoCount},
	} {
		pct := 0.0
		if report.TotalFound > 0 {
			pct = float64(row.cnt) / float64(report.TotalFound) * 100
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f%% |\n", row.label, row.cnt, pct)
	}
	fmt.Fprintf(&b, "| Total | %d | 100%% |\n\n", report.TotalFound)

	b.WriteString("## Detailed Findings\n\n")
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "### %d. %s\n\n", f.ID, f.Title)
		fmt.Fprintf(&b, "- **Severity:** %s | **CVSS:** %.1f\n", f.Severity, f.CVSS)
		if f.CWE != "" {
			fmt.Fprintf(&b, "- **CWE:** %s\n", f.CWE)
		}
		if f.OWASPCategory != "" {
			fmt.Fprintf(&b, "- **OWASP Category:** %s\n", f.OWASPCategory)
		}
		b.WriteString("\n")
		if f.Description != "" {
			fmt.Fprintf(&b, "**Description:** %s\n\n", f.Description)
		}
		if f.AffectedURL != "" {
			fmt.Fprintf(&b, "**Affected URL:** `%s`\n\n", f.AffectedURL)
		}
		if f.Parameter != "" {
			fmt.Fprintf(&b, "**Parameter:** `%s`\n\n", f.Parameter)
		}
		if len(f.StepsToReproduce) > 0 {
			b.WriteString("**Steps to Reproduce:**\n\n")
			for i, s := range f.StepsToReproduce {
				fmt.Fprintf(&b, "%d. %s\n", i+1, s)
			}
			b.WriteString("\n")
		}
		if f.Evidence != "" {
			b.WriteString("**Evidence:**\n\n```\n")
			b.WriteString(f.Evidence)
			b.WriteString("\n```\n\n")
		}
		if f.Impact != "" {
			fmt.Fprintf(&b, "**Impact:** %s\n\n", f.Impact)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", f.Remediation)
		}
		if f.RemediationEffort != "" {
			fmt.Fprintf(&b, "**Effort:** %s\n\n", f.RemediationEffort)
		}
		if len(f.References) > 0 {
			b.WriteString("**References:**\n\n")
			for _, ref := range f.References {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			b.WriteString("\n")
		}
		b.WriteString("---\n\n")
	}

	if report.OWASPCompliance != nil && len(report.OWASPCompliance) > 0 {
		b.WriteString("## OWASP Top 10 (2021) Compliance Matrix\n\n")
		b.WriteString("| Category | Status |\n")
		b.WriteString("|----------|--------|\n")
		for _, cat := range owaspOrder() {
			status := "PASS"
			if !report.OWASPCompliance[cat] {
				status = "FAIL"
			}
			fmt.Fprintf(&b, "| %s | %s |\n", cat, status)
		}
		b.WriteString("\n")
	}

	b.WriteString("## Timeline\n\n")
	fmt.Fprintf(&b, "- **Assessment Start:** %s\n", report.AssessmentDate.Format("02 Jan 2006 15:04 MST"))
	fmt.Fprintf(&b, "- **Assessment End:** %s\n", report.AssessmentDate.Add(report.ScanDuration).Format("02 Jan 2006 15:04 MST"))
	fmt.Fprintf(&b, "- **Scan Duration:** %s\n", report.ScanDuration.Round(time.Second).String())
	fmt.Fprintf(&b, "- **Report Generated:** %s\n\n", report.ReportDate.Format("02 Jan 2006 15:04 MST"))

	b.WriteString("## Disclaimer\n\n")
	b.WriteString("This report is provided as-is for informational purposes. The assessment was performed within the agreed scope and time frame. Results reflect the state of the target systems at the time of testing and may not represent their current security posture. This report is confidential and intended solely for the named recipient. Unauthorized distribution is prohibited.\n\n")

	fmt.Fprintf(&b, "---\n*Generated by STRESS-STRIKE v%s on %s*\n", report.Version, report.ReportDate.Format("02 Jan 2006 15:04 MST"))

	return []byte(b.String())
}

// SaveReport writes the report to disk in the specified format ("html", "md", or "pdf").
func SaveReport(report *PentestReport, format, filename string) error {
	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	var data []byte
	switch strings.ToLower(format) {
	case "html", "htm":
		data = GenerateHTML(report)
	case "pdf":
		data = GeneratePDF(report)
	case "md", "markdown":
		data = GenerateMarkdown(report)
	default:
		return fmt.Errorf("unsupported report format: %s", format)
	}

	return os.WriteFile(filename, data, 0o600)
}

func esc(s string) string {
	return html.EscapeString(s)
}
