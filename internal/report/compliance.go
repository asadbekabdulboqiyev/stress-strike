package report

import (
	"fmt"
	"math"
	"strings"
)

// ComplianceFramework identifies a supported compliance standard.
type ComplianceFramework string

const (
	CompPCI  ComplianceFramework = "PCI DSS v4.0"
	CompSOC2 ComplianceFramework = "SOC 2"
	CompISO  ComplianceFramework = "ISO 27001:2022"
)

// Control status values emitted by AssessCompliance.
const (
	CompStatusPass      = "PASS"
	CompStatusFail      = "FAIL"
	CompStatusAttention = "ATTENTION"
)

// ControlResult captures how a single control was evidenced.
type ControlResult struct {
	ID          string   // "PCI-6.2.4", "SOC2-CC7.1", "ISO-A.8.8"
	Title       string   // human readable control name
	Status      string   // "PASS" | "FAIL" | "ATTENTION"
	Findings    []string // titles of findings triggering it
	Requirement string   // what the control demands (1 line)
}

// ComplianceResult summarizes one framework assessment.
type ComplianceResult struct {
	Framework string
	Controls  []ControlResult
	Pass      int
	Fail      int
	Attention int
	Score     int // % pass of applicable controls
}

// SupportedFrameworks returns every framework this module can assess.
func SupportedFrameworks() []ComplianceFramework {
	return []ComplianceFramework{CompPCI, CompSOC2, CompISO}
}

// compControlDef is the internal mapping definition for one control.
type compControlDef struct {
	ID          string
	Title       string
	Requirement string
	CWEs        []string // findings carrying these CWEs trigger FAIL
	Keywords    []string // substring hits on title+description trigger FAIL
	OWASPCats   []string // a failing OWASP category triggers FAIL
	Evidence    bool     // scanner-evidence control: ATTENTION when findings exist
}

const (
	owaspCatInjection = "A03:2021 - Injection"
	owaspCatCrypto    = "A02:2021 - Cryptographic Failures"
	owaspCatAccess    = "A01:2021 - Broken Access Control"
	owaspCatAuthN     = "A07:2021 - Identification and Authentication Failures"
	owaspCatMisconfig = "A05:2021 - Security Misconfiguration"
	owaspCatOutdated  = "A06:2021 - Vulnerable and Outdated Components"
)

var compFrameworkDefs = map[ComplianceFramework][]compControlDef{
	CompPCI: {
		{
			ID:          "PCI-6.2.4",
			Title:       "Secure Development and Vulnerability Remediation",
			Requirement: "Custom and third-party software is developed securely and known vulnerabilities are corrected before production deployment.",
			CWEs:        []string{"CWE-79", "CWE-89", "CWE-94", "CWE-78", "CWE-434"},
			OWASPCats:   []string{owaspCatInjection},
		},
		{
			ID:          "PCI-4.2.1",
			Title:       "Strong Cryptography for Cardholder Data in Transit",
			Requirement: "Strong cryptography and security protocols protect cardholder data during transmission over open, public networks.",
			CWEs:        []string{"CWE-326", "CWE-327", "CWE-759", "CWE-760"},
			OWASPCats:   []string{owaspCatCrypto},
		},
		{
			ID:          "PCI-2.2.2",
			Title:       "Insecure Default Settings Removed",
			Requirement: "Vendor defaults and other insecure default settings are changed or removed before a system component is deployed.",
			CWEs:        []string{"CWE-798", "CWE-255", "CWE-1188"},
			Keywords:    []string{"default credential", "default password"},
		},
		{
			ID:          "PCI-6.4.3",
			Title:       "Public-Facing Page Script Protection",
			Requirement: "Script content loaded to public-facing pages is managed and authorized, with browser-side protections such as CSP and security headers enabled.",
			CWEs:        []string{"CWE-693", "CWE-1021"},
		},
		{
			ID:          "PCI-8.2.8",
			Title:       "Session Identification and Termination",
			Requirement: "User sessions are uniquely identified, protected against fixation and terminated after a defined period of inactivity.",
			CWEs:        []string{"CWE-287", "CWE-384", "CWE-613", "CWE-614"},
			OWASPCats:   []string{owaspCatAuthN},
		},
		{
			ID:          "PCI-10.2.1",
			Title:       "Audit Log Coverage",
			Requirement: "Audit logs capture all access to system components and critical security events cannot be silently dropped.",
			CWEs:        []string{"CWE-778"},
		},
		{
			ID:          "PCI-11.3.1",
			Title:       "External Vulnerability Scanning Evidence",
			Requirement: "External vulnerability scans are performed at least quarterly and after significant changes; this assessment provides scanning evidence requiring follow-up.",
			Evidence:    true,
		},
		{
			ID:          "PCI-1.3.1",
			Title:       "Network Exposure Restriction",
			Requirement: "Network security controls restrict inbound traffic to trusted networks and only necessary services and protocols are exposed.",
			CWEs:        []string{"CWE-16"},
			Keywords:    []string{"exposed service", "open port"},
		},
	},
	CompSOC2: {
		{
			ID:          "SOC2-CC6.1",
			Title:       "Logical Access Security",
			Requirement: "Logical access to information assets is granted based on role, least privilege and authenticated identity.",
			CWEs:        []string{"CWE-287", "CWE-798", "CWE-255", "CWE-306", "CWE-862"},
			OWASPCats:   []string{owaspCatAuthN, owaspCatAccess},
		},
		{
			ID:          "SOC2-CC6.6",
			Title:       "Boundary Protection Against External Threats",
			Requirement: "Boundary defenses such as firewalls, transport encryption and hardened configurations restrict external access to system resources.",
			CWEs:        []string{"CWE-16", "CWE-693", "CWE-326", "CWE-327"},
			OWASPCats:   []string{owaspCatMisconfig, owaspCatCrypto},
		},
		{
			ID:          "SOC2-CC6.7",
			Title:       "Data in Transit Protection",
			Requirement: "Confidential and personal information is encrypted end to end whenever transmitted or moved between systems.",
			CWEs:        []string{"CWE-311", "CWE-319", "CWE-614"},
			OWASPCats:   []string{owaspCatCrypto},
		},
		{
			ID:          "SOC2-CC7.1",
			Title:       "Vulnerability Detection and Configuration Monitoring",
			Requirement: "Security configurations are continuously evaluated and vulnerabilities are detected and remediated across the environment.",
			CWEs:        []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-434"},
			OWASPCats:   []string{owaspCatInjection},
		},
		{
			ID:          "SOC2-CC7.2",
			Title:       "Anomaly Monitoring and Disclosure Control",
			Requirement: "Anomalous activity is monitored and sensitive system information is not disclosed to unauthorized parties.",
			CWEs:        []string{"CWE-200", "CWE-540"},
		},
		{
			ID:          "SOC2-CC8.1",
			Title:       "Change and Component Lifecycle Management",
			Requirement: "Changes to system components are authorized, tested and approved; unsupported or outdated components are removed.",
			CWEs:        []string{"CWE-1104"},
			Keywords:    []string{"cve-", "outdated", "unpatched"},
			OWASPCats:   []string{owaspCatOutdated},
		},
		{
			ID:          "SOC2-CC9.1",
			Title:       "Risk Mitigation",
			Requirement: "Risks threatening the achievement of objectives, including security misconfigurations, are identified, assessed and mitigated.",
			CWEs:        []string{"CWE-16"},
			OWASPCats:   []string{owaspCatMisconfig},
		},
	},
	CompISO: {
		{
			ID:          "ISO-A.8.8",
			Title:       "Management of Technical Vulnerabilities",
			Requirement: "Technical vulnerabilities are identified, evaluated and remediated according to their risk exposure.",
			CWEs:        []string{"CWE-1104"},
			Keywords:    []string{"cve-", "outdated", "unpatched", "unsupported"},
			OWASPCats:   []string{owaspCatOutdated},
		},
		{
			ID:          "ISO-A.8.9",
			Title:       "Configuration Management",
			Requirement: "Configurations of hardware, software and services are documented, implemented, monitored and enforced.",
			CWEs:        []string{"CWE-15", "CWE-16", "CWE-1004"},
			OWASPCats:   []string{owaspCatMisconfig},
		},
		{
			ID:          "ISO-A.8.24",
			Title:       "Use of Cryptography",
			Requirement: "Rules for the effective use of cryptography, including key management, are defined and applied.",
			CWEs:        []string{"CWE-321", "CWE-322", "CWE-326", "CWE-327", "CWE-759", "CWE-760"},
			OWASPCats:   []string{owaspCatCrypto},
		},
		{
			ID:          "ISO-A.8.26",
			Title:       "Application Security Requirements",
			Requirement: "Secure coding principles are applied and application security requirements are verified throughout development.",
			CWEs:        []string{"CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-434"},
			OWASPCats:   []string{owaspCatInjection},
		},
		{
			ID:          "ISO-A.5.15",
			Title:       "Access Control Rules",
			Requirement: "Rules governing physical and logical access to information assets are established, documented and enforced.",
			CWEs:        []string{"CWE-284", "CWE-285", "CWE-287", "CWE-306", "CWE-862", "CWE-863"},
			OWASPCats:   []string{owaspCatAccess, owaspCatAuthN},
		},
		{
			ID:          "ISO-A.8.12",
			Title:       "Data Leakage Prevention",
			Requirement: "Data leakage prevention measures are applied to systems and channels processing sensitive information.",
			CWEs:        []string{"CWE-200", "CWE-359", "CWE-538", "CWE-540"},
		},
		{
			ID:          "ISO-A.8.13",
			Title:       "Information Backup",
			Requirement: "Backup copies of information and software are maintained, protected and regularly tested (requires manual verification).",
		},
	},
}

func normCWE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// owaspCategoryFailed reports whether any of the given OWASP categories is
// explicitly marked as failed in the compliance map.
func owaspCategoryFailed(cats []string, owasp map[string]bool) bool {
	for _, cat := range cats {
		if v, present := owasp[cat]; present && !v {
			return true
		}
	}
	return false
}

// AssessCompliance maps pentest findings onto a framework's controls.
//
// Rule set:
//   - a finding whose CWE (or keyword) matches a control -> FAIL, listing titles
//   - a failing OWASP category mapped to the control      -> FAIL
//   - scanner-evidence controls (e.g. PCI 11.3.1)         -> ATTENTION when any
//     finding exists, otherwise PASS
//   - no related findings                                 -> PASS
//
// Score is the percentage of applicable controls that PASS, rounded.
func AssessCompliance(framework ComplianceFramework, findings []PentestFinding, owasp map[string]bool) *ComplianceResult {
	defs, ok := compFrameworkDefs[framework]
	if !ok || len(defs) == 0 {
		return nil
	}

	res := &ComplianceResult{Framework: string(framework)}

	lowered := make([]string, len(findings))
	for i := range findings {
		lowered[i] = strings.ToLower(findings[i].Title + " " + findings[i].Description)
	}

	for _, def := range defs {
		ctl := ControlResult{
			ID:          def.ID,
			Title:       def.Title,
			Requirement: def.Requirement,
		}

		if def.Evidence {
			if len(findings) > 0 {
				ctl.Status = CompStatusAttention
				for i := range findings {
					ctl.Findings = append(ctl.Findings, findings[i].Title)
				}
			} else {
				ctl.Status = CompStatusPass
			}
		} else {
			cweSet := make(map[string]struct{}, len(def.CWEs))
			for _, c := range def.CWEs {
				cweSet[normCWE(c)] = struct{}{}
			}
			for i := range findings {
				f := &findings[i]
				hit := false
				if _, hit = cweSet[normCWE(f.CWE)]; !hit {
					for _, kw := range def.Keywords {
						if strings.Contains(lowered[i], kw) {
							hit = true
							break
						}
					}
				}
				if hit {
					ctl.Findings = append(ctl.Findings, f.Title)
				}
			}
			if len(ctl.Findings) > 0 || owaspCategoryFailed(def.OWASPCats, owasp) {
				ctl.Status = CompStatusFail
			} else {
				ctl.Status = CompStatusPass
			}
		}

		switch ctl.Status {
		case CompStatusFail:
			res.Fail++
		case CompStatusAttention:
			res.Attention++
		default:
			res.Pass++
		}
		res.Controls = append(res.Controls, ctl)
	}

	if total := len(res.Controls); total > 0 {
		res.Score = int(math.Round(float64(res.Pass) / float64(total) * 100.0))
	}
	return res
}

// ─── Rendering ──────────────────────────────────────────────────────────────

func compScoreColor(score int) string {
	switch {
	case score >= 90:
		return "#28a745"
	case score >= 70:
		return "#ffc107"
	default:
		return "#dc3545"
	}
}

var compAmberRGB = pdfHexToRGB("#ffc107")

func compSlug(fw string) string {
	var b strings.Builder
	b.Grow(len(fw) + 4)
	for _, r := range fw {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func compCell(s string) string {
	return strings.ReplaceAll(s, "|", "/")
}

// complianceHTML renders the Compliance Impact section into an HTML report.
func complianceHTML(b *strings.Builder, results []ComplianceResult) {
	b.WriteString(`<div class="section" id="compliance-impact"><h2>Compliance Impact</h2>`)
	for _, res := range results {
		fmt.Fprintf(b, `<div id="compliance-%s"><h3>%s <span class="severity-badge" style="background:%s">Score %d%%</span></h3>`,
			compSlug(res.Framework), esc(res.Framework), compScoreColor(res.Score), res.Score)
		fmt.Fprintf(b, `<p style="font-size:12px;color:var(--muted);margin-bottom:12px">%d PASS / %d FAIL / %d ATTENTION across %d applicable controls.</p>`,
			res.Pass, res.Fail, res.Attention, len(res.Controls))
		b.WriteString(`<table class="owasp-table"><thead><tr><th>Control</th><th>Requirement</th><th>Status</th><th>Related Findings</th></tr></thead><tbody>`)
		for _, ctl := range res.Controls {
			var symbol string
			switch ctl.Status {
			case CompStatusFail:
				symbol = `<span class="cross">&#10007; FAIL</span>`
			case CompStatusAttention:
				symbol = `<span style="color:#ffc107;font-weight:700">&#9888; ATTENTION</span>`
			default:
				symbol = `<span class="check">&#10003; PASS</span>`
			}
			fmt.Fprintf(b, `<tr><td><strong>%s</strong><br><span style="color:var(--muted);font-size:12px">%s</span></td><td>%s</td><td>%s</td><td>%d</td></tr>`,
				esc(ctl.ID), esc(ctl.Title), esc(ctl.Requirement), symbol, len(ctl.Findings))
		}
		b.WriteString(`</tbody></table></div>`)
	}
	b.WriteString(`</div>`)
}

// complianceMarkdown renders the Compliance Impact section into a Markdown report.
func complianceMarkdown(b *strings.Builder, results []ComplianceResult) {
	b.WriteString("## Compliance Impact\n\n")
	for _, res := range results {
		fmt.Fprintf(b, "### %s\n\n", res.Framework)
		fmt.Fprintf(b, "**Score:** %d%% | **PASS:** %d | **FAIL:** %d | **ATTENTION:** %d | **Applicable controls:** %d\n\n",
			res.Score, res.Pass, res.Fail, res.Attention, len(res.Controls))
		b.WriteString("| Control | Requirement | Status | Related Findings |\n")
		b.WriteString("|---------|-------------|--------|------------------|\n")
		for _, ctl := range res.Controls {
			fmt.Fprintf(b, "| %s %s | %s | %s | %d |\n",
				compCell(ctl.ID), compCell(ctl.Title), compCell(ctl.Requirement),
				compCell(ctl.Status), len(ctl.Findings))
		}
		b.WriteString("\n")
	}
}

// pdfCompliance renders the Compliance Impact section using the pure-Go PDF engine.
func pdfCompliance(d *pdfDoc, results []ComplianceResult) {
	d.heading("Compliance Impact")
	for _, res := range results {
		d.need(84)
		d.y -= 4
		d.text(pdfMarginL, d.y, fontBold, 11, pdfColNavy, pdfClean(res.Framework))
		d.y -= 14
		d.kvWrap("Score", fmt.Sprintf("%d%% (%d PASS / %d FAIL / %d ATTENTION of %d applicable controls)",
			res.Score, res.Pass, res.Fail, res.Attention, len(res.Controls)), 9, 0)
		d.y -= 4

		for _, ctl := range res.Controls {
			idTitle := pdfClean(ctl.ID + "  " + ctl.Title)
			tlines := pdfWrap(idTitle, fontBold, 8.5, pdfContentW-64)
			reqLines := pdfWrap(pdfClean(ctl.Requirement), fontReg, 8, pdfContentW-28)

			extra := 4.0
			if len(ctl.Findings) > 0 {
				extra += 10
			}
			d.need(float64(len(tlines))*12 + float64(len(reqLines))*10 + extra)

			statusColor := pdfColOKGreen
			switch ctl.Status {
			case CompStatusFail:
				statusColor = pdfColBadRed
			case CompStatusAttention:
				statusColor = compAmberRGB
			}

			for k, ln := range tlines {
				d.text(pdfMarginL, d.y, fontBold, 8.5, pdfColDark, ln)
				if k == 0 {
					sw := pdfTextWidth(ctl.Status, fontBold, 8)
					d.text(pdfPageW-pdfMarginR-sw, d.y, fontBold, 8, statusColor, ctl.Status)
				}
				d.y -= 12
			}
			for _, ln := range reqLines {
				d.text(pdfMarginL+14, d.y, fontReg, 8, pdfColMuted, ln)
				d.y -= 10
			}
			if n := len(ctl.Findings); n > 0 {
				d.text(pdfMarginL+14, d.y, fontReg, 7.5, pdfColLabel, fmt.Sprintf("Related findings: %d", n))
				d.y -= 10
			}
			d.y -= 4
		}
		d.y -= 6
	}
}
