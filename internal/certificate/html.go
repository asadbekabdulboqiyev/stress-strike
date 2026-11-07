package certificate

import (
	"fmt"
	"html"
	"strings"
)

// RenderHTML renders the certificate as a self-contained, printable English
// page. signature/publicKey/signedAt/version are inserted into the signature
// seal. The seal block is excluded from the cryptographic boundary (see
// stripSeal), so any values may be rendered here without affecting the bound
// document hash.
func RenderHTML(a Assessment, signature, publicKey, signedAt, version string) string {
	var rows strings.Builder
	for _, f := range a.Findings {
		rows.WriteString(fmt.Sprintf(
			"\t\t<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(f.Severity), html.EscapeString(f.Title),
			html.EscapeString(f.Evidence), html.EscapeString(f.ID),
		))
	}
	if rows.Len() == 0 {
		rows.WriteString("\t\t<tr><td colspan=\"4\">No defects found.</td></tr>\n")
	}

	var comps strings.Builder
	for _, ctl := range a.Compliance {
		comps.WriteString(fmt.Sprintf(
			"\t\t<tr><td>%s</td><td>%s %s</td><td>%s</td></tr>\n",
			html.EscapeString(ctl.Framework), html.EscapeString(ctl.ID),
			html.EscapeString(ctl.Title), html.EscapeString(ctl.Status),
		))
	}
	if comps.Len() == 0 {
		comps.WriteString("\t\t<tr><td colspan=\"3\">No compliance controls mapped.</td></tr>\n")
	}

	covered := make([]string, 0, len(a.Covered))
	for _, x := range a.Covered {
		covered = append(covered, html.EscapeString(x))
	}

	total := a.Counts.Critical + a.Counts.High + a.Counts.Medium + a.Counts.Low + a.Counts.Info

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>stress-strike — Security Assessment Certificate</title>
<style>
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; color: #1f2937; line-height: 1.5; padding: 32px; max-width: 860px; margin: auto; background: #fafafa; }
  .cert { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 36px; box-shadow: 0 4px 12px rgba(0,0,0,0.06); }
  .header { border-bottom: 3px solid #111827; padding-bottom: 16px; margin-bottom: 24px; }
  .header h1 { margin: 0; font-size: 22px; letter-spacing: 0.04em; text-transform: uppercase; }
  .header .sub { color: #6b7280; font-size: 13px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
  .card { background: #f3f4f6; border-radius: 8px; padding: 14px; text-align: center; }
  .card .v { font-size: 20px; font-weight: 700; color: #111827; }
  .card .l { font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }
  h2 { font-size: 14px; text-transform: uppercase; letter-spacing: 0.08em; color: #6b7280; margin: 24px 0 8px; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e5e7eb; font-size: 13px; }
  th { background: #f9fafb; font-weight: 700; color: #374151; font-size: 11px; text-transform: uppercase; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 700; text-transform: uppercase; }
  .b-critical { background: #fee2e2; color: #991b1b; }
  .b-high { background: #fecaca; color: #991b1b; }
  .b-medium { background: #fef3c7; color: #92400e; }
  .b-low { background: #d1fae5; color: #065f46; }
  .b-info { background: #dbeafe; color: #1e40af; }
  .seal { margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 16px; font-size: 12px; color: #6b7280; }
  .seal pre { background: #f3f4f6; padding: 10px; border-radius: 6px; font-size: 10px; word-break: break-all; overflow-wrap: break-word; }
  .verdict { font-size: 15px; font-weight: 700; margin-top: 10px; }
  .v-pass { color: #065f46; } .v-fail { color: #991b1b; } .v-warn { color: #92400e; }
</style>
</head>
<body>
<div class="cert">
  <div class="header">
    <h1>stress-strike Security Assessment Certificate</h1>
    <div class="sub">Format: ss-cert/v1 &bull; Ed25519-signed &bull; verifies offline with ` + "stress-strike certificate --verify" + `</div>
  </div>

  <div class="grid">
    <div class="card"><div class="v">` + html.EscapeString(a.Grade) + `</div><div class="l">Grade</div></div>
    <div class="card"><div class="v verdict v-` + strings.ToLower(a.Verdict) + `">` + html.EscapeString(a.Verdict) + `</div><div class="l">Verdict</div></div>
    <div class="card"><div class="v">` + fmt.Sprintf("%d", a.RiskScore) + `/100</div><div class="l">Risk score</div></div>
    <div class="card"><div class="v">` + fmt.Sprintf("%d", total) + `</div><div class="l">Findings</div></div>
    <div class="card"><div class="v">` + fmt.Sprintf("%d/%d", a.OWASPPass, 10) + `</div><div class="l">OWASP Top 10 pass</div></div>
  </div>

  <h2>Assessment</h2>
  <table>
    <tr><td style="width:30%"><b>Target</b></td><td>` + html.EscapeString(a.Target) + `</td></tr>
    <tr><td><b>Scope</b></td><td>` + html.EscapeString(a.Scope) + `</td></tr>
    <tr><td><b>Started</b></td><td>` + html.EscapeString(a.Started) + ` UTC</td></tr>
    <tr><td><b>Ended</b></td><td>` + html.EscapeString(a.Ended) + ` UTC</td></tr>
    <tr><td><b>Duration</b></td><td>` + html.EscapeString(a.Duration) + `</td></tr>
    <tr><td><b>Issuer</b></td><td>` + html.EscapeString(a.Issuer) + `</td></tr>
    <tr><td><b>Issued</b></td><td>` + html.EscapeString(a.SignedAt) + ` UTC</td></tr>
    <tr><td><b>Tool</b></td><td>` + html.EscapeString(a.Tool) + ` ` + html.EscapeString(a.ToolVersion) + `</td></tr>
    <tr><td><b>Scanner families</b></td><td>` + strings.Join(covered, ", ") + `</td></tr>
  </table>

  <h2>Severity counts</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr><td><span class="badge b-critical">critical</span></td><td>` + fmt.Sprintf("%d", a.Counts.Critical) + `</td></tr>
    <tr><td><span class="badge b-high">high</span></td><td>` + fmt.Sprintf("%d", a.Counts.High) + `</td></tr>
    <tr><td><span class="badge b-medium">medium</span></td><td>` + fmt.Sprintf("%d", a.Counts.Medium) + `</td></tr>
    <tr><td><span class="badge b-low">low</span></td><td>` + fmt.Sprintf("%d", a.Counts.Low) + `</td></tr>
    <tr><td><span class="badge b-info">info</span></td><td>` + fmt.Sprintf("%d", a.Counts.Info) + `</td></tr>
  </table>

  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Evidence</th><th>ID</th></tr>
` + rows.String() + `  </table>

  <h2>Compliance mapping</h2>
  <table>
    <tr><th>Framework</th><th>Control</th><th>Status</th></tr>
` + comps.String() + `  </table>

  <div class="seal">
    <div><b>Ed25519 signature (over canonical assessment JSON):</b></div>
    <pre>` + html.EscapeString(signature) + `</pre>
    <div><b>Signer public key:</b></div>
    <pre>` + html.EscapeString(publicKey) + `</pre>
    <div><b>Signed at:</b> ` + html.EscapeString(signedAt) + ` UTC &nbsp;&bull;&nbsp; <b>Format:</b> ` + html.EscapeString(version) + `</div>
    <div style="margin-top:10px">Verify: ` + "stress-strike certificate --verify cert.json" + ` &mdash; valid only if the signature matches the assessment and public key.</div>
  </div>
</div>
</body>
</html>`
}

// HTML renders the full certificate page from a sealed Certificate, including
// its signature seal. It is the display form; the cryptographic boundary is
// the Assessment.DocumentSHA over the seal-excluded body.
func HTML(c *Certificate) string {
	return RenderHTML(c.Assessment, c.Signature, c.PublicKey, c.SignedAt, c.Version)
}
