package report

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// Page geometry: US Letter, points.
const (
	pdfPageW     = 612.0
	pdfPageH     = 792.0
	pdfMarginL   = 56.0
	pdfMarginR   = 56.0
	pdfMarginTop = 756.0
	pdfMarginBot = 64.0
	pdfContentW  = pdfPageW - pdfMarginL - pdfMarginR
)

type pdfFont int

const (
	fontReg pdfFont = iota
	fontBold
	fontMono
)

func (f pdfFont) ref() string {
	switch f {
	case fontBold:
		return "/F2"
	case fontMono:
		return "/F3"
	default:
		return "/F1"
	}
}

func (f pdfFont) baseName() string {
	switch f {
	case fontBold:
		return "Helvetica-Bold"
	case fontMono:
		return "Courier"
	default:
		return "Helvetica"
	}
}

// Standard AFM widths (per 1000 units) for ASCII 32..126.
var pdfWidthsHelv = [95]int{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

var pdfWidthsHelvBold = [95]int{
	278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
	975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
	333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
	611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
}

func pdfTextWidth(s string, f pdfFont, size float64) float64 {
	if f == fontMono {
		return float64(len(s)) * 600.0 * size / 1000.0
	}
	w := &pdfWidthsHelv
	if f == fontBold {
		w = &pdfWidthsHelvBold
	}
	sum := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 32 && c <= 126 {
			sum += w[c-32]
		}
	}
	return float64(sum) * size / 1000.0
}

var pdfSanitizer = strings.NewReplacer(
	"\u2018", "'", "\u2019", "'", "\u201A", "'", "\u201B", "'",
	"\u201C", "\"", "\u201D", "\"", "\u201E", "\"",
	"\u2013", "-", "\u2014", "-", "\u2212", "-", "\u2010", "-",
	"\u2022", "*", "\u2026", "...", "\u00A0", " ",
	"\t", " ", "\r", "",
)

func pdfClean(s string) string {
	s = pdfSanitizer.Replace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func pdfEscapeStr(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' || c == '(' || c == ')' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

type pdfRGB struct{ r, g, b float64 }

func pdfHexToRGB(hex string) pdfRGB {
	hex = strings.TrimPrefix(strings.TrimSpace(hex), "#")
	if len(hex) != 6 {
		return pdfRGB{0, 0, 0}
	}
	v, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return pdfRGB{0, 0, 0}
	}
	return pdfRGB{
		float64((v>>16)&0xff) / 255.0,
		float64((v>>8)&0xff) / 255.0,
		float64(v&0xff) / 255.0,
	}
}

var (
	pdfColWhite   = pdfRGB{1, 1, 1}
	pdfColDark    = pdfHexToRGB("#212529")
	pdfColMuted   = pdfHexToRGB("#6c757d")
	pdfColLabel   = pdfHexToRGB("#495057")
	pdfColBorder  = pdfHexToRGB("#dee2e6")
	pdfColNavy    = pdfHexToRGB("#131b2c")
	pdfColSubtle  = pdfRGB{0.62, 0.68, 0.78}
	pdfColCodeBG  = pdfHexToRGB("#f1f3f5")
	pdfColCode    = pdfHexToRGB("#1a1a2e")
	pdfColConfRed = pdfHexToRGB("#dc3545")

	pdfColOKGreen = pdfHexToRGB("#28a745")
	pdfColBadRed  = pdfHexToRGB("#dc3545")
)

func pdfSevRGB(sev string) pdfRGB { return pdfHexToRGB(severityColor(sev)) }

// wrapASCII word-wraps pre-sanitized ASCII text; hard-splits oversized words.
func pdfWrap(s string, f pdfFont, size, maxW float64) []string {
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		cur := ""
		for _, w := range words {
			cand := w
			if cur != "" {
				cand = cur + " " + w
			}
			if pdfTextWidth(cand, f, size) <= maxW {
				cur = cand
				continue
			}
			if cur != "" {
				lines = append(lines, cur)
				cur = ""
			}
			for pdfTextWidth(w, f, size) > maxW && len(w) > 1 {
				lo, hi := 1, len(w)
				for lo < hi {
					mid := (lo + hi + 1) / 2
					if pdfTextWidth(w[:mid], f, size) <= maxW {
						lo = mid
					} else {
						hi = mid - 1
					}
				}
				if lo < 1 {
					lo = 1
				}
				lines = append(lines, w[:lo])
				w = w[lo:]
			}
			cur = w
		}
		lines = append(lines, cur)
	}
	return lines
}

type pdfDoc struct {
	pages [][]byte
	cur   bytes.Buffer
	y     float64
}

func newPDFDoc() *pdfDoc { return &pdfDoc{y: pdfMarginTop} }

func pdfEmitText(buf *bytes.Buffer, x, y float64, f pdfFont, size float64, c pdfRGB, s string) {
	fmt.Fprintf(buf, "BT %s %.2f Tf %.4f %.4f %.4f rg 1 0 0 1 %.2f %.2f Tm (%s) Tj ET\n",
		f.ref(), size, c.r, c.g, c.b, x, y, pdfEscapeStr(s))
}

func pdfEmitRect(buf *bytes.Buffer, x, y, w, h float64, c pdfRGB) {
	fmt.Fprintf(buf, "q %.4f %.4f %.4f rg %.2f %.2f %.2f %.2f re f Q\n", c.r, c.g, c.b, x, y, w, h)
}

func pdfEmitHLine(buf *bytes.Buffer, y float64, c pdfRGB, wd float64) {
	fmt.Fprintf(buf, "q %.4f %.4f %.4f RG %.2f w %.2f %.2f m %.2f %.2f l S Q\n",
		c.r, c.g, c.b, wd, pdfMarginL, y, pdfPageW-pdfMarginR, y)
}

func (d *pdfDoc) flushPage() {
	if d.cur.Len() > 0 {
		buf := make([]byte, d.cur.Len())
		copy(buf, d.cur.Bytes())
		d.pages = append(d.pages, buf)
		d.cur.Reset()
	}
	d.y = pdfMarginTop
}

func (d *pdfDoc) need(h float64) {
	if d.y-h < pdfMarginBot {
		d.flushPage()
	}
}

func (d *pdfDoc) text(x, y float64, f pdfFont, size float64, c pdfRGB, s string) {
	pdfEmitText(&d.cur, x, y, f, size, c, s)
}

func (d *pdfDoc) para(s string, f pdfFont, size float64, c pdfRGB, indent float64) {
	lh := size * 1.42
	for _, ln := range pdfWrap(pdfClean(s), f, size, pdfContentW-indent) {
		d.need(lh)
		d.text(pdfMarginL+indent, d.y, f, size, c, ln)
		d.y -= lh
	}
}

func (d *pdfDoc) heading(title string) {
	d.need(46)
	d.y -= 10
	d.text(pdfMarginL, d.y, fontBold, 14, pdfColNavy, title)
	d.y -= 9
	pdfEmitHLine(&d.cur, d.y, pdfColBorder, 0.8)
	d.y -= 17
}

func (d *pdfDoc) fieldLabel(label string) {
	d.need(26)
	d.text(pdfMarginL, d.y, fontBold, 7.8, pdfColLabel, strings.ToUpper(pdfClean(label)))
	d.y -= 12
}

func (d *pdfDoc) field(label, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	d.fieldLabel(label)
	d.para(body, fontReg, 9.5, pdfColDark, 0)
	d.y -= 3
}

func (d *pdfDoc) fieldMono(label, body string) {
	if strings.TrimSpace(body) == "" {
		return
	}
	d.fieldLabel(label)
	d.para(body, fontMono, 8.5, pdfColDark, 0)
	d.y -= 3
}

// kvWrap draws "label:" bold followed by a wrapped value.
func (d *pdfDoc) kvWrap(label, value string, size float64, indent float64) {
	lbl := pdfClean(label) + ": "
	lw := pdfTextWidth(lbl, fontBold, size)
	firstW := pdfContentW - indent - lw - 2
	lines := pdfWrap(pdfClean(value), fontReg, size, firstW)
	lh := size * 1.5
	d.need(lh)
	d.text(pdfMarginL+indent, d.y, fontBold, size, pdfColLabel, lbl)
	if len(lines) > 0 {
		d.text(pdfMarginL+indent+lw+2, d.y, fontReg, size, pdfColDark, lines[0])
	}
	d.y -= lh
	for _, ln := range lines[1:] {
		d.need(lh)
		d.text(pdfMarginL+indent, d.y, fontReg, size, pdfColDark, ln)
		d.y -= lh
	}
}

func (d *pdfDoc) badge(text string, c pdfRGB, size float64) {
	w := pdfTextWidth(text, fontBold, size) + 16
	h := size + 10
	d.need(h + 10)
	pdfEmitRect(&d.cur, pdfMarginL, d.y-h+3, w, h, c)
	d.text(pdfMarginL+8, d.y-h+3+(h-size)/2+1, fontBold, size, pdfColWhite, text)
	d.y -= h + 10
}

func (d *pdfDoc) centerText(s string, f pdfFont, size float64, c pdfRGB) {
	d.need(size * 1.8)
	x := pdfMarginL + (pdfContentW-pdfTextWidth(s, f, size))/2
	d.text(x, d.y, f, size, c, s)
	d.y -= size * 1.8
}

type pdfStat struct {
	label string
	count int
	color string
}

func (d *pdfDoc) statGrid(items []pdfStat) {
	n := float64(len(items))
	gap := 8.0
	bw := (pdfContentW - gap*(n-1)) / n
	d.need(56)
	x := pdfMarginL
	for _, it := range items {
		c := pdfHexToRGB(it.color)
		pdfEmitRect(&d.cur, x, d.y-36, bw, 36, pdfColCodeBG)
		pdfEmitRect(&d.cur, x, d.y-5, bw, 3, c)
		num := strconv.Itoa(it.count)
		d.text(x+(bw-pdfTextWidth(num, fontBold, 15))/2, d.y-24, fontBold, 15, c, num)
		lbl := strings.ToUpper(pdfClean(it.label))
		d.text(x+(bw-pdfTextWidth(lbl, fontReg, 6.8))/2, d.y-32.5, fontReg, 6.8, pdfColMuted, lbl)
		x += bw + gap
	}
	d.y -= 50
}

func (d *pdfDoc) evidenceBlock(ev string) {
	const size, lh = 8.0, 11.0
	maxw := pdfContentW - 14
	for _, ln := range pdfWrap(pdfClean(ev), fontMono, size, maxw) {
		d.need(lh)
		pdfEmitRect(&d.cur, pdfMarginL-4, d.y-lh+3.5, pdfContentW+8, lh, pdfColCodeBG)
		d.text(pdfMarginL+3, d.y, fontMono, size, pdfColCode, ln)
		d.y -= lh
	}
	d.y -= 4
}

func (d *pdfDoc) finding(n int, f *PentestFinding) {
	d.y -= 4
	d.need(84)

	title := fmt.Sprintf("%d. %s", n, pdfClean(f.Title))
	tlh := 15.0
	for _, ln := range pdfWrap(title, fontBold, 11.5, pdfContentW-16) {
		d.text(pdfMarginL, d.y, fontBold, 11.5, pdfColDark, ln)
		d.y -= tlh
	}

	segs := []string{"SEVERITY: " + strings.ToUpper(pdfClean(f.Severity))}
	if f.CVSS > 0 {
		segs = append(segs, fmt.Sprintf("CVSS: %.1f", f.CVSS))
	}
	if f.CWE != "" {
		segs = append(segs, "CWE: "+pdfClean(f.CWE))
	}
	if f.OWASPCategory != "" {
		segs = append(segs, "OWASP: "+pdfClean(f.OWASPCategory))
	}
	meta := strings.Join(segs, "   ")
	d.need(16)
	pdfEmitRect(&d.cur, pdfMarginL, d.y-2.5, 8, 8, pdfSevRGB(f.Severity))
	d.text(pdfMarginL+13, d.y, fontBold, 8, pdfColMuted, meta)
	d.y -= 18

	d.field("Description", f.Description)
	d.fieldMono("Affected URL", f.AffectedURL)
	d.fieldMono("Parameter", f.Parameter)

	if len(f.StepsToReproduce) > 0 {
		d.fieldLabel("Steps to Reproduce")
		for i, s := range f.StepsToReproduce {
			d.para(fmt.Sprintf("%d. %s", i+1, s), fontReg, 9.5, pdfColDark, 12)
		}
		d.y -= 3
	}

	if strings.TrimSpace(f.Evidence) != "" {
		d.fieldLabel("Evidence")
		d.evidenceBlock(f.Evidence)
	}

	d.field("Impact", f.Impact)
	d.field("Remediation", f.Remediation)
	d.kvWrap("Remediation Effort", f.RemediationEffort, 9, 0)

	if len(f.References) > 0 {
		d.fieldLabel("References")
		for _, ref := range f.References {
			d.para("- "+ref, fontReg, 8.8, pdfColMuted, 12)
		}
	}

	d.y -= 4
	d.need(12)
	pdfEmitHLine(&d.cur, d.y, pdfColBorder, 0.5)
	d.y -= 12
}

func pdfCover(d *pdfDoc, r *PentestReport) {
	bannerH := 170.0
	pdfEmitRect(&d.cur, 0, pdfPageH-bannerH, pdfPageW, bannerH, pdfColNavy)

	title := pdfClean(r.Title)
	if title == "" {
		title = "Penetration Test Report"
	}
	y := pdfPageH - 62
	for _, ln := range pdfWrap(title, fontBold, 21, pdfContentW-32) {
		pdfEmitText(&d.cur, pdfMarginL, y, fontBold, 21, pdfColWhite, ln)
		y -= 27
	}
	y -= 4
	pdfEmitText(&d.cur, pdfMarginL, y, fontBold, 9.5, pdfColSubtle,
		"CONFIDENTIAL - SECURITY ASSESSMENT REPORT")

	d.y = pdfPageH - bannerH - 34
	d.text(pdfMarginL, d.y, fontBold, 10.5, pdfColConfRed, "*** CONFIDENTIAL ***")
	d.y -= 26

	d.kvWrap("Client", r.ClientName, 10.5, 0)
	d.kvWrap("Assessor", r.Assessor, 10.5, 0)
	d.kvWrap("Version", r.Version, 10.5, 0)
	d.kvWrap("Assessment Date", r.AssessmentDate.Format("02 Jan 2006"), 10.5, 0)
	d.kvWrap("Report Date", r.ReportDate.Format("02 Jan 2006"), 10.5, 0)
	d.kvWrap("Duration", r.ScanDuration.Round(1e9).String(), 10.5, 0)

	d.flushPage()
}

const pdfDisclaimerText = "This report is provided as-is for informational purposes. " +
	"The assessment was performed within the agreed scope and time frame. Results reflect " +
	"the state of the target systems at the time of testing and may not represent their " +
	"current security posture. This report is confidential and intended solely for the named " +
	"recipient. Unauthorized distribution is prohibited. The assessor assumes no liability " +
	"for damages arising from the use of this report."

// GeneratePDF renders the report as a valid PDF 1.4 document using only stdlib.
func GeneratePDF(report *PentestReport) []byte {
	d := newPDFDoc()
	r := report

	pdfCover(d, r)

	d.heading("Executive Summary")
	if strings.TrimSpace(r.ExecutiveSummary) == "" {
		d.para("No executive summary provided.", fontReg, 9.5, pdfColMuted, 0)
	} else {
		d.para(r.ExecutiveSummary, fontReg, 9.5, pdfColDark, 0)
	}

	d.heading("Risk Assessment")
	rating := strings.ToUpper(pdfClean(r.RiskRating))
	if rating == "" {
		rating = "NOT RATED"
	}
	d.badge(rating+" RISK", pdfHexToRGB(riskGaugeColor(r.RiskRating)), 10)
	d.kvWrap("Overall Score", fmt.Sprintf("%d / 100", r.OverallScore), 10, 0)
	d.kvWrap("Grade", r.Grade, 10, 0)
	d.para(fmt.Sprintf("Overall security posture rated %s based on %d total findings across %d checks performed.",
		strings.ToUpper(pdfClean(r.RiskRating)), r.TotalFound, r.TotalChecks),
		fontReg, 9, pdfColMuted, 0)

	d.heading("Findings Summary")
	d.statGrid([]pdfStat{
		{"Critical", r.CriticalCount, "#dc3545"},
		{"High", r.HighCount, "#fd7e14"},
		{"Medium", r.MediumCount, "#ffc107"},
		{"Low", r.LowCount, "#28a745"},
		{"Info", r.InfoCount, "#17a2b8"},
		{"Checks Run", r.TotalChecks, "#0d6efd"},
	})

	if len(r.TargetURLs) > 0 || len(r.IPAddresses) > 0 || len(r.Exclusions) > 0 {
		d.heading("Scope")
		for _, grp := range []struct {
			label string
			items []string
		}{
			{"Target URLs", r.TargetURLs},
			{"IP Addresses", r.IPAddresses},
			{"Exclusions", r.Exclusions},
		} {
			if len(grp.items) == 0 {
				continue
			}
			d.fieldLabel(grp.label)
			for _, item := range grp.items {
				d.para("- "+item, fontReg, 9.5, pdfColDark, 12)
			}
			d.y -= 4
		}
	}

	d.heading("Detailed Findings")
	if len(r.Findings) == 0 {
		d.para("No findings recorded.", fontReg, 9.5, pdfColMuted, 0)
	}
	for i := range r.Findings {
		d.finding(i+1, &r.Findings[i])
	}

	if r.OWASPCompliance != nil && len(r.OWASPCompliance) > 0 {
		d.heading("OWASP Top 10 (2021) Compliance Matrix")
		for _, cat := range owaspOrder() {
			status, scolor := "PASS", pdfColOKGreen
			if !r.OWASPCompliance[cat] {
				status, scolor = "FAIL", pdfColBadRed
			}
			d.need(18)
			catLines := pdfWrap(pdfClean(cat), fontReg, 9, pdfContentW-60)
			for k, ln := range catLines {
				d.text(pdfMarginL, d.y, fontReg, 9, pdfColDark, ln)
				if k == 0 {
					sw := pdfTextWidth(status, fontBold, 9)
					d.text(pdfPageW-pdfMarginR-sw, d.y, fontBold, 9, scolor, status)
				}
				d.y -= 12
			}
			d.y -= 4
		}
	}

	if r.Compliance != nil && len(r.Compliance) > 0 {
		pdfCompliance(d, r.Compliance)
	}

	d.heading("Timeline")
	d.kvWrap("Assessment Start", r.AssessmentDate.Format("02 Jan 2006 15:04 MST"), 9.5, 0)
	d.kvWrap("Assessment End", r.AssessmentDate.Add(r.ScanDuration).Format("02 Jan 2006 15:04 MST"), 9.5, 0)
	d.kvWrap("Scan Duration", r.ScanDuration.Round(1e9).String(), 9.5, 0)
	d.kvWrap("Report Generated", r.ReportDate.Format("02 Jan 2006 15:04 MST"), 9.5, 0)

	d.heading("Disclaimer")
	d.para(pdfDisclaimerText, fontReg, 8.3, pdfColMuted, 0)
	d.y -= 20
	d.centerText("STRESS-STRIKE Penetration Testing Framework", fontBold, 8, pdfColMuted)

	return d.build(pdfClean(report.Title))
}

// build assembles page content streams into the final PDF file structure:
// catalog, page tree, fonts, per-page objects, xref table and trailer.
func (d *pdfDoc) build(docTitle string) []byte {
	d.flushPage()
	if len(d.pages) == 0 {
		d.pages = [][]byte{{}}
	}
	npages := len(d.pages)

	footLeft := "CONFIDENTIAL - STRESS-STRIKE Penetration Testing Framework"
	for i := range d.pages {
		var fb bytes.Buffer
		pdfEmitHLine(&fb, 48, pdfColBorder, 0.6)
		pdfEmitText(&fb, pdfMarginL, 37, fontReg, 7, pdfColMuted, footLeft)
		pageLbl := fmt.Sprintf("Page %d of %d", i+1, npages)
		pdfEmitText(&fb, pdfPageW-pdfMarginR-pdfTextWidth(pageLbl, fontReg, 7), 37, fontReg, 7, pdfColMuted, pageLbl)
		d.pages[i] = append(d.pages[i], fb.Bytes()...)
	}

	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")

	offsets := make([]int, 8)
	writeObj := func(num int, body string) {
		for len(offsets) <= num {
			offsets = append(offsets, 0)
		}
		offsets[num] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", num, body)
	}

	kids := make([]string, npages)
	for i := range kids {
		kids[i] = fmt.Sprintf("%d 0 R", 7+2*i)
	}

	writeObj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	writeObj(2, fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), npages))
	writeObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	writeObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	writeObj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>")
	writeObj(6, fmt.Sprintf("<< /Title (%s) /Producer (STRESS-STRIKE Penetration Testing Framework) >>",
		pdfEscapeStr(docTitle)))

	for i, stream := range d.pages {
		pn := 7 + 2*i
		writeObj(pn, fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.0f %.0f] "+
			"/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
			pdfPageW, pdfPageH, pn+1))
		writeObj(pn+1, fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(stream), stream))
	}

	total := 6 + 2*npages
	xrefPos := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", total+1)
	out.WriteString("0000000000 65535 f \n")
	for i := 1; i <= total; i++ {
		fmt.Fprintf(&out, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n", total+1, xrefPos)
	out.WriteString("%%EOF\n")

	return out.Bytes()
}
