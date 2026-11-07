package certificate

import (
	"bytes"
	"fmt"
	"strings"
)

// PDF renders a certificate as a minimal but valid PDF 1.4 document (pure Go,
// no external dependencies). One page per Page() call, portrait letter,
// Helvetica 10pt, lines drawn from the top (y=740) downward by 13 units.
type PDF struct {
	pages [][]string
}

// NewPDF starts a PDF document with one blank page.
func NewPDF() *PDF {
	return &PDF{pages: [][]string{{}}}
}

// Page starts a new page.
func (p *PDF) Page() *PDF {
	p.pages = append(p.pages, []string{})
	return p
}

// Text appends a line to the current page.
func (p *PDF) Text(s string) *PDF {
	top := &p.pages[len(p.pages)-1]
	*top = append(*top, s)
	return p
}

// Bytes finalizes and returns the PDF bytes.
func (p *PDF) Bytes() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")

	type objW func() int
	var offsets []int
	objNum := 0
	newObj := func() int {
		objNum++
		offsets = append(offsets, b.Len())
		b.WriteString(fmt.Sprintf("%d 0 obj\n", objNum))
		return objNum
	}
	closeObj := func() {
		b.WriteString("endobj\n")
	}

	// 1 Catalog
	newObj()
	b.WriteString("<< /Type /Catalog /Pages 2 0 R >>\n")
	closeObj()

	// 2 Pages root
	newObj()
	fmt.Fprintf(&b, "<< /Type /Pages /Kids [")
	for i := range p.pages {
		fmt.Fprintf(&b, " %d 0 R", 3+3*i)
	}
	fmt.Fprintf(&b, "] /Count %d /MediaBox [0 0 612 792] >>\n", len(p.pages))
	closeObj()

	next := 3
	fontObjs := make([]int, len(p.pages))
	contentObjs := make([]int, len(p.pages))
	for i := range p.pages {
		// page object
		newObj()
		fontObjs[i] = next
		next++
		contentObjs[i] = next
		next++
		fmt.Fprintf(&b, "<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>\n", fontObjs[i], contentObjs[i])
		closeObj()
		// font object
		newObj()
		b.WriteString("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n")
		closeObj()
		// content object
		content := buildContent(p.pages[i])
		newObj()
		fmt.Fprintf(&b, "<< /Length %d >>\nstream\n", len(content))
		b.Write(content)
		b.WriteString("\nendstream\n")
		closeObj()
	}

	// xref
	xrefOff := b.Len()
	b.WriteString("xref\n")
	fmt.Fprintf(&b, "0 %d\n", objNum+1)
	b.WriteString("0000000000 65535 f \n")
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	b.WriteString("trailer\n")
	b.WriteString("<< /Size ")
	fmt.Fprintf(&b, "%d", objNum+1)
	b.WriteString(" /Root 1 0 R >>\n")
	b.WriteString("startxref\n")
	fmt.Fprintf(&b, "%d\n", xrefOff)
	b.WriteString("%%EOF\n")

	return b.Bytes(), nil
}

func buildContent(lines []string) []byte {
	var b bytes.Buffer
	y := 740.0
	fmt.Fprintf(&b, "BT /F1 10 Tf 50 %.0f Td\n", y)
	for _, s := range lines {
		esc := pdfEscape(s)
		fmt.Fprintf(&b, "(%s) Tj\n", esc)
		y -= 15
		fmt.Fprintf(&b, "0 -15 Td\n")
	}
	b.WriteString("ET\n")
	return b.Bytes()
}

func pdfEscape(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case '(':
			sb.WriteString("\\(")
		case ')':
			sb.WriteString("\\)")
		case '\\':
			sb.WriteString("\\\\")
		default:
			if r < 32 || r > 126 {
				fmt.Fprintf(&sb, "\\%03o", r)
			} else {
				sb.WriteRune(r)
			}
		}
	}
	return sb.String()
}
