#!/usr/bin/env python3
"""Convert STUDY-GUIDE.md to a clean PDF using reportlab.

Handles basic Markdown: headings, paragraphs, bullet/numbered lists,
code blocks, tables, bold, inline code, blockquotes, hr, and escaping.
"""
import re
import sys

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Preformatted
)

IN = sys.argv[1]
OUT = sys.argv[2] if len(sys.argv) > 2 else "STUDY-GUIDE.pdf"

# ---------- colors / palette ----------
INK = colors.HexColor("#111827")
ACCENT = colors.HexColor("#0f766e")
ACCENT_LIGHT = colors.HexColor("#ccfbf1")
GREY = colors.HexColor("#6b7280")
LIGHT_GREY = colors.HexColor("#f3f4f6")
BORDER = colors.HexColor("#e5e7eb")
WHITE = colors.HexColor("#ffffff")

# ---------- styles ----------
def st(name, **kw):
    base = dict(
        fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK,
        spaceAfter=5, alignment=TA_LEFT,
    )
    base.update(kw)
    return ParagraphStyle(name, **base)

styles = {
    "h1": st("h1", fontName="Helvetica-Bold", fontSize=20, leading=26,
             textColor=ACCENT, spaceBefore=0, spaceAfter=8),
    "h2": st("h2", fontName="Helvetica-Bold", fontSize=15, leading=20,
             textColor=ACCENT, spaceBefore=14, spaceAfter=6),
    "h3": st("h3", fontName="Helvetica-Bold", fontSize=12, leading=16,
             textColor=INK, spaceBefore=10, spaceAfter=4),
    "h4": st("h4", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
             textColor=INK, spaceBefore=8, spaceAfter=3),
    "p": st("p"),
    "bullet": st("bullet", leftIndent=14, bulletIndent=4, spaceAfter=2),
    "num": st("num", leftIndent=14, bulletIndent=4, spaceAfter=2),
    "quote": st("quote", leftIndent=14, textColor=GREY, fontName="Helvetica-Oblique",
                backColor=ACCENT_LIGHT, borderPadding=(6, 6, 6, 6),
                borderColor=ACCENT, borderWidth=0.7),
    "code": st("code", fontName="Courier", fontSize=8.2, leading=10.5,
               textColor=colors.HexColor("#b91c1c"),
               backColor=LIGHT_GREY, borderPadding=(2, 2, 2, 2)),
    "codeblock": ParagraphStyle("codeblock", fontName="Courier", fontSize=7.8,
                                leading=10, textColor=colors.HexColor("#1f2937"),
                                backColor=colors.HexColor("#f9fafb"),
                                borderColor=BORDER, borderWidth=0.7,
                                borderPadding=(6, 6, 6, 6), spaceBefore=4,
                                spaceAfter=6),
    "tablehead": ParagraphStyle("tablehead", fontName="Helvetica-Bold", fontSize=8.5,
                                leading=11, textColor=WHITE),
    "tablecell": st("tablecell", fontSize=8.2, leading=11),
    "toc": st("toc", leftIndent=10, spaceAfter=2),
    "foot": ParagraphStyle("foot", fontName="Helvetica-Oblique", fontSize=8,
                           leading=10, textColor=GREY, spaceBefore=6),
}

# ---------- markdown-ish inline parser ----------
INLINE_RE = r'(\*\*.*?\*\*|`[^`]+`|\*[^*]+?\*)'

def inline(text, base_style="p"):
    """Convert **bold**, `code`, *italic* into reportlab <b>/<font>/<i>."""
    def repl(m):
        t = m.group(0)
        if t.startswith("**") and t.endswith("**"):
            return "<b>%s</b>" % t[2:-2]
        if t.startswith("`") and t.endswith("`"):
            return '<font face="Courier" color="#b91c1c">%s</font>' % t[1:-1]
        if t.startswith("*") and t.endswith("*") and len(t) > 2:
            return "<i>%s</i>" % t[1:-1]
        return t
    # escape & < > first, then apply inline
    out = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out = re.sub(INLINE_RE, repl, out)
    # restore natural tags we generated
    out = (out.replace("&lt;b&gt;", "<b>").replace("&lt;/b&gt;", "</b>")
              .replace("&lt;i&gt;", "<i>").replace("&lt;/i&gt;", "</i>")
              .replace("&lt;font", "<font").replace("font&gt;", "font>"))
    return out

# ---------- markdown table parser ----------
def is_table_sep(line):
    return bool(re.match(r'^\s*\|?[\s:|-]+\|?\s*$', line)) and "-" in line

def parse_table(lines, i):
    """Parse a markdown table starting at header row i. Returns (rows, next_i)."""
    header = [c.strip() for c in lines[i].strip().strip("|").split("|")]
    rows = [header]
    j = i + 1
    if j < len(lines) and is_table_sep(lines[j]):
        j += 1
    while j < len(lines) and lines[j].strip() and not lines[j].strip().startswith("|"):
        j += 1
    while j < len(lines) and lines[j].strip().startswith("|"):
        cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
        rows.append(cells)
        j += 1
    return rows, j

def make_table(rows):
    data = []
    for idx, r in enumerate(rows):
        style = styles["tablehead"] if idx == 0 else styles["tablecell"]
        data.append([Paragraph(inline(c), style) for c in r])
    t = Table(data, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GREY]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t

# ---------- code fence ----------
def is_fence(line):
    return line.strip().startswith("```")

# ---------- build flowables ----------
def parse(lines):
    story = []
    i = 0
    n = len(lines)
    list_type = None  # "*" or "1."
    order_counter = 0

    def flush_list():
        nonlocal list_type, order_counter
        list_type = None
        order_counter = 0

    while i < n:
        raw = lines[i].rstrip("\n")
        stripped = raw.strip()

        # blank line
        if not stripped:
            flush_list()
            i += 1
            continue

        # code fence
        if is_fence(raw):
            flush_list()
            i += 1
            buf = []
            while i < n and not is_fence(lines[i]):
                buf.append(lines[i].rstrip("\n"))
                i += 1
            i += 1  # skip closing fence
            story.append(Preformatted("\n".join(buf), styles["codeblock"]))
            continue

        # heading
        m = re.match(r'^(#{1,4})\s+(.*)$', stripped)
        if m:
            flush_list()
            level, text = len(m.group(1)), m.group(2)
            story.append(Paragraph(inline(text), styles["h%d" % level]))
            i += 1
            continue

        # horizontal rule
        if re.match(r'^\s*---+\s*$', raw):
            flush_list()
            story.append(Spacer(1, 4))
            story.append(Paragraph("", styles["p"]))
            i += 1
            continue

        # blockquote
        if stripped.startswith(">"):
            flush_list()
            text = stripped.lstrip(">").strip()
            story.append(Paragraph(inline(text), styles["quote"]))
            i += 1
            continue

        # table
        if "|" in raw and not stripped.startswith("|"):
            # header row does not start with | but has |; check next line is separator
            if i + 1 < n and is_table_sep(lines[i + 1]):
                flush_list()
                rows, nxt = parse_table(lines, i)
                story.append(make_table(rows))
                story.append(Spacer(1, 4))
                i = nxt
                continue

        # unordered list
        m = re.match(r'^\s*[-*]\s+(.*)$', stripped)
        if m:
            if list_type != "bullet":
                flush_list()
                list_type = "bullet"
            story.append(Paragraph(inline(m.group(1)), styles["bullet"], bulletText="•"))
            i += 1
            continue

        # ordered list
        m = re.match(r'^\s*\d+[.)]\s+(.*)$', stripped)
        if m:
            if list_type != "num":
                flush_list()
                list_type = "num"
                order_counter = 1
            bullet = "%d." % order_counter
            order_counter += 1
            story.append(Paragraph(inline(m.group(1)), styles["num"], bulletText=bullet))
            i += 1
            continue

        # paragraph (may span line continuation — keep simple: one line = one para)
        flush_list()
        story.append(Paragraph(inline(stripped), styles["p"]))
        i += 1

    return story

# ---------- cover / toc ----------
def build_doc():
    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=16*mm, bottomMargin=16*mm,
        title="stress-strike — Study Guide",
        author="stress-strike",
    )

    from reportlab.platypus import PageBreak
    story = []

    # Cover
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph("stress-strike", styles["h1"]))
    story.append(Paragraph("To'liq O'rganish Qo'llanmasi (Study Guide)", styles["h2"]))
    story.append(Paragraph("Go load-testing va security suite — arxitektura, oqimlar va mustaqil o'rganish rejasi", styles["p"]))
    story.append(Spacer(1, 4*mm))

    # TOC
    headings = []
    for line in open(IN, encoding="utf-8"):
        m = re.match(r'^(#{2,3})\s+(.*)$', line.strip())
        if m:
            lvl = len(m.group(1))
            text = m.group(2).replace("`", "")
            headings.append((lvl, text))
    story.append(Paragraph("Mundarija", styles["h2"]))
    for lvl, text in headings:
        indent = 10 if lvl == 2 else 22
        p = Paragraph(inline(text), ParagraphStyle("toc%d" % lvl,
                       parent=styles["toc"], leftIndent=indent,
                       fontSize=9 if lvl == 2 else 8.5))
        story.append(p)
    story.append(PageBreak())

    # Body
    with open(IN, encoding="utf-8") as f:
        lines = f.readlines()
    story.extend(parse(lines))

    story.append(Spacer(1, 10))
    story.append(Paragraph("— End of document. Stress-strike study guide —", styles["foot"]))

    # footer page numbers
    def footer(canvas, d):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(GREY)
        canvas.drawString(18*mm, 10*mm, "stress-strike — Study Guide")
        canvas.drawRightString(A4[0]-18*mm, 10*mm, "Page %d" % d.page)
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print("PDF yaratildi:", OUT)

if __name__ == "__main__":
    build_doc()
