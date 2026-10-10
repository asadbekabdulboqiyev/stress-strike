#!/usr/bin/env bash
set -euo pipefail

OUT="reports/white-label.pdf"
MD="docs/WHITE-LABEL.md"

if [ -f "docs/md2pdf.py" ]; then
  python3 docs/md2pdf.py "$MD" "$OUT" || true
fi

echo "White-label PDF generated at $OUT (best-effort)"
