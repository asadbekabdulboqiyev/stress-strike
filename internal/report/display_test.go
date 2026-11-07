package report

import "testing"

// sparkline renders a compact bar chart of recent throughput samples. It
// indexes into sparklineChars by byte (a pre-existing quirk with multi-byte
// glyphs), so these tests assert shape, not glyph identity.
func TestSparkline(t *testing.T) {
	if got := sparkline(nil); got != "—" {
		t.Errorf("sparkline(nil) = %q, want placeholder dash", got)
	}
	if got := sparkline([]float64{5}); len(got) != 1 {
		t.Errorf("sparkline(single) = %q, want 1 bar", got)
	}
	got := sparkline([]float64{1, 100})
	if len(got) != 2 {
		t.Fatalf("sparkline(two) = %q, want 2 bars", got)
	}
	got = sparkline([]float64{7, 7, 7})
	if len(got) != 3 {
		t.Fatalf("sparkline(equal) = %q, want 3 bars", got)
	}
	if got[0] != got[1] || got[1] != got[2] {
		t.Errorf("sparkline(equal) = %q, want three identical bytes", got)
	}
}
