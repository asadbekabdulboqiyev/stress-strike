package metrics

import (
	"testing"
	"time"
)

func BenchmarkHistogramAdd(b *testing.B) {
	h := &Histogram{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Add(time.Duration(i%1000+1) * time.Millisecond)
	}
}

func BenchmarkHistogramSnapshot(b *testing.B) {
	h := &Histogram{}
	// Pre-populate with 1M samples
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%1000+1) * time.Millisecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Snapshot()
	}
}

func BenchmarkPercentile(b *testing.B) {
	h := &Histogram{}
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%1000+1) * time.Millisecond)
	}
	snap := h.Snapshot()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = snap.Percentile(0.50)
		_ = snap.Percentile(0.95)
		_ = snap.Percentile(0.99)
	}
}

// BenchmarkPercentileLive measures the three percentiles a live caller (the
// progress panel, the dashboard push) actually reads. Unlike
// BenchmarkPercentile it does not pay for a Snapshot, because that is the whole
// point: the live path must not copy the bucket array.
func BenchmarkPercentileLive(b *testing.B) {
	h := &Histogram{}
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%1000+1) * time.Millisecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Percentile(0.50)
		_ = h.Percentile(0.95)
		_ = h.Percentile(0.99)
	}
}

// BenchmarkLiveReadPattern is the full read a live frame performs: three
// percentiles plus average and max, with no Snapshot anywhere.
func BenchmarkLiveReadPattern(b *testing.B) {
	h := &Histogram{}
	for i := 0; i < 1_000_000; i++ {
		h.Add(time.Duration(i%1000+1) * time.Millisecond)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.Percentile(0.50)
		_ = h.Percentile(0.95)
		_ = h.Percentile(0.99)
		_ = h.Avg()
		_ = h.MaxLatency()
	}
}

func BenchmarkStepStatsRecord(b *testing.B) {
	s := NewStepStats("bench")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Record(time.Duration(i%100)*time.Millisecond, 200, "")
	}
}

func BenchmarkStepStatsRecordWithErrors(b *testing.B) {
	s := NewStepStats("bench")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		errName := ""
		if i%5 == 0 {
			errName = "err"
		}
		s.Record(time.Duration(i%100)*time.Millisecond, 200, errName)
	}
}

func BenchmarkTelemetryTotalRequests(b *testing.B) {
	tel := NewTelemetry()
	for i := 0; i < 1000; i++ {
		step := NewStepStats("step")
		step.Record(time.Millisecond, 200, "")
		tel.AddStep(step)
	}
	tel.Finish()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tel.TotalRequests()
	}
}

func BenchmarkTelemetryRPS(b *testing.B) {
	tel := NewTelemetry()
	for i := 0; i < 1000; i++ {
		step := NewStepStats("step")
		step.Record(time.Millisecond, 200, "")
		tel.AddStep(step)
	}
	tel.Finish()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tel.RPS()
	}
}
