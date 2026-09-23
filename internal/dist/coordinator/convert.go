// Package coordinator implements the distributed master/worker control plane:
// scenario distribution, live telemetry streaming, result aggregation and the
// gRPC service surface shared by `stress-strike-master` and
// `stress-strike-worker`.
package coordinator

import (
	"time"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/config"
	distproto "github.com/asadbekabdulboqiyev/stress-strike/internal/dist/proto"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/metrics"
	"github.com/asadbekabdulboqiyev/stress-strike/internal/report"
)

// StatusToProto converts an in-process status-code histogram into proto form.
func StatusToProto(m map[int]uint64) map[int32]int64 {
	out := make(map[int32]int64, len(m))
	for k, v := range m {
		out[int32(k)] = int64(v)
	}
	return out
}

// StatusFromProto converts a proto status-code histogram into in-process form.
func StatusFromProto(m map[int32]int64) map[int]uint64 {
	out := make(map[int]uint64, len(m))
	for k, v := range m {
		out[int(k)] = uint64(v)
	}
	return out
}

// ErrorsToProto converts an in-process error histogram into proto form.
func ErrorsToProto(m map[string]uint64) map[string]int64 {
	out := make(map[string]int64, len(m))
	for k, v := range m {
		out[k] = int64(v)
	}
	return out
}

// ErrorsFromProto converts a proto error histogram into in-process form.
func ErrorsFromProto(m map[string]int64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = uint64(v)
	}
	return out
}

// LatencyToProto converts a histogram snapshot into proto percentiles.
func LatencyToProto(snap metrics.HistogramSnapshot) *distproto.LatencyPercentiles {
	return &distproto.LatencyPercentiles{
		P50Ms: snap.Percentile(0.50).Milliseconds(),
		P95Ms: snap.Percentile(0.95).Milliseconds(),
		P99Ms: snap.Percentile(0.99).Milliseconds(),
		AvgMs: snap.Average.Milliseconds(),
		MinMs: snap.Min.Milliseconds(),
		MaxMs: snap.Max.Milliseconds(),
	}
}

func latencyFromProto(p *distproto.LatencyPercentiles) (min, avg, max, p50, p95, p99 time.Duration) {
	if p == nil {
		return
	}
	return time.Duration(p.MinMs) * time.Millisecond,
		time.Duration(p.AvgMs) * time.Millisecond,
		time.Duration(p.MaxMs) * time.Millisecond,
		time.Duration(p.P50Ms) * time.Millisecond,
		time.Duration(p.P95Ms) * time.Millisecond,
		time.Duration(p.P99Ms) * time.Millisecond
}

// TelemetryToProto snapshots a live *metrics.Telemetry into a proto message,
// including per-step breakdowns. Safe to call while the run is in progress.
func TelemetryToProto(tel *metrics.Telemetry, snap metrics.HistogramSnapshot) *distproto.TelemetrySnapshot {
	ts := &distproto.TelemetrySnapshot{
		Timestamp:     time.Now().UnixMilli(),
		ElapsedMs:     tel.Elapsed().Milliseconds(),
		TotalRequests: int64(tel.TotalRequests()),
		TotalErrors:   int64(tel.TotalErrors()),
		Rps:           tel.RPS(),
		ActiveUsers:   tel.ActiveUsers.Load(),
		StatusCodes:   StatusToProto(tel.StatusCodes()),
		ErrorTypes:    ErrorsToProto(tel.Errors()),
		Latency:       LatencyToProto(snap),
	}
	for _, step := range tel.Steps {
		ts.Steps = append(ts.Steps, &distproto.StepTelemetry{
			Name:        step.Name,
			Requests:    int64(step.Requests()),
			Errors:      int64(step.ErrorCount()),
			Latency:     LatencyToProto(step.Latency.Snapshot()),
			StatusCodes: StatusToProto(step.StatusCodes()),
			ErrorTypes:  ErrorsToProto(step.Errors()),
		})
	}
	return ts
}

// StepReportToProto converts an in-process step report into proto form.
func StepReportToProto(s *report.StepReport) *distproto.StepReport {
	if s == nil {
		return nil
	}
	return &distproto.StepReport{
		Name:        s.Name,
		Requests:    int64(s.Requests),
		Errors:      int64(s.Errors),
		StatusCodes: StatusToProto(s.Status),
		ErrorTypes:  ErrorsToProto(s.ErrorTypes),
		MinMs:       s.Min.Milliseconds(),
		AvgMs:       s.Avg.Milliseconds(),
		MaxMs:       s.Max.Milliseconds(),
		P50Ms:       s.P50.Milliseconds(),
		P95Ms:       s.P95.Milliseconds(),
		P99Ms:       s.P99.Milliseconds(),
	}
}

// StepReportFromProto converts a proto step report into in-process form.
func StepReportFromProto(s *distproto.StepReport) report.StepReport {
	if s == nil {
		return report.StepReport{}
	}
	return report.StepReport{
		Name:       s.Name,
		Requests:   uint64(s.Requests),
		Errors:     uint64(s.Errors),
		Status:     StatusFromProto(s.StatusCodes),
		ErrorTypes: ErrorsFromProto(s.ErrorTypes),
		Min:        time.Duration(s.MinMs) * time.Millisecond,
		Avg:        time.Duration(s.AvgMs) * time.Millisecond,
		Max:        time.Duration(s.MaxMs) * time.Millisecond,
		P50:        time.Duration(s.P50Ms) * time.Millisecond,
		P95:        time.Duration(s.P95Ms) * time.Millisecond,
		P99:        time.Duration(s.P99Ms) * time.Millisecond,
	}
}

// ReportToProto converts a full report into proto form for transport.
func ReportToProto(r *report.Report) *distproto.Report {
	if r == nil {
		return nil
	}
	out := &distproto.Report{
		Name:          r.Name,
		BaseUrl:       r.BaseURL,
		LoadProfile:   r.LoadProfile,
		StartedAt:     r.StartedAt.UnixMilli(),
		EndedAt:       r.EndedAt.UnixMilli(),
		DurationMs:    r.Duration.Milliseconds(),
		ActiveUsers:   r.ActiveUsers,
		TotalRequests: int64(r.TotalRequests),
		TotalErrors:   int64(r.TotalErrors),
		ErrorRatePct:  r.ErrorRatePct,
		Rps:           r.RPS,
		StatusCodes:   StatusToProto(r.Status),
		Errors:        ErrorsToProto(r.Errors),
		Overall:       StepReportToProto(&r.Overall),
		Sla:           slaResultsToProto(r.SLA),
	}
	for i := range r.Steps {
		out.Steps = append(out.Steps, StepReportToProto(&r.Steps[i]))
	}
	for _, s := range r.Timeline {
		out.Timeline = append(out.Timeline, &distproto.TimelineSample{
			Second:        int32(s.Second),
			RequestsTotal: int64(s.Requests),
			ErrorsTotal:   int64(s.Errors),
			ActiveUsers:   s.ActiveUsers,
		})
	}
	return out
}

// ReportFromProto converts a transported proto report back into a report.Report.
func ReportFromProto(r *distproto.Report) *report.Report {
	if r == nil {
		return nil
	}
	out := &report.Report{
		Name:          r.Name,
		BaseURL:       r.BaseUrl,
		LoadProfile:   r.LoadProfile,
		StartedAt:     time.UnixMilli(r.StartedAt),
		EndedAt:       time.UnixMilli(r.EndedAt),
		Duration:      time.Duration(r.DurationMs) * time.Millisecond,
		ActiveUsers:   r.ActiveUsers,
		TotalRequests: uint64(r.TotalRequests),
		TotalErrors:   uint64(r.TotalErrors),
		ErrorRatePct:  r.ErrorRatePct,
		RPS:           r.Rps,
		Status:        StatusFromProto(r.StatusCodes),
		Errors:        ErrorsFromProto(r.Errors),
		Overall:       StepReportFromProto(r.Overall),
		SLA:           slaResultsFromProto(r.Sla),
	}
	for _, s := range r.Steps {
		out.Steps = append(out.Steps, StepReportFromProto(s))
	}
	for _, s := range r.Timeline {
		out.Timeline = append(out.Timeline, metrics.TimelineSample{
			Second:      int(s.Second),
			Requests:    uint64(s.RequestsTotal),
			Errors:      uint64(s.ErrorsTotal),
			ActiveUsers: s.ActiveUsers,
		})
	}
	return out
}

func slaResultsToProto(results []report.SLAResult) []*distproto.SLAResult {
	out := make([]*distproto.SLAResult, len(results))
	for i, r := range results {
		out[i] = &distproto.SLAResult{
			Metric: r.Metric,
			Target: r.Target,
			Actual: r.Actual,
			Pass:   r.Pass,
		}
	}
	return out
}

func slaResultsFromProto(results []*distproto.SLAResult) []report.SLAResult {
	out := make([]report.SLAResult, len(results))
	for i, r := range results {
		out[i] = report.SLAResult{
			Metric: r.Metric,
			Target: r.Target,
			Actual: r.Actual,
			Pass:   r.Pass,
		}
	}
	return out
}

// ScenarioToProto converts a scenario into its wire representation.
func ScenarioToProto(sc *config.Scenario) *distproto.Scenario {
	if sc == nil {
		return nil
	}
	out := &distproto.Scenario{
		Name:      sc.Name,
		BaseUrl:   sc.BaseURL,
		Variables: sc.Variables,
		Profile: &distproto.LoadProfile{
			Type:           sc.Profile.Type,
			Users:          int32(sc.Profile.Users),
			Duration:       int32(sc.Profile.Duration),
			RampUp:         int32(sc.Profile.RampUp),
			SpikeUsers:     int32(sc.Profile.SpikeUsers),
			SpikeWarmup:    int32(sc.Profile.SpikeWarmup),
			SpikeHold:      int32(sc.Profile.SpikeHold),
			WavePeriod:     int32(sc.Profile.WavePeriod),
			Rps:            int32(sc.Profile.RPS),
			TargetRps:      int32(sc.Profile.TargetRPS),
			Timeout:        int32(sc.Profile.Timeout),
			KeepAlive:      sc.Profile.KeepAlive != nil && *sc.Profile.KeepAlive,
			TlsFingerprint: sc.Profile.TLSFingerprint,
		},
		Sla: scenarioSLAToProto(sc.SLA),
	}
	for _, s := range sc.Steps {
		step := &distproto.Step{
			Name:          s.Name,
			Type:          s.Type,
			Method:        s.Method,
			Url:           s.URL,
			Headers:       s.Headers,
			Body:          s.Body,
			Timeout:       int32(s.Timeout),
			FrameType:     s.FrameType,
			GrpcMethod:    s.GrpcMethod,
			AwaitResponse: s.AwaitResponse,
			Session:       s.Session,
		}
		for _, ext := range s.Extract {
			step.Extract = append(step.Extract, &distproto.Extract{
				Name: ext.Name,
				From: ext.From,
				Path: ext.Path,
			})
		}
		for _, ass := range s.Assertions {
			step.Assertions = append(step.Assertions, &distproto.Assertion{
				Type:  ass.Type,
				Value: ass.Value,
			})
		}
		out.Steps = append(out.Steps, step)
	}
	return out
}

// ScenarioFromProto rebuilds a scenario from the wire representation. It
// returns ok=false for a nil/empty payload.
func ScenarioFromProto(p *distproto.Scenario) (*config.Scenario, bool) {
	if p == nil {
		return nil, false
	}
	sc := &config.Scenario{
		Name:      p.Name,
		BaseURL:   p.BaseUrl,
		Variables: p.Variables,
	}
	if p.Profile != nil {
		keepAlive := p.Profile.KeepAlive
		sc.Profile = config.Profile{
			Type:           p.Profile.Type,
			Users:          int(p.Profile.Users),
			Duration:       int(p.Profile.Duration),
			RampUp:         int(p.Profile.RampUp),
			SpikeUsers:     int(p.Profile.SpikeUsers),
			SpikeWarmup:    int(p.Profile.SpikeWarmup),
			SpikeHold:      int(p.Profile.SpikeHold),
			WavePeriod:     int(p.Profile.WavePeriod),
			RPS:            int(p.Profile.Rps),
			TargetRPS:      int(p.Profile.TargetRps),
			Timeout:        int(p.Profile.Timeout),
			KeepAlive:      &keepAlive,
			TLSFingerprint: p.Profile.TlsFingerprint,
		}
	}
	for _, s := range p.Steps {
		step := config.Step{
			Name:          s.Name,
			Type:          s.Type,
			Method:        s.Method,
			URL:           s.Url,
			Headers:       s.Headers,
			Body:          s.Body,
			Timeout:       int(s.Timeout),
			FrameType:     s.FrameType,
			GrpcMethod:    s.GrpcMethod,
			AwaitResponse: s.AwaitResponse,
			Session:       s.Session,
		}
		for _, ext := range s.Extract {
			step.Extract = append(step.Extract, config.Extract{
				Name: ext.Name,
				From: ext.From,
				Path: ext.Path,
			})
		}
		for _, ass := range s.Assertions {
			step.Assertions = append(step.Assertions, config.Assertion{
				Type:  ass.Type,
				Value: ass.Value,
			})
		}
		sc.Steps = append(sc.Steps, step)
	}
	if p.Sla != nil {
		sc.SLA = &config.SLA{
			MaxP99Ms:        p.Sla.MaxP99Ms,
			MaxAvgMs:        p.Sla.MaxAvgMs,
			MaxErrorRatePct: p.Sla.MaxErrorRatePct,
			MinRPS:          p.Sla.MinRps,
		}
	}
	return sc, true
}

func scenarioSLAToProto(sla *config.SLA) *distproto.SLA {
	if sla == nil || (sla.MaxP99Ms <= 0 && sla.MaxAvgMs <= 0 && sla.MaxErrorRatePct <= 0 && sla.MinRPS <= 0) {
		return nil
	}
	return &distproto.SLA{
		MaxP99Ms:        sla.MaxP99Ms,
		MaxAvgMs:        sla.MaxAvgMs,
		MaxErrorRatePct: sla.MaxErrorRatePct,
		MinRps:          sla.MinRPS,
	}
}
