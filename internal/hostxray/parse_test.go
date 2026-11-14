package hostxray

import (
	"strings"
	"testing"
)

// Fixtures are inline so the parser tests — and therefore the package build on
// darwin — need no /proc. Each fixture mirrors real kernel output, including
// the header noise and column order.

const loadAvgFixture = "0.42 0.35 0.30 1/523 12345\n"

const memInfoFixture = `MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:    8192000 kB
Buffers:          204800 kB
Cached:          4096000 kB
SwapCached:            0 kB
`

const memInfoLegacyFixture = `MemTotal:       16384000 kB
MemFree:         1024000 kB
Buffers:          204800 kB
Cached:          4096000 kB
`

const netDevFixture = `Interfaces:  50    0    0    0    0     0          0         0        0     0    0    0    0     0       0          0
  lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 2000 20 3 4 0 0 0 0 3000 30 5 6 0 0 0 0
`

const psiMemoryFixture = `some avg10=0.05 avg60=0.13 avg300=0.04 total=123456789
full avg10=0.01 avg60=0.02 avg300=0.03 total=987654
`

const psiCPUFixature = "some avg10=2.50 avg60=1.75 avg300=0.90 total=424242\n"

const procStatFixture = `cpu  123 45 678 9012 34 5 6 7 0 0
cpu0 100 20 300 4000 10 1 2 3 0 0
intr 12345
ctxt 67890
`

func TestParseLoadAvg(t *testing.T) {
	load, err := ParseLoadAvg(strings.NewReader(loadAvgFixture))
	if err != nil {
		t.Fatalf("ParseLoadAvg: %v", err)
	}
	if !load.Available {
		t.Fatal("Available = false, want true")
	}
	if load.One != 0.42 || load.Five != 0.35 || load.Fifteen != 0.30 {
		t.Fatalf("load = %+v, want 0.42/0.35/0.30", load)
	}
	if load.Runnable != 1 || load.Processes != 523 {
		t.Fatalf("runnable/total = %d/%d, want 1/523", load.Runnable, load.Processes)
	}
}

func TestParseLoadAvgMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"too few":      "0.1 0.2\n",
		"bad 1-minute": "abc 0.2 0.3 1/2 3\n",
		"bad 5-minute": "0.1 xyz 0.3 1/2 3\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLoadAvg(strings.NewReader(fixture)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseLoadAvgOptionalRunnable(t *testing.T) {
	load, err := ParseLoadAvg(strings.NewReader("1.00 2.00 3.00\n"))
	if err != nil {
		t.Fatalf("ParseLoadAvg: %v", err)
	}
	if load.Runnable != 0 || load.Processes != 0 {
		t.Fatalf("runnable/total = %d/%d, want 0/0", load.Runnable, load.Processes)
	}
}

func TestParseMemInfo(t *testing.T) {
	mem, err := ParseMemInfo(strings.NewReader(memInfoFixture))
	if err != nil {
		t.Fatalf("ParseMemInfo: %v", err)
	}
	if !mem.Available {
		t.Fatal("Available = false, want true")
	}
	if mem.TotalBytes != 16384000*1024 {
		t.Fatalf("TotalBytes = %d, want %d", mem.TotalBytes, 16384000*1024)
	}
	if mem.AvailableBytes != 8192000*1024 {
		t.Fatalf("AvailableBytes = %d, want %d", mem.AvailableBytes, 8192000*1024)
	}
	if mem.UsedPct != 50 {
		t.Fatalf("UsedPct = %v, want 50", mem.UsedPct)
	}
}

func TestParseMemInfoLegacyFallback(t *testing.T) {
	mem, err := ParseMemInfo(strings.NewReader(memInfoLegacyFixture))
	if err != nil {
		t.Fatalf("ParseMemInfo: %v", err)
	}
	wantAvailable := uint64(1024000+204800+4096000) * 1024
	if mem.AvailableBytes != wantAvailable {
		t.Fatalf("AvailableBytes = %d, want %d (MemFree+Buffers+Cached)", mem.AvailableBytes, wantAvailable)
	}
}

func TestParseMemInfoMalformed(t *testing.T) {
	cases := map[string]string{
		"missing total":  "MemFree: 1024 kB\n",
		"zero total":     "MemTotal: 0 kB\n",
		"bad number":     "MemTotal: lots kB\n",
		"unknown unit":   "MemTotal: 100 XB\n",
		"overflow bytes": "MemTotal: 18446744073709551615 GB\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMemInfo(strings.NewReader(fixture)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseNetDev(t *testing.T) {
	ifaces, err := ParseNetDev(strings.NewReader(netDevFixture))
	if err != nil {
		t.Fatalf("ParseNetDev: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("interfaces = %d, want 2", len(ifaces))
	}
	eth0 := ifaces[1]
	if eth0.Name != "eth0" {
		t.Fatalf("second interface = %q, want eth0", eth0.Name)
	}
	if eth0.RxBytes != 2000 || eth0.RxErrors != 3 || eth0.RxDrops != 4 {
		t.Fatalf("eth0 rx = %+v", eth0)
	}
	if eth0.TxBytes != 3000 || eth0.TxErrors != 5 || eth0.TxDrops != 6 {
		t.Fatalf("eth0 tx = %+v", eth0)
	}
}

func TestParseNetDevMalformed(t *testing.T) {
	cases := map[string]string{
		"headers only": "Interfaces: x\n face | bytes\n",
		"short row":    "  eth0: 1 2 3\n",
		"bad counter":  "  eth0: 1 2 3 4 5 6 7 8 9 10 eleven 12 13 14 15 16\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNetDev(strings.NewReader(fixture)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestAggregateNetDev(t *testing.T) {
	ifaces, err := ParseNetDev(strings.NewReader(netDevFixture))
	if err != nil {
		t.Fatalf("ParseNetDev: %v", err)
	}
	agg := AggregateNetDev(ifaces)
	if agg.Name != "aggregate" {
		t.Fatalf("Name = %q, want aggregate", agg.Name)
	}
	if agg.RxBytes != 3000 || agg.TxBytes != 4000 {
		t.Fatalf("aggregate bytes = %d/%d, want 3000/4000", agg.RxBytes, agg.TxBytes)
	}
	if agg.RxErrors != 3 || agg.RxDrops != 4 || agg.TxErrors != 5 || agg.TxDrops != 6 {
		t.Fatalf("aggregate faults = %+v", agg)
	}
}

func TestAggregateNetDevSaturates(t *testing.T) {
	agg := AggregateNetDev([]InterfaceCounters{
		{Name: "a", RxBytes: ^uint64(0) - 1},
		{Name: "b", RxBytes: 10},
	})
	if agg.RxBytes != ^uint64(0) {
		t.Fatalf("RxBytes = %d, want saturation at MaxUint64", agg.RxBytes)
	}
}

func TestParsePSI(t *testing.T) {
	pressure, err := ParsePSI(strings.NewReader(psiMemoryFixture))
	if err != nil {
		t.Fatalf("ParsePSI: %v", err)
	}
	if !pressure.HasSome || !pressure.HasFull {
		t.Fatalf("HasSome/HasFull = %v/%v, want true/true", pressure.HasSome, pressure.HasFull)
	}
	if pressure.Some10 != 0.05 || pressure.Some60 != 0.13 || pressure.Some300 != 0.04 {
		t.Fatalf("some avgs = %+v", pressure)
	}
	if pressure.SomeTotalMicros != 123456789 || pressure.FullTotalMicros != 987654 {
		t.Fatalf("totals = %d/%d", pressure.SomeTotalMicros, pressure.FullTotalMicros)
	}
}

func TestParsePSICPUHasNoFull(t *testing.T) {
	pressure, err := ParsePSI(strings.NewReader(psiCPUFixature))
	if err != nil {
		t.Fatalf("ParsePSI: %v", err)
	}
	if pressure.HasFull {
		t.Fatal("HasFull = true for a CPU pressure file")
	}
	if pressure.Some10 != 2.5 {
		t.Fatalf("Some10 = %v, want 2.5", pressure.Some10)
	}
}

func TestParsePSIMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":        "",
		"missing some": "full avg10=0.1 avg60=0.1 avg300=0.1 total=1\n",
		"bad avg":      "some avg10=abc avg60=0.1 avg300=0.1 total=1\n",
		"bad total":    "some avg10=0.1 avg60=0.1 avg300=0.1 total=abc\n",
		"no equals":    "some nonsense\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePSI(strings.NewReader(fixture)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestParseProcStat(t *testing.T) {
	stat, err := ParseProcStat(strings.NewReader(procStatFixture))
	if err != nil {
		t.Fatalf("ParseProcStat: %v", err)
	}
	if stat.User != 123 || stat.Nice != 45 || stat.System != 678 || stat.Idle != 9012 {
		t.Fatalf("stat = %+v", stat)
	}
	if stat.IOWait != 34 || stat.IRQ != 5 || stat.SoftIRQ != 6 || stat.Steal != 7 {
		t.Fatalf("stat = %+v", stat)
	}
	if stat.Guest != 0 || stat.GuestNice != 0 {
		t.Fatalf("guest fields = %d/%d, want 0/0", stat.Guest, stat.GuestNice)
	}
}

func TestParseProcStatMalformed(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"per-cpu only":   "cpu0 1 2 3 4 5 6 7 8 9 10\n",
		"too few fields": "cpu 1 2 3\n",
		"non numeric":    "cpu 1 2 three 4 5\n",
	}
	for name, fixture := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseProcStat(strings.NewReader(fixture)); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestUtilization(t *testing.T) {
	prev := CPUJiffies{User: 10, System: 10, Idle: 80}
	cur := CPUJiffies{User: 20, System: 20, Idle: 160}
	util, iowait, ok := Utilization(prev, cur)
	if !ok {
		t.Fatal("Utilization ok = false")
	}
	if util != 20 || iowait != 0 {
		t.Fatalf("util/iowait = %v/%v, want 20/0", util, iowait)
	}
}

func TestUtilizationIncludesIOWait(t *testing.T) {
	prev := CPUJiffies{Idle: 50, IOWait: 50}
	cur := CPUJiffies{Idle: 50, IOWait: 100}
	util, iowait, ok := Utilization(prev, cur)
	if !ok {
		t.Fatal("Utilization ok = false")
	}
	if util != 100 || iowait != 100 {
		t.Fatalf("util/iowait = %v/%v, want 100/100", util, iowait)
	}
}

func TestUtilizationCounterRegression(t *testing.T) {
	prev := CPUJiffies{Idle: 100}
	cur := CPUJiffies{Idle: 90}
	if _, _, ok := Utilization(prev, cur); ok {
		t.Fatal("ok = true after a counter regression")
	}
	if _, _, ok := Utilization(prev, prev); ok {
		t.Fatal("ok = true for a zero-length interval")
	}
}
