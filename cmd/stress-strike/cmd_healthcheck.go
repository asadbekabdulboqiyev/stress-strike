package main

import (
	"os"

	"github.com/asadbekabdulboqiyev/stress-strike/internal/probe"
)

// cmdHealthcheck implements the `stress-strike healthcheck` subcommand used by
// container HEALTHCHECK instructions. Distroless images ship no shell, wget or
// curl, so the binary probes itself:
//
//	stress-strike healthcheck -addr http://127.0.0.1:9090/healthz
//
// It exits 0 when the endpoint answers 2xx and 1 otherwise. The probe logic is
// shared with the master and worker binaries in internal/probe.
func cmdHealthcheck() {
	os.Exit(probe.Run(os.Args[2:], ""))
}
