package main

import (
	"os"

	"github.com/asadbekabdulboqiyev/sift/internal/probe"
)

// cmdHealthcheck implements the `Sift healthcheck` subcommand used by
// container HEALTHCHECK instructions. Distroless images ship no shell, wget or
// curl, so the binary probes itself:
//
//	Sift healthcheck -addr http://127.0.0.1:9090/healthz
//
// It exits 0 when the endpoint answers 2xx and 1 otherwise. The probe logic is
// shared with the master and worker binaries in internal/probe.
func cmdHealthcheck() {
	exitProcess(probe.Run(os.Args[2:], ""))
}
