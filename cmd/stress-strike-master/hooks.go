package main

import (
	"log"
	"os"
)

// Test seams. Production uses the real process/log exits; tests swap these for
// panics so a failure path can be asserted without killing the test binary.
var (
	exitProcess = os.Exit
	fatal       = log.Fatal
	fatalf      = log.Fatalf
)
