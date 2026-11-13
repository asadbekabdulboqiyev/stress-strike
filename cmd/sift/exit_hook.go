package main

import "os"

// exitProcess terminates the process with the given exit code.
//
// It is a variable rather than a direct os.Exit call so tests can drive the
// command entry points in-process: cmd_verify_test.go historically built the
// real binary and ran it as a subprocess, which exercises behaviour but
// contributes no statement coverage. The tests in cli_cover_test.go swap this
// hook for one that stops the command with a sentinel panic, so every branch
// after the exit point still runs under the race detector.
//
// Production behaviour is unchanged: exitProcess is os.Exit.
var exitProcess = os.Exit
