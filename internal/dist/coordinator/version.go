package coordinator

// Version is the control-plane version advertised by master and worker. It can
// be overridden at build time via -ldflags, and by the command binaries.
var Version = "0.14.2"
