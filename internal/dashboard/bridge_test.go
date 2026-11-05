package dashboard

import (
	"testing"
)

func TestNewEngineBridge(t *testing.T) {
	srv := NewServer()
	bridge := NewEngineBridge(srv)
	if bridge == nil {
		t.Fatal("NewEngineBridge returned nil")
	}
	if bridge.server != srv {
		t.Error("bridge.server not set")
	}
	if bridge.statusCodes == nil {
		t.Error("bridge.statusCodes not initialized")
	}
	if bridge.stopCh == nil {
		t.Error("bridge.stopCh not initialized")
	}
}
