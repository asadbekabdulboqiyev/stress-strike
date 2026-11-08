package auth

import (
	"testing"
)

func TestAuthBrowserConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AuthConfig
		wantErr bool
	}{
		{
			name: "valid browser auth",
			cfg: AuthConfig{
				Type:     AuthBrowser,
				LoginURL: "https://example.com/login",
				Username: "user",
				Password: "pass",
			},
			wantErr: false,
		},
		{
			name: "missing login url",
			cfg: AuthConfig{
				Type:     AuthBrowser,
				Username: "user",
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "missing username",
			cfg: AuthConfig{
				Type:     AuthBrowser,
				LoginURL: "https://example.com/login",
				Password: "pass",
			},
			wantErr: true,
		},
		{
			name: "missing password",
			cfg: AuthConfig{
				Type:     AuthBrowser,
				LoginURL: "https://example.com/login",
				Username: "user",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAuthSession(tt.cfg, 0)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAuthSession() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAuthBrowserString(t *testing.T) {
	if AuthBrowser.String() != "browser" {
		t.Errorf("AuthBrowser.String() = %q, want %q", AuthBrowser.String(), "browser")
	}
}
