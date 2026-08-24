package config

import "testing"

func TestStepProtocolOptionValidation(t *testing.T) {
	cases := []struct {
		name    string
		step    Step
		wantErr bool
	}{
		{
			name: "valid ws binary frame",
			step: Step{Name: "ws", Type: "ws", URL: "ws://h", FrameType: "binary"},
		},
		{
			name:    "invalid frame_type",
			step:    Step{Name: "ws", Type: "ws", URL: "ws://h", FrameType: "gzip"},
			wantErr: true,
		},
		{
			name: "valid grpc_method",
			step: Step{Name: "g", Type: "grpc", URL: "grpc://h", GrpcMethod: "/pkg.Svc/Call"},
		},
		{
			name:    "grpc_method without leading slash",
			step:    Step{Name: "g", Type: "grpc", URL: "grpc://h", GrpcMethod: "pkg.Svc/Call"},
			wantErr: true,
		},
		{
			name: "udp await_response",
			step: Step{Name: "u", Type: "udp", URL: "h:1", AwaitResponse: true},
		},
		{
			name: "tcp session pooling",
			step: Step{Name: "t", Type: "tcp", URL: "h:1", Session: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := &Scenario{
				Name:    t.Name(),
				Profile: Profile{Users: 1, Duration: 1, Timeout: 5},
				Steps:   []Step{tc.step},
			}
			err := sc.Normalize()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Normalize() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
