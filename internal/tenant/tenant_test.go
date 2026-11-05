package tenant

import (
	"context"
	"testing"
)

func TestFromContextEmptyForBackground(t *testing.T) {
	// Arrange
	ctx := context.Background()

	// Act
	got := FromContext(ctx)

	// Assert
	if got != "" {
		t.Fatalf("FromContext(background) = %q, want empty string", got)
	}
}

func TestWithContextRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		tenantID string
	}{
		{name: "simple id", tenantID: "t-acme"},
		{name: "uuid-like id", tenantID: "0b8f1f5e-7c1a-4b2f-9d3e-1a2b3c4d5e6f"},
		{name: "empty id", tenantID: ""},
		{name: "unicode id", tenantID: "toshkent-1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Arrange
			ctx := context.Background()

			// Act
			derived := WithContext(ctx, tc.tenantID)

			// Assert
			if got := FromContext(derived); got != tc.tenantID {
				t.Fatalf("FromContext(WithContext(ctx, %q)) = %q", tc.tenantID, got)
			}
			if got := FromContext(ctx); got != "" {
				t.Fatalf("parent context mutated: FromContext(parent) = %q, want empty", got)
			}
		})
	}
}

func TestWithContextInnerWins(t *testing.T) {
	// Arrange
	outer := WithContext(context.Background(), "t-outer")

	// Act
	inner := WithContext(outer, "t-inner")

	// Assert
	if got := FromContext(inner); got != "t-inner" {
		t.Fatalf("FromContext(inner) = %q, want %q", got, "t-inner")
	}
	if got := FromContext(outer); got != "t-outer" {
		t.Fatalf("outer context changed: got %q, want %q", got, "t-outer")
	}
}

// TestFromContextIgnoresNonStringValue covers the type-assertion failure path:
// a foreign value stored under the same key must degrade to "" instead of
// panicking.
func TestFromContextIgnoresNonStringValue(t *testing.T) {
	// Arrange
	ctx := context.WithValue(context.Background(), key, 42)

	// Act
	got := FromContext(ctx)

	// Assert
	if got != "" {
		t.Fatalf("FromContext(non-string value) = %q, want empty string", got)
	}
}

// TestFromContextIgnoresOtherKeys ensures the package key is private and does
// not collide with unrelated context values.
func TestFromContextIgnoresOtherKeys(t *testing.T) {
	type foreignKey struct{}
	ctx := context.WithValue(context.Background(), foreignKey{}, "t-leak")

	if got := FromContext(ctx); got != "" {
		t.Fatalf("FromContext(foreign key) = %q, want empty string", got)
	}
}

// TestWithContextNilParentPanics documents that context.WithValue requires a
// non-nil parent; callers must pass context.Background() or a derived context.
func TestWithContextNilParentPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("WithContext(nil) did not panic")
		}
	}()
	_ = WithContext(nil, "t-x") //nolint:staticcheck // intentional nil parent
}

func BenchmarkWithContext(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = FromContext(WithContext(ctx, "t-bench"))
	}
}
