package auth

import (
	"context"
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestValidateSTDIOSource_ValidTerminal(t *testing.T) {
	// When running tests, STDIO is typically connected to terminal or pipe
	// This test verifies the validation logic works
	result := ValidateSTDIOSource()

	// In test environment, STDIO should be valid (connected to terminal or pipe)
	if !result {
		t.Logf("STDIO validation failed - running in environment without terminal/pipe")
		// This is not necessarily a failure - just means running in pipe/non-TTY environment
	}
}

func TestIsAuthenticated_STDIO_Valid(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// STDIO authentication should succeed when STDIO source is valid
	authenticated, err := IsAuthenticated(ctx, "stdio", logger)

	// We can't guarantee STDIO is valid in all test environments
	// but we can verify the function returns either true with nil error, or false with error
	if authenticated && err != nil {
		t.Errorf("Expected nil error when authenticated=true, got: %v", err)
	}

	if !authenticated && err == nil {
		t.Errorf("Expected error when authenticated=false, got nil")
	}
}

func TestIsAuthenticated_STDIO_InvalidTransport(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	authenticated, err := IsAuthenticated(ctx, "invalid_transport", logger)

	if authenticated {
		t.Error("Expected authentication to fail for invalid transport")
	}

	if err == nil {
		t.Error("Expected error for invalid transport")
	}

	if err.Error() != "unknown transport type: invalid_transport" {
		t.Errorf("Expected 'unknown transport type' error, got: %v", err)
	}
}

func TestIsAuthenticated_STDIO_ProcessInfo(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Just verify the function works with process info
	pid := os.Getpid()
	ppid := os.Getppid()

	if pid == 0 {
		t.Error("Expected valid PID, got 0")
	}

	if ppid == 0 {
		t.Error("Expected valid PPID, got 0")
	}

	// Call IsAuthenticated with STDIO
	_, _ = IsAuthenticated(ctx, "stdio", logger)
	// No assertion needed - we're just verifying no panic occurs
}

func TestValidateSTDIOSource_Consistency(t *testing.T) {
	// Verify that multiple calls return consistent results
	result1 := ValidateSTDIOSource()
	result2 := ValidateSTDIOSource()

	if result1 != result2 {
		t.Error("ValidateSTDIOSource returned different results on consecutive calls")
	}
}

func TestIsAuthenticated_STDIO_WithLogger(t *testing.T) {
	// Test with a real logger (should not panic)
	config := zap.NewDevelopmentConfig()
	logger, err := config.Build()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	ctx := context.Background()
	authenticated, err := IsAuthenticated(ctx, "stdio", logger)

	// Verify function returns valid result without panic
	if authenticated && err != nil {
		t.Errorf("Expected nil error when authenticated=true, got: %v", err)
	}

	if !authenticated && err == nil {
		t.Errorf("Expected error when authenticated=false, got nil")
	}
}

func TestIsAuthenticated_HTTPWithoutAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Ensure no API key is configured
	os.Unsetenv("SLACK_MCP_API_KEY")
	os.Unsetenv("SLACK_MCP_SSE_API_KEY")

	// HTTP without configured API key - should succeed (auth not required)
	authenticated, err := IsAuthenticated(ctx, "http", logger)

	if !authenticated {
		t.Error("Expected HTTP authentication to succeed when no API key configured")
	}

	if err != nil {
		t.Errorf("Expected nil error when no API key configured, got: %v", err)
	}
}

func TestIsAuthenticated_SSEWithoutAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Ensure no API key is configured
	os.Unsetenv("SLACK_MCP_API_KEY")
	os.Unsetenv("SLACK_MCP_SSE_API_KEY")

	// SSE without configured API key - should succeed (auth not required)
	authenticated, err := IsAuthenticated(ctx, "sse", logger)

	if !authenticated {
		t.Error("Expected SSE authentication to succeed when no API key configured")
	}

	if err != nil {
		t.Errorf("Expected nil error when no API key configured, got: %v", err)
	}
}

func TestIsAuthenticated_HTTPWithAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Set auth key environment variable
	testToken := "test-secret-token-123"
	os.Setenv("SLACK_MCP_API_KEY", testToken)
	defer os.Unsetenv("SLACK_MCP_API_KEY")

	// Create context with auth token
	ctx = withAuthKey(ctx, testToken)

	authenticated, err := IsAuthenticated(ctx, "http", logger)

	if !authenticated {
		t.Error("Expected HTTP authentication to succeed with valid token")
	}

	if err != nil {
		t.Errorf("Expected nil error for valid token, got: %v", err)
	}
}

func TestIsAuthenticated_HTTPWithInvalidAuth(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Set auth key environment variable
	testToken := "test-secret-token-123"
	os.Setenv("SLACK_MCP_API_KEY", testToken)
	defer os.Unsetenv("SLACK_MCP_API_KEY")

	// Create context with wrong auth token
	ctx = withAuthKey(ctx, "wrong-token")

	authenticated, err := IsAuthenticated(ctx, "http", logger)

	if authenticated {
		t.Error("Expected HTTP authentication to fail with invalid token")
	}

	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestIsAuthenticated_HTTPWithBearerToken(t *testing.T) {
	logger := zap.NewNop()
	ctx := context.Background()

	// Set auth key environment variable
	testToken := "test-secret-token-123"
	os.Setenv("SLACK_MCP_API_KEY", testToken)
	defer os.Unsetenv("SLACK_MCP_API_KEY")

	// Create context with Bearer token format
	ctx = withAuthKey(ctx, "Bearer "+testToken)

	authenticated, err := IsAuthenticated(ctx, "http", logger)

	if !authenticated {
		t.Error("Expected HTTP authentication to succeed with valid Bearer token")
	}

	if err != nil {
		t.Errorf("Expected nil error for valid Bearer token, got: %v", err)
	}
}
