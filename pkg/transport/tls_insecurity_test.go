package transport

import (
	"os"
	"testing"

	"go.uber.org/zap"
)

func TestParseTLSInsecurityOption_Default(t *testing.T) {
	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
	logger := zap.NewNop()

	option, err := ParseTLSInsecurityOption(logger)

	if err != nil {
		t.Errorf("Expected no error for default, got: %v", err)
	}

	if option.Enabled {
		t.Error("Expected secure (false) by default")
	}

	if option.Source != "default" {
		t.Errorf("Expected source='default', got: %q", option.Source)
	}
}

func TestParseTLSInsecurityOption_ExplicitFalse(t *testing.T) {
	tests := []string{"false", "0", "no", "off"}

	logger := zap.NewNop()

	for _, testVal := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", testVal)

		option, err := ParseTLSInsecurityOption(logger)

		if err != nil {
			t.Errorf("Value %q: expected no error, got: %v", testVal, err)
		}

		if option.Enabled {
			t.Errorf("Value %q: expected secure (false), got enabled=true", testVal)
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_ExplicitTrue(t *testing.T) {
	tests := []string{"true", "1", "yes", "on"}

	logger := zap.NewNop()

	for _, testVal := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", testVal)

		option, err := ParseTLSInsecurityOption(logger)

		if err != nil {
			t.Errorf("Value %q: expected no error, got: %v", testVal, err)
		}

		if !option.Enabled {
			t.Errorf("Value %q: expected insecure (true), got enabled=false", testVal)
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_CaseInsensitive(t *testing.T) {
	tests := []string{"TRUE", "False", "YES", "Off", "TrUe", "nO"}

	logger := zap.NewNop()

	for _, testVal := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", testVal)

		option, err := ParseTLSInsecurityOption(logger)

		if err != nil {
			t.Errorf("Value %q: expected no error, got: %v", testVal, err)
		}

		// Just verify it parses successfully - exact value depends on the case
		if option.Source == "" {
			t.Errorf("Value %q: expected non-empty source", testVal)
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_WithWhitespace(t *testing.T) {
	tests := []struct {
		value   string
		enabled bool
	}{
		{"  true  ", true},
		{" false ", false},
		{"\ttrue\t", true},
		{"\nfalse\n", false},
	}

	logger := zap.NewNop()

	for _, tt := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", tt.value)

		option, err := ParseTLSInsecurityOption(logger)

		if err != nil {
			t.Errorf("Value %q: expected no error, got: %v", tt.value, err)
		}

		if option.Enabled != tt.enabled {
			t.Errorf("Value %q: expected enabled=%v, got %v", tt.value, tt.enabled, option.Enabled)
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_InvalidValues(t *testing.T) {
	tests := []string{
		"invalid",
		"maybe",
		"nope",
		"anything-else",
		"2",
		"-1",
		"disable",
		"enable",
		"insecure",
		"secure",
		"y",
		"n",
	}

	logger := zap.NewNop()

	for _, testVal := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", testVal)

		_, err := ParseTLSInsecurityOption(logger)

		if err == nil {
			t.Errorf("Value %q: expected error, got nil", testVal)
		}

		if err.Error() == "" {
			t.Errorf("Value %q: expected non-empty error message", testVal)
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_ErrorMessage(t *testing.T) {
	os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", "invalid_value")
	logger := zap.NewNop()

	_, err := ParseTLSInsecurityOption(logger)

	if err == nil {
		t.Error("Expected error for invalid value")
	}

	errMsg := err.Error()

	// Verify error message contains helpful information
	if errMsg != "invalid SLACK_MCP_SERVER_CA_INSECURE value: \"invalid_value\" (must be one of: true, false, 1, 0, yes, no, on, off)" {
		t.Errorf("Error message format unexpected: %s", errMsg)
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestTLSInsecurityOption_SourceTracking(t *testing.T) {
	tests := []struct {
		value         string
		expectedInSrc bool
	}{
		{"true", true},
		{"false", true},
		{"1", true},
		{"0", true},
	}

	logger := zap.NewNop()

	for _, tt := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", tt.value)

		option, _ := ParseTLSInsecurityOption(logger)

		if option.Source == "default" {
			t.Errorf("Value %q: expected non-default source, got 'default'", tt.value)
		}

		if tt.expectedInSrc && tt.value != "" {
			if option.Source == "" {
				t.Errorf("Value %q: expected source to contain value info", tt.value)
			}
		}
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_MultipleInvocations(t *testing.T) {
	os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", "true")
	logger := zap.NewNop()

	option1, _ := ParseTLSInsecurityOption(logger)
	option2, _ := ParseTLSInsecurityOption(logger)

	if option1.Enabled != option2.Enabled {
		t.Error("Expected consistent results across multiple invocations")
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_EmptyStringIsSecure(t *testing.T) {
	os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", "")
	logger := zap.NewNop()

	option, err := ParseTLSInsecurityOption(logger)

	if err != nil {
		t.Errorf("Expected no error for empty string, got: %v", err)
	}

	if option.Enabled {
		t.Error("Expected empty string to mean secure (false)")
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}

func TestParseTLSInsecurityOption_WithLogger(t *testing.T) {
	config := zap.NewDevelopmentConfig()
	logger, err := config.Build()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", "invalid")

	// Should not panic with real logger
	_, err = ParseTLSInsecurityOption(logger)

	if err == nil {
		t.Error("Expected error for invalid value")
	}

	os.Unsetenv("SLACK_MCP_SERVER_CA_INSECURE")
}
