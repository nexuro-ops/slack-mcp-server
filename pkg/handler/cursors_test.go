package handler

import (
	"encoding/base64"
	"fmt"
	"testing"
)

func TestParseAndValidateCursor_Success(t *testing.T) {
	tests := []struct {
		name         string
		channelID    string
		pageNumber   int
		expectValid  bool
	}{
		{
			name:        "Valid channel cursor page 1",
			channelID:   "C1234567890",
			pageNumber:  1,
			expectValid: true,
		},
		{
			name:        "Valid DM cursor page 1",
			channelID:   "D1234567890",
			pageNumber:  1,
			expectValid: true,
		},
		{
			name:        "Valid cursor max page number",
			channelID:   "C1234567890",
			pageNumber:  maxPageNumber,
			expectValid: true,
		},
		{
			name:        "Valid cursor middle page",
			channelID:   "C1234567890",
			pageNumber:  500,
			expectValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create cursor
			cursor, err := CreateCursor(tt.channelID, tt.pageNumber)
			if err != nil {
				t.Fatalf("CreateCursor failed: %v", err)
			}

			// Parse and validate
			validated, err := ParseAndValidateCursor(cursor)
			if err != nil {
				t.Fatalf("ParseAndValidateCursor failed: %v", err)
			}

			if validated.ChannelID != tt.channelID {
				t.Errorf("expected channel ID %q, got %q", tt.channelID, validated.ChannelID)
			}
			if validated.Page != tt.pageNumber {
				t.Errorf("expected page %d, got %d", tt.pageNumber, validated.Page)
			}
			if validated.Version != cursorFormatVersion {
				t.Errorf("expected version %q, got %q", cursorFormatVersion, validated.Version)
			}
		})
	}
}

func TestParseAndValidateCursor_InvalidCursor(t *testing.T) {
	tests := []struct {
		name          string
		cursor        string
		expectError   bool
		errorContains string
	}{
		{
			name:          "Empty cursor",
			cursor:        "",
			expectError:   true,
			errorContains: "empty",
		},
		{
			name:          "Invalid base64",
			cursor:        "!!!invalid!!!",
			expectError:   true,
			errorContains: "decode failed",
		},
		{
			name:          "Missing parts",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890")),
			expectError:   true,
			errorContains: "expected 3 parts",
		},
		{
			name:          "Too many parts",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890:1:extra")),
			expectError:   true,
			errorContains: "expected 3 parts",
		},
		{
			name:          "Wrong version",
			cursor:        base64.StdEncoding.EncodeToString([]byte("2:C1234567890:1")),
			expectError:   true,
			errorContains: "unsupported cursor version",
		},
		{
			name:          "Invalid channel ID - wrong length",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C12345678:1")),
			expectError:   true,
			errorContains: "invalid channel ID",
		},
		{
			name:          "Invalid channel ID - wrong prefix",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:X1234567890:1")),
			expectError:   true,
			errorContains: "invalid channel ID",
		},
		{
			name:          "Invalid channel ID - lowercase",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:c1234567890:1")),
			expectError:   true,
			errorContains: "invalid channel ID",
		},
		{
			name:          "Invalid channel ID - special chars",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C123456!@#:1")),
			expectError:   true,
			errorContains: "invalid channel ID",
		},
		{
			name:          "Invalid page number - not numeric",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890:abc")),
			expectError:   true,
			errorContains: "invalid page number",
		},
		{
			name:          "Page number too high",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890:10000")),
			expectError:   true,
			errorContains: "out of valid range",
		},
		{
			name:          "Page number zero",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890:0")),
			expectError:   true,
			errorContains: "out of valid range",
		},
		{
			name:          "Page number negative",
			cursor:        base64.StdEncoding.EncodeToString([]byte("1:C1234567890:-1")),
			expectError:   true,
			errorContains: "out of valid range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validated, err := ParseAndValidateCursor(tt.cursor)
			if !tt.expectError {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if validated == nil {
					t.Errorf("expected validated cursor, got nil")
				}
			} else {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

func TestCreateCursor_InvalidInputs(t *testing.T) {
	tests := []struct {
		name          string
		channelID     string
		pageNumber    int
		expectError   bool
		errorContains string
	}{
		{
			name:          "Invalid channel ID",
			channelID:     "INVALID",
			pageNumber:    1,
			expectError:   true,
			errorContains: "invalid channel ID",
		},
		{
			name:          "Page number too high",
			channelID:     "C1234567890",
			pageNumber:    maxPageNumber + 1,
			expectError:   true,
			errorContains: "invalid page number",
		},
		{
			name:          "Page number zero",
			channelID:     "C1234567890",
			pageNumber:    0,
			expectError:   true,
			errorContains: "invalid page number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cursor, err := CreateCursor(tt.channelID, tt.pageNumber)
			if !tt.expectError {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cursor == "" {
					t.Errorf("expected cursor, got empty string")
				}
			} else {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
					t.Errorf("expected error to contain %q, got %q", tt.errorContains, err.Error())
				}
			}
		})
	}
}

func TestIsValidChannelID(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		valid   bool
	}{
		{
			name:  "Valid channel ID",
			id:    "C1234567890",
			valid: true,
		},
		{
			name:  "Valid DM ID",
			id:    "D1234567890",
			valid: true,
		},
		{
			name:  "Wrong length - too short",
			id:    "C123456789",
			valid: false,
		},
		{
			name:  "Wrong length - too long",
			id:    "C12345678901",
			valid: false,
		},
		{
			name:  "Invalid prefix",
			id:    "X1234567890",
			valid: false,
		},
		{
			name:  "Lowercase C prefix",
			id:    "c1234567890",
			valid: false,
		},
		{
			name:  "Contains special chars",
			id:    "C123456!@#",
			valid: false,
		},
		{
			name:  "Contains spaces",
			id:    "C12345 7890",
			valid: false,
		},
		{
			name:  "Empty string",
			id:    "",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidChannelID(tt.id)
			if result != tt.valid {
				t.Errorf("isValidChannelID(%q) = %v, expected %v", tt.id, result, tt.valid)
			}
		})
	}
}

func TestCursorRoundTrip(t *testing.T) {
	// Test that we can create a cursor, encode it, and decode it back to the same values
	tests := []struct {
		channelID  string
		pageNumber int
	}{
		{"C1234567890", 1},
		{"C1234567890", 100},
		{"C1234567890", 9999},
		{"D0987654321", 1},
		{"D0987654321", 500},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_page_%d", tt.channelID, tt.pageNumber), func(t *testing.T) {
			// Create cursor
			cursor, err := CreateCursor(tt.channelID, tt.pageNumber)
			if err != nil {
				t.Fatalf("CreateCursor failed: %v", err)
			}

			// Parse and validate
			validated, err := ParseAndValidateCursor(cursor)
			if err != nil {
				t.Fatalf("ParseAndValidateCursor failed: %v", err)
			}

			// Verify values match
			if validated.ChannelID != tt.channelID {
				t.Errorf("channel ID mismatch: got %q, expected %q", validated.ChannelID, tt.channelID)
			}
			if validated.Page != tt.pageNumber {
				t.Errorf("page number mismatch: got %d, expected %d", validated.Page, tt.pageNumber)
			}
		})
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && s[0:len(substr)] == substr) || (len(s) > len(substr)-1 && contains(s[1:], substr)))
}
