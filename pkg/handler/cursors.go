package handler

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// Cursor validation constants
const (
	cursorFormatVersion = "1"
	maxPageNumber       = 9999
	minPageNumber       = 1
	cursorPartCount     = 3
)

// ValidatedCursor represents a successfully parsed and validated cursor
type ValidatedCursor struct {
	Version   string
	ChannelID string
	Page      int
}

// ParseAndValidateCursor safely parses base64-encoded cursor with strict bounds checking
func ParseAndValidateCursor(rawCursor string) (*ValidatedCursor, error) {
	// Step 1: Validate input is non-empty
	if rawCursor == "" {
		return nil, fmt.Errorf("cursor cannot be empty")
	}

	// Step 2: Decode from base64 (stops early if invalid)
	decodedCursor, err := base64.StdEncoding.DecodeString(rawCursor)
	if err != nil {
		return nil, fmt.Errorf("cursor decode failed: %w", err)
	}

	// Step 3: Validate decoded content is not empty
	if len(decodedCursor) == 0 {
		return nil, fmt.Errorf("decoded cursor is empty")
	}

	// Step 4: Split by delimiter with exact part count check
	parts := strings.Split(string(decodedCursor), ":")
	if len(parts) != cursorPartCount {
		return nil, fmt.Errorf("invalid cursor format: expected %d parts, got %d",
			cursorPartCount, len(parts))
	}

	// Step 5: Validate and extract version
	version := parts[0]
	if version != cursorFormatVersion {
		return nil, fmt.Errorf("unsupported cursor version: %q", version)
	}

	// Step 6: Validate channel ID format
	channelID := parts[1]
	if !isValidChannelID(channelID) {
		return nil, fmt.Errorf("invalid channel ID in cursor")
	}

	// Step 7: Parse and validate page number
	pageStr := parts[2]
	page, err := strconv.Atoi(pageStr)
	if err != nil {
		return nil, fmt.Errorf("invalid page number in cursor: %w", err)
	}

	// Step 8: Bounds check page number
	if page < minPageNumber || page > maxPageNumber {
		return nil, fmt.Errorf("page number out of valid range [%d, %d]: %d",
			minPageNumber, maxPageNumber, page)
	}

	return &ValidatedCursor{
		Version:   version,
		ChannelID: channelID,
		Page:      page,
	}, nil
}

// isValidChannelID checks if channel ID follows Slack's format
// Slack channel IDs start with C or D (channel or direct message)
// followed by 10 alphanumeric characters (A-Z, 0-9)
func isValidChannelID(channelID string) bool {
	if len(channelID) != 11 {
		return false
	}
	// First character must be C (channel) or D (DM)
	if channelID[0] != 'C' && channelID[0] != 'D' {
		return false
	}
	// Remaining characters must be alphanumeric (A-Z, 0-9)
	for i := 1; i < len(channelID); i++ {
		c := channelID[i]
		if !((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// CreateCursor encodes cursor in validated format
func CreateCursor(channelID string, pageNumber int) (string, error) {
	if !isValidChannelID(channelID) {
		return "", fmt.Errorf("invalid channel ID")
	}
	if pageNumber < minPageNumber || pageNumber > maxPageNumber {
		return "", fmt.Errorf("invalid page number: must be between %d and %d", minPageNumber, maxPageNumber)
	}

	cursorStr := fmt.Sprintf("%s:%s:%d", cursorFormatVersion, channelID, pageNumber)
	return base64.StdEncoding.EncodeToString([]byte(cursorStr)), nil
}
