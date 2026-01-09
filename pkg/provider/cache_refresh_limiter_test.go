package provider

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// TestCalculateBackoff tests exponential backoff calculation
func TestCalculateBackoff(t *testing.T) {
	ap := &ApiProvider{
		logger: zap.NewNop(),
		backoffConfig: BackoffConfig{
			InitialDelay: 1 * time.Second,
			MaxDelay:     60 * time.Second,
			Multiplier:   2.0,
			MaxRetries:   3,
		},
	}

	tests := []struct {
		retryCount int
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{0, 1 * time.Second, 1 * time.Second},
		{1, 2 * time.Second, 2 * time.Second},
		{2, 4 * time.Second, 4 * time.Second},
		{3, 60 * time.Second, 60 * time.Second}, // At MaxRetries, caps at MaxDelay
		{4, 60 * time.Second, 60 * time.Second}, // Beyond MaxRetries, stays at MaxDelay
	}

	for _, tt := range tests {
		backoff := ap.calculateBackoff(tt.retryCount)
		if backoff < tt.expectedMin || backoff > tt.expectedMax {
			t.Errorf("Retry %d: expected %v-%v, got %v",
				tt.retryCount, tt.expectedMin, tt.expectedMax, backoff)
		}
	}
}

// TestRetryCountTracking tests retry count increment and reset
func TestRetryCountTracking(t *testing.T) {
	ap := &ApiProvider{
		logger:         zap.NewNop(),
		refreshRetries: make(map[string]int),
		retryMu:        sync.RWMutex{},
	}

	// Initial should be 0
	if count := ap.getRetryCount("users"); count != 0 {
		t.Errorf("Expected initial retry count 0, got %d", count)
	}

	// Increment
	ap.incrementRetryCount("users")
	if count := ap.getRetryCount("users"); count != 1 {
		t.Errorf("Expected retry count 1 after increment, got %d", count)
	}

	// Multiple increments
	ap.incrementRetryCount("users")
	ap.incrementRetryCount("users")
	if count := ap.getRetryCount("users"); count != 3 {
		t.Errorf("Expected retry count 3 after multiple increments, got %d", count)
	}

	// Reset
	ap.resetRetryCount("users")
	if count := ap.getRetryCount("users"); count != 0 {
		t.Errorf("Expected retry count 0 after reset, got %d", count)
	}
}

// TestIsSlackRateLimitError tests detection of Slack rate limit errors
func TestIsSlackRateLimitError(t *testing.T) {
	tests := []struct {
		err       error
		isRateErr bool
	}{
		{nil, false},
		{errors.New("some other error"), false},
		{errors.New("rate_limited"), true},
		{errors.New("rate limit exceeded"), true},
		{errors.New("429 Too Many Requests"), true},
		{errors.New("connection failed"), false},
	}

	for _, tt := range tests {
		result := isSlackRateLimitError(tt.err)
		if result != tt.isRateErr {
			t.Errorf("Error %v: expected isRateErr=%v, got %v", tt.err, tt.isRateErr, result)
		}
	}
}

// TestRefreshLimiterEnforced tests that refresh limiter blocks requests
func TestRefreshLimiterEnforced(t *testing.T) {
	// Create a limiter that only allows 0.5 requests per second (1 per 2 seconds)
	refreshLimiter := rate.NewLimiter(0.5, 1)

	// First request should be allowed
	if !refreshLimiter.Allow() {
		t.Error("Expected first refresh to be allowed")
	}

	// Second request should be rejected (not enough time elapsed)
	if refreshLimiter.Allow() {
		t.Error("Expected second refresh to be rate limited")
	}

	// After waiting, should be allowed again
	time.Sleep(2100 * time.Millisecond)
	if !refreshLimiter.Allow() {
		t.Error("Expected refresh to be allowed after backoff period")
	}
}

// TestConcurrentRetryCountAccess tests thread-safe retry count access
func TestConcurrentRetryCountAccess(t *testing.T) {
	ap := &ApiProvider{
		logger:         zap.NewNop(),
		refreshRetries: make(map[string]int),
		retryMu:        sync.RWMutex{},
	}

	done := make(chan bool)
	errors := make(chan error, 10)

	// Concurrent increments
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				ap.incrementRetryCount("users")
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have count of 1000 (10 goroutines * 100 increments)
	count := ap.getRetryCount("users")
	if count != 1000 {
		t.Errorf("Expected retry count 1000 after concurrent increments, got %d", count)
	}

	close(errors)
}

// TestBackoffConfigDefaults tests that default backoff config is reasonable
func TestBackoffConfigDefaults(t *testing.T) {
	if DefaultRefreshRate != 1 {
		t.Errorf("DefaultRefreshRate should be 1, got %d", DefaultRefreshRate)
	}

	if DefaultRefreshBurst != 2 {
		t.Errorf("DefaultRefreshBurst should be 2, got %d", DefaultRefreshBurst)
	}

	if DefaultInitialBackoff != 1*time.Second {
		t.Errorf("DefaultInitialBackoff should be 1s, got %v", DefaultInitialBackoff)
	}

	if DefaultMaxBackoff != 60*time.Second {
		t.Errorf("DefaultMaxBackoff should be 60s, got %v", DefaultMaxBackoff)
	}

	if DefaultBackoffMultiplier != 2.0 {
		t.Errorf("DefaultBackoffMultiplier should be 2.0, got %v", DefaultBackoffMultiplier)
	}

	if DefaultMaxRetries != 3 {
		t.Errorf("DefaultMaxRetries should be 3, got %d", DefaultMaxRetries)
	}
}

// TestMultipleOperationRetryTracking tests independent retry tracking for different operations
func TestMultipleOperationRetryTracking(t *testing.T) {
	ap := &ApiProvider{
		logger:         zap.NewNop(),
		refreshRetries: make(map[string]int),
		retryMu:        sync.RWMutex{},
	}

	// Increment users retries
	ap.incrementRetryCount("users")
	ap.incrementRetryCount("users")

	// Increment channels retries
	ap.incrementRetryCount("channels")

	// Check counts are independent
	if usersCount := ap.getRetryCount("users"); usersCount != 2 {
		t.Errorf("Expected users retry count 2, got %d", usersCount)
	}

	if channelsCount := ap.getRetryCount("channels"); channelsCount != 1 {
		t.Errorf("Expected channels retry count 1, got %d", channelsCount)
	}

	// Reset one should not affect the other
	ap.resetRetryCount("users")
	if usersCount := ap.getRetryCount("users"); usersCount != 0 {
		t.Errorf("Expected users retry count 0 after reset, got %d", usersCount)
	}

	if channelsCount := ap.getRetryCount("channels"); channelsCount != 1 {
		t.Errorf("Expected channels retry count 1 (unchanged), got %d", channelsCount)
	}
}

// TestBackoffCapAtMaxDelay tests that backoff calculation caps at MaxDelay
func TestBackoffCapAtMaxDelay(t *testing.T) {
	ap := &ApiProvider{
		logger: zap.NewNop(),
		backoffConfig: BackoffConfig{
			InitialDelay: 1 * time.Second,
			MaxDelay:     10 * time.Second, // Set max lower for easier testing
			Multiplier:   2.0,
			MaxRetries:   10,
		},
	}

	// Test exponential growth up to max
	for i := 0; i < 20; i++ {
		backoff := ap.calculateBackoff(i)
		if backoff > ap.backoffConfig.MaxDelay {
			t.Errorf("Backoff %d exceeded MaxDelay: %v > %v",
				i, backoff, ap.backoffConfig.MaxDelay)
		}
	}

	// Explicitly test that a very high retry count returns MaxDelay
	backoff := ap.calculateBackoff(100)
	if backoff != ap.backoffConfig.MaxDelay {
		t.Errorf("Expected backoff to cap at MaxDelay (%v), got %v",
			ap.backoffConfig.MaxDelay, backoff)
	}
}

// Mock SlackAPI for testing
type mockSlackAPI struct{}

func (m *mockSlackAPI) AuthTest() (*interface{}, error) {
	return nil, nil
}

func (m *mockSlackAPI) AuthTestContext(ctx context.Context) (*interface{}, error) {
	return nil, nil
}

func (m *mockSlackAPI) GetUsersContext(ctx context.Context, options ...interface{}) (interface{}, error) {
	return nil, nil
}

func (m *mockSlackAPI) GetUsersInfo(users ...string) (*interface{}, error) {
	return nil, nil
}

func (m *mockSlackAPI) PostMessageContext(ctx context.Context, channel string, options ...interface{}) (string, string, error) {
	return "", "", nil
}

func (m *mockSlackAPI) MarkConversationContext(ctx context.Context, channel, ts string) error {
	return nil
}

func (m *mockSlackAPI) GetConversationHistoryContext(ctx context.Context, params *interface{}) (*interface{}, error) {
	return nil, nil
}

func (m *mockSlackAPI) GetConversationRepliesContext(ctx context.Context, params *interface{}) (interface{}, bool, string, error) {
	return nil, false, "", nil
}

func (m *mockSlackAPI) SearchContext(ctx context.Context, query string, params interface{}) (*interface{}, *interface{}, error) {
	return nil, nil, nil
}

func (m *mockSlackAPI) GetConversationsContext(ctx context.Context, params *interface{}) (interface{}, string, error) {
	return nil, "", nil
}

func (m *mockSlackAPI) ClientUserBoot(ctx context.Context) (*interface{}, error) {
	return nil, nil
}
