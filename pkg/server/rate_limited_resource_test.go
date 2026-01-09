package server

import (
	"context"
	"errors"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func TestRateLimitedResourceHandler_AllowsFirstRequest(t *testing.T) {
	logger := zap.NewNop()
	requestCount := 0

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		requestCount++
		return []mcp.ResourceContents{}, nil
	}

	limiter := rate.NewLimiter(1, 1) // 1 RPS, 1 burst
	handler := NewRateLimitedResourceHandler("test", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	result, err := handler(ctx, request)

	if err != nil {
		t.Errorf("Expected first request to succeed, got error: %v", err)
	}

	if requestCount != 1 {
		t.Errorf("Expected handler to be called once, was called %d times", requestCount)
	}

	if result == nil {
		t.Error("Expected non-nil result")
	}
}

func TestRateLimitedResourceHandler_RateLimits(t *testing.T) {
	logger := zap.NewNop()
	requestCount := 0

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		requestCount++
		return []mcp.ResourceContents{}, nil
	}

	// 1 RPS with burst of 1 - second request should be rate limited
	limiter := rate.NewLimiter(1, 1)
	handler := NewRateLimitedResourceHandler("test", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	// First request should succeed
	_, err := handler(ctx, request)
	if err != nil {
		t.Errorf("Expected first request to succeed, got error: %v", err)
	}

	// Second request should be rate limited
	_, err = handler(ctx, request)
	if err == nil {
		t.Error("Expected second request to be rate limited")
	}

	if err != nil && err.Error() == "" {
		t.Error("Expected non-empty error message for rate limit")
	}

	// Handler should only be called once (first request)
	if requestCount != 1 {
		t.Errorf("Expected handler to be called once, was called %d times", requestCount)
	}
}

func TestRateLimitedResourceHandler_CallsUnderlyingHandler(t *testing.T) {
	logger := zap.NewNop()
	handlerCalled := false
	expectedResult := []mcp.ResourceContents{
		&mcp.TextResourceContents{
			URI:      "test://resource",
			MIMEType: "text/plain",
		},
	}

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		handlerCalled = true
		return expectedResult, nil
	}

	limiter := rate.NewLimiter(1000, 1000) // High limit - won't trigger
	handler := NewRateLimitedResourceHandler("test", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	result, err := handler(ctx, request)

	if !handlerCalled {
		t.Error("Expected underlying handler to be called")
	}

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	if len(result) != len(expectedResult) {
		t.Errorf("Expected %d results, got %d", len(expectedResult), len(result))
	}
}

func TestRateLimitedResourceHandler_PropagatehHandlerError(t *testing.T) {
	logger := zap.NewNop()
	expectedErr := errors.New("handler error")

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return nil, expectedErr
	}

	limiter := rate.NewLimiter(1000, 1000) // High limit - won't trigger
	handler := NewRateLimitedResourceHandler("test", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	result, err := handler(ctx, request)

	if err != expectedErr {
		t.Errorf("Expected error %v, got %v", expectedErr, err)
	}

	if result != nil {
		t.Error("Expected nil result when error occurs")
	}
}

func TestRateLimitedResourceHandler_BurstAllowsMultipleRequests(t *testing.T) {
	logger := zap.NewNop()
	requestCount := 0

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		requestCount++
		return []mcp.ResourceContents{}, nil
	}

	// 1 RPS with burst of 3 - first 3 requests should succeed
	limiter := rate.NewLimiter(1, 3)
	handler := NewRateLimitedResourceHandler("test", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	// First 3 requests should succeed (burst)
	for i := 0; i < 3; i++ {
		_, err := handler(ctx, request)
		if err != nil {
			t.Errorf("Request %d: expected success, got error: %v", i+1, err)
		}
	}

	// Fourth request should be rate limited
	_, err := handler(ctx, request)
	if err == nil {
		t.Error("Expected fourth request to be rate limited")
	}

	if requestCount != 3 {
		t.Errorf("Expected handler to be called 3 times, was called %d times", requestCount)
	}
}

func TestRateLimitedResourceHandler_LogsRateLimitWarning(t *testing.T) {
	config := zap.NewDevelopmentConfig()
	logger, err := config.Build()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	mockHandler := func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{}, nil
	}

	// 1 RPS with burst of 1 - second request will be rate limited
	limiter := rate.NewLimiter(1, 1)
	handler := NewRateLimitedResourceHandler("test-resource", mockHandler, limiter, logger)

	ctx := context.Background()
	request := mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{
			URI: "test://resource",
		},
	}

	// First request succeeds
	handler(ctx, request)

	// Second request triggers rate limit (logs warning)
	_, err = handler(ctx, request)

	// Should not panic when logging with real logger
	if err == nil {
		t.Error("Expected rate limit error")
	}
}
