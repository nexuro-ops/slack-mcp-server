# Phase 2: Architecture & Design - High Priority Issues Resolution

**Document Version:** 1.0
**Status:** Design Phase (Ready for Implementation)
**Target Completion:** Implementation Phase 3
**Reviewer:** Architecture Design Review

---

## Executive Summary

This document provides comprehensive architectural designs for resolving 5 high-priority security and reliability issues in the Slack MCP Server. These issues address API rate limiting enforcement, TLS configuration robustness, resource endpoint security, and authentication consistency.

**High Priority Issues to Address:**
1. No Concurrency Limits on Cache Refresh
2. Silent TLS Configuration Failures
3. No Rate Limiting on Resource Endpoints
4. Missing Authentication on Resource Handlers (STDIO)
5. Uncontrolled TLS Insecurity Option

---

## 1. HIGH PRIORITY ISSUE #1: No Concurrency Limits on Cache Refresh

### Problem Analysis

**Location:** `pkg/provider/api.go:140-150, 474-645`

**Current State:**
```go
type ApiProvider struct {
	// ... existing fields ...
	rateLimiter *rate.Limiter  // ✅ EXISTS but UNUSED!
}

func (ap *ApiProvider) RefreshUsers(ctx context.Context) error {
	// ❌ NO rate limiting check before API calls
	list, err := ap.client.GetUsers(ctx)
	if err != nil {
		return fmt.Errorf("users list: %w", err)
	}
	// ... process results ...
}

func (ap *ApiProvider) RefreshChannels(ctx context.Context) error {
	// ❌ NO rate limiting check before API calls
	list, err := ap.client.GetChannelsContext(ctx)
	if err != nil {
		return fmt.Errorf("channels list: %w", err)
	}
	// ... process results ...
}
```

**Root Cause:**
- `rateLimiter` field initialized during provider creation but never invoked
- Multiple concurrent refresh calls can bypass rate limiting
- No backpressure mechanism for cache refresh operations
- Slack API rate limit headers (X-Rate-Limit-Remaining) not inspected

**Vulnerability Impact:**
- **API Rate Limit Exhaustion**: Uncontrolled concurrent refreshes exhaust Slack API quota
- **Service Degradation**: Once quota exhausted, all Slack operations fail
- **DDoS Exposure**: Attacker could trigger cache refreshes via rapid requests
- **Cascading Failures**: Failed refreshes don't retry; cache becomes stale

### Design Solution

**Architecture Pattern:** Distributed Rate Limiting with Adaptive Backoff

#### Step 1: Enhanced Rate Limiter Configuration

```go
type ApiProvider struct {
	// ... existing fields ...

	// Rate limiting configuration
	rateLimiter    *rate.Limiter
	refreshLimiter *rate.Limiter  // Separate limiter for cache refresh
	backoffConfig  BackoffConfig

	// Retry state
	refreshRetries map[string]int  // Track retry counts per operation
	retryMu        sync.RWMutex
}

type BackoffConfig struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	MaxRetries   int
}

// Recommended configuration
const (
	DefaultRefreshRate = 1  // 1 refresh per second (conservative)
	DefaultRefreshBurst = 2 // Allow burst of 2 for failover scenarios

	DefaultInitialBackoff = 1 * time.Second
	DefaultMaxBackoff = 60 * time.Second
	DefaultBackoffMultiplier = 2.0
	DefaultMaxRetries = 3
)
```

#### Step 2: Rate Limit Enforcement in Refresh Methods

```go
func (ap *ApiProvider) RefreshUsers(ctx context.Context) error {
	// Step 1: Acquire rate limit token (blocks until available)
	if !ap.refreshLimiter.Allow() {
		ap.logger.Warn("Cache refresh rate limit exceeded",
			zap.String("operation", "refresh_users"))
		return fmt.Errorf("rate limit exceeded for user cache refresh")
	}

	// Step 2: Implement exponential backoff retry logic
	retryCount := ap.getRetryCount("users")
	backoff := ap.calculateBackoff(retryCount)

	// Step 3: Make API call with timeout
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := ap.client.GetUsers(ctx)
	if err != nil {
		// Step 4: Check for rate limit errors
		if isSlackRateLimitError(err) {
			ap.incrementRetryCount("users")
			ap.logger.Error("Slack rate limit hit during user refresh",
				zap.Error(err),
				zap.Int("retry_count", retryCount),
				zap.Duration("backoff", backoff))
			return fmt.Errorf("slack rate limited: %w", err)
		}
		return fmt.Errorf("users list: %w", err)
	}

	// Step 5: Reset retry counter on success
	ap.resetRetryCount("users")

	// ... process results ...
}

func (ap *ApiProvider) RefreshChannels(ctx context.Context) error {
	// Same pattern as RefreshUsers
	if !ap.refreshLimiter.Allow() {
		ap.logger.Warn("Cache refresh rate limit exceeded",
			zap.String("operation", "refresh_channels"))
		return fmt.Errorf("rate limit exceeded for channel cache refresh")
	}

	retryCount := ap.getRetryCount("channels")
	backoff := ap.calculateBackoff(retryCount)

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	list, err := ap.client.GetChannelsContext(ctx)
	if err != nil {
		if isSlackRateLimitError(err) {
			ap.incrementRetryCount("channels")
			ap.logger.Error("Slack rate limit hit during channel refresh",
				zap.Error(err),
				zap.Int("retry_count", retryCount),
				zap.Duration("backoff", backoff))
			return fmt.Errorf("slack rate limited: %w", err)
		}
		return fmt.Errorf("channels list: %w", err)
	}

	ap.resetRetryCount("channels")

	// ... process results ...
}
```

#### Step 3: Helper Functions

```go
func (ap *ApiProvider) calculateBackoff(retryCount int) time.Duration {
	if retryCount >= ap.backoffConfig.MaxRetries {
		return ap.backoffConfig.MaxDelay
	}

	backoff := time.Duration(float64(ap.backoffConfig.InitialDelay) *
		math.Pow(ap.backoffConfig.Multiplier, float64(retryCount)))

	if backoff > ap.backoffConfig.MaxDelay {
		backoff = ap.backoffConfig.MaxDelay
	}

	return backoff
}

func (ap *ApiProvider) getRetryCount(operation string) int {
	ap.retryMu.RLock()
	defer ap.retryMu.RUnlock()
	return ap.refreshRetries[operation]
}

func (ap *ApiProvider) incrementRetryCount(operation string) {
	ap.retryMu.Lock()
	defer ap.retryMu.Unlock()
	ap.refreshRetries[operation]++
}

func (ap *ApiProvider) resetRetryCount(operation string) {
	ap.retryMu.Lock()
	defer ap.retryMu.Unlock()
	ap.refreshRetries[operation] = 0
}

func isSlackRateLimitError(err error) bool {
	// Check for Slack's specific rate limit error indicators
	if err == nil {
		return false
	}

	errStr := err.Error()
	return strings.Contains(errStr, "rate_limited") ||
		strings.Contains(errStr, "rate limit") ||
		strings.Contains(errStr, "429")
}
```

#### Step 4: Initialization in Provider

```go
func New(transport string, logger *zap.Logger) *ApiProvider {
	// ... existing initialization ...

	ap := &ApiProvider{
		// ... existing fields ...
		rateLimiter:    rate.NewLimiter(1, 10),      // 1 RPS, burst 10
		refreshLimiter: rate.NewLimiter(
			rate.Limit(DefaultRefreshRate),
			DefaultRefreshBurst),
		backoffConfig: BackoffConfig{
			InitialDelay: DefaultInitialBackoff,
			MaxDelay: DefaultMaxBackoff,
			Multiplier: DefaultBackoffMultiplier,
			MaxRetries: DefaultMaxRetries,
		},
		refreshRetries: make(map[string]int),
	}

	return ap
}
```

### Success Criteria

- ✅ Cache refresh operations respect rate limiter
- ✅ Concurrent refresh requests are serialized/limited
- ✅ Slack rate limit errors trigger exponential backoff
- ✅ Retry counts tracked per operation type
- ✅ Maximum 3 retries before giving up
- ✅ Logs indicate rate limit hits and backoff timing
- ✅ `go test -race` shows no race conditions on refreshRetries map

### Testing Strategy

```go
// Test concurrent refresh attempts
func TestRefreshUsersRateLimited(t *testing.T) {
	ap := NewProviderWithLimiter(
		rate.NewLimiter(0.5, 1)) // 0.5 RPS - allows 1 per 2 seconds

	start := time.Now()

	// Attempt 2 concurrent refreshes
	go ap.RefreshUsers(context.Background())
	time.Sleep(100*time.Millisecond)
	go ap.RefreshUsers(context.Background())

	elapsed := time.Since(start)

	// Should take > 2 seconds due to rate limiting
	if elapsed < 2*time.Second {
		t.Errorf("Expected rate limiting delay, got %v", elapsed)
	}
}

// Test backoff on rate limit errors
func TestBackoffExponential(t *testing.T) {
	ap := NewProviderWithBackoffConfig(BackoffConfig{
		InitialDelay: 1*time.Second,
		MaxDelay: 60*time.Second,
		Multiplier: 2.0,
		MaxRetries: 3,
	})

	tests := []struct {
		retry int
		expectedMin time.Duration
		expectedMax time.Duration
	}{
		{0, 1*time.Second, 1*time.Second},
		{1, 2*time.Second, 2*time.Second},
		{2, 4*time.Second, 4*time.Second},
		{3, 8*time.Second, 8*time.Second},
	}

	for _, tt := range tests {
		backoff := ap.calculateBackoff(tt.retry)
		if backoff < tt.expectedMin || backoff > tt.expectedMax {
			t.Errorf("Retry %d: expected %v-%v, got %v",
				tt.retry, tt.expectedMin, tt.expectedMax, backoff)
		}
	}
}
```

---

## 2. HIGH PRIORITY ISSUE #2: Silent TLS Configuration Failures

### Problem Analysis

**Location:** `pkg/transport/transport.go:359-374, 396-430`

**Current State:**
```go
func (t *Transport) buildHTTPClient() {
	// ... code ...

	// Certificate appending failures silently ignored
	if toolkitPEM != "" {
		if ok := rootCAs.AppendCertsFromPEM([]byte(toolkitPEM)); !ok {
			t.logger.Warn("Failed to append toolkit certificate")  // ⚠️ WARN only
		}
	}

	if customCA != "" {
		if ok := rootCAs.AppendCertsFromPEM([]byte(customCA)); !ok {
			t.logger.Warn("Failed to append custom CA certificate")  // ⚠️ WARN only
		}
	}

	// ❌ CONTINUES EXECUTION with incomplete cert bundle!
	tlsConfig := &tls.Config{
		RootCAs: rootCAs,
	}
}
```

**Root Cause:**
- Failed certificate append operations log WARNING but continue execution
- Function doesn't validate cert bundle before use
- Incomplete/missing certificates silently create insecure connections
- No fallback or user notification mechanism

**Vulnerability Impact:**
- **Silent TLS Downgrade**: Connections proceed without required certs
- **Man-in-the-Middle Risk**: Missing custom CAs allow unauthorized intermediaries
- **Compliance Violation**: Certificate validation requirements not enforced
- **Hard to Debug**: Failures only visible in WARN logs, easy to miss

### Design Solution

**Architecture Pattern:** Fail-Fast Certificate Validation with Explicit Audit Trail

#### Step 1: Certificate Validation Structure

```go
type CertificateBundle struct {
	SystemCAs       *x509.CertPool // System CA certificates
	CustomCAs       *x509.CertPool // Custom CA certificates
	ToolkitCerts    []*x509.Certificate

	// Validation tracking
	ValidationErrors []CertValidationError
	IsValid          bool
}

type CertValidationError struct {
	Source    string // "toolkit", "custom_ca", "system"
	Error     string
	Severity  string // "fatal", "warning"
}
```

#### Step 2: Explicit Certificate Validation

```go
func (t *Transport) buildHTTPClient() {
	// ... existing code ...

	// Step 1: Build certificate pool with validation
	certBundle, err := t.buildAndValidateCertificateBundle()
	if err != nil {
		// FATAL: Don't continue with invalid certificates
		t.logger.Fatal("Certificate validation failed, cannot proceed",
			zap.Error(err),
			zap.String("component", "transport"),
		)
	}

	// Step 2: Log certificate bundle summary
	t.logCertificateSummary(certBundle)

	// Step 3: Only proceed with validated bundle
	tlsConfig := &tls.Config{
		RootCAs: certBundle.SystemCAs,
		// ... other config ...
	}
}

func (t *Transport) buildAndValidateCertificateBundle() (*CertificateBundle, error) {
	bundle := &CertificateBundle{
		ValidationErrors: []CertValidationError{},
	}

	// Step 1: Load system CA pool
	systemCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to load system CA pool: %w", err)
	}
	bundle.SystemCAs = systemCAs

	// Step 2: Load custom CA from environment
	customCA := os.Getenv("SLACK_MCP_SERVER_CA_CERT")
	if customCA != "" {
		if !systemCAs.AppendCertsFromPEM([]byte(customCA)) {
			err := fmt.Errorf("failed to parse custom CA certificate")
			bundle.ValidationErrors = append(bundle.ValidationErrors,
				CertValidationError{
					Source: "custom_ca",
					Error: err.Error(),
					Severity: "fatal",
				})
			return nil, err
		}
	}

	// Step 3: Load toolkit certificate from environment
	toolkitPEM := os.Getenv("SLACK_MCP_TOOLKIT_CERT")
	if toolkitPEM != "" {
		certs, err := parseCertificatesPEM([]byte(toolkitPEM))
		if err != nil {
			err := fmt.Errorf("failed to parse toolkit certificate: %w", err)
			bundle.ValidationErrors = append(bundle.ValidationErrors,
				CertValidationError{
					Source: "toolkit",
					Error: err.Error(),
					Severity: "fatal",
				})
			return nil, err
		}

		// Validate each certificate
		for i, cert := range certs {
			if err := validateCertificate(cert); err != nil {
				bundle.ValidationErrors = append(bundle.ValidationErrors,
					CertValidationError{
						Source: fmt.Sprintf("toolkit[%d]", i),
						Error: err.Error(),
						Severity: "fatal",
					})
				return nil, fmt.Errorf("invalid toolkit certificate: %w", err)
			}
		}

		bundle.ToolkitCerts = certs
		if !systemCAs.AppendCertsFromPEM([]byte(toolkitPEM)) {
			return nil, fmt.Errorf("failed to append toolkit certificates to bundle")
		}
	}

	bundle.IsValid = true
	return bundle, nil
}

func validateCertificate(cert *x509.Certificate) error {
	// Check certificate expiration
	if time.Now().After(cert.NotAfter) {
		return fmt.Errorf("certificate expired on %v", cert.NotAfter)
	}

	if time.Now().Before(cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid, starts at %v", cert.NotBefore)
	}

	// Warn if certificate expires soon (< 30 days)
	daysUntilExpiry := time.Until(cert.NotAfter).Hours() / 24
	if daysUntilExpiry < 30 {
		// This should be logged but doesn't fail validation
		return nil
	}

	return nil
}

func parseCertificatesPEM(certPEM []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(certPEM) > 0 {
		block, rest := pem.Decode(certPEM)
		if block == nil {
			break
		}

		if block.Type != "CERTIFICATE" {
			certPEM = rest
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		certs = append(certs, cert)
		certPEM = rest
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in PEM")
	}

	return certs, nil
}

func (t *Transport) logCertificateSummary(bundle *CertificateBundle) {
	t.logger.Info("TLS Certificate Bundle Summary",
		zap.Int("system_cas_count", len(bundle.SystemCAs.Subjects())),
		zap.Int("custom_certs", len(bundle.ToolkitCerts)),
		zap.Bool("is_valid", bundle.IsValid),
	)

	for _, cert := range bundle.ToolkitCerts {
		t.logger.Info("Loaded Certificate",
			zap.String("subject", cert.Subject.String()),
			zap.String("issuer", cert.Issuer.String()),
			zap.Time("not_before", cert.NotBefore),
			zap.Time("not_after", cert.NotAfter),
		)
	}

	for _, err := range bundle.ValidationErrors {
		if err.Severity == "fatal" {
			t.logger.Error("Certificate Validation Error",
				zap.String("source", err.Source),
				zap.String("error", err.Error),
			)
		}
	}
}
```

#### Step 3: Initialization Strategy

```go
func (t *Transport) initialize() error {
	// Step 1: Validate TLS configuration early
	if err := t.validateTLSConfiguration(); err != nil {
		return fmt.Errorf("TLS configuration validation failed: %w", err)
	}

	// Step 2: Build HTTP client with validated certs
	if err := t.buildHTTPClient(); err != nil {
		return fmt.Errorf("HTTP client setup failed: %w", err)
	}

	return nil
}

func (t *Transport) validateTLSConfiguration() error {
	insecure := os.Getenv("SLACK_MCP_SERVER_CA_INSECURE")

	// Strict validation: only explicit boolean values allowed
	if insecure != "" && insecure != "true" && insecure != "false" && insecure != "0" && insecure != "1" {
		return fmt.Errorf("invalid SLACK_MCP_SERVER_CA_INSECURE value: %q (must be true/false)", insecure)
	}

	if insecure == "true" || insecure == "1" {
		t.logger.Warn("InsecureSkipVerify enabled - TLS verification disabled",
			zap.String("component", "transport"),
		)
	}

	return nil
}
```

### Success Criteria

- ✅ Failed certificate append operations are fatal (panic)
- ✅ Certificate validation performed before TLS config creation
- ✅ Certificate expiration dates logged at startup
- ✅ Certificates expiring within 30 days trigger warning logs
- ✅ All certificate sources (system, custom, toolkit) logged at INFO level
- ✅ Server startup fails if required certificates cannot be loaded
- ✅ Clear error messages indicating which certificate failed and why

### Testing Strategy

```go
// Test fatal failure on invalid certificate
func TestCertificateValidationFailsFatal(t *testing.T) {
	transport := NewTransport("test", invalidCertPEM)
	err := transport.initialize()

	if err == nil {
		t.Error("Expected error for invalid certificate, got nil")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("Expected certificate-related error, got: %v", err)
	}
}

// Test certificate expiration detection
func TestCertificateExpirationDetected(t *testing.T) {
	expiredCertPEM := generateExpiredCertPEM()
	transport := NewTransport("test", expiredCertPEM)
	err := transport.initialize()

	if err == nil {
		t.Error("Expected error for expired certificate")
	}
}
```

---

## 3. HIGH PRIORITY ISSUE #3: No Rate Limiting on Resource Endpoints

### Problem Analysis

**Location:** `pkg/server/server.go:200-212, pkg/handler/channels.go, pkg/handler/conversations.go`

**Current State:**
```go
// Tools have rate limiting (good)
func (s *MCPServer) listTools(ctx context.Context) []mcp.Tool {
	// Has rate limiting middleware
}

// BUT Resources don't have rate limiting (bad!)
func (s *MCPServer) getResources() []*mcp.Resource {
	return []*mcp.Resource{
		{
			URI: "slack://channels",
			Name: "Slack Channels",
			MimeType: "application/json",
			// ❌ NO RATE LIMITING!
		},
		{
			URI: "slack://conversations",
			Name: "Slack Conversations",
			MimeType: "application/json",
			// ❌ NO RATE LIMITING!
		},
	}
}

// Resource handlers called without rate limit checks
func (h *ChannelsHandler) Handle(uri string) error {
	// ❌ Can be called infinitely fast
	return h.provideChannels()
}
```

**Root Cause:**
- Tools have rate limiter middleware, resources do not
- Resource handlers invoked without any rate limit checks
- No backpressure on resource polling requests
- Clients can hammer endpoints without throttling

**Vulnerability Impact:**
- **DoS Exposure**: Rapid resource requests exhaust server resources
- **Cache Thrashing**: Repeated calls to expensive handlers degrade performance
- **API Quota Abuse**: Unmetered resource reads consume Slack API quota
- **Inconsistent Security**: Tools protected, resources unprotected

### Design Solution

**Architecture Pattern:** Unified Rate Limiting for Tools and Resources

#### Step 1: Enhanced Rate Limiter Configuration

```go
type RateLimiterConfig struct {
	// Tool endpoints rate limiting
	ToolsRPS      int           // Requests per second
	ToolsBurst    int           // Burst size

	// Resource endpoints rate limiting
	ResourceRPS   int           // Requests per second
	ResourceBurst int           // Burst size

	// Per-resource limits
	ChannelsRPS   int
	ConversationsRPS int
}

const (
	DefaultToolsRPS = 10
	DefaultToolsBurst = 20

	DefaultResourceRPS = 5
	DefaultResourceBurst = 10

	DefaultChannelsRPS = 2
	DefaultConversationsRPS = 2
)
```

#### Step 2: Rate Limiter Middleware for Resources

```go
type RateLimitedHandler struct {
	handler mcp.Handler
	limiter *rate.Limiter
	logger  *zap.Logger
	name    string
}

func (rl *RateLimitedHandler) Handle(ctx context.Context, uri string) (interface{}, error) {
	// Step 1: Check rate limit
	if !rl.limiter.Allow() {
		rl.logger.Warn("Resource rate limit exceeded",
			zap.String("resource", rl.name),
			zap.String("uri", uri),
		)
		return nil, fmt.Errorf("rate limit exceeded for resource: %s", rl.name)
	}

	// Step 2: Delegate to actual handler
	return rl.handler.Handle(ctx, uri)
}

func NewRateLimitedHandler(name string, handler mcp.Handler,
	rps float64, burst int, logger *zap.Logger) *RateLimitedHandler {
	return &RateLimitedHandler{
		handler: handler,
		limiter: rate.NewLimiter(rate.Limit(rps), burst),
		logger: logger,
		name: name,
	}
}
```

#### Step 3: Server Integration

```go
func (s *MCPServer) getResources() []*mcp.Resource {
	return []*mcp.Resource{
		{
			URI: "slack://channels",
			Name: "Slack Channels",
			MimeType: "application/json",
		},
		{
			URI: "slack://conversations",
			Name: "Slack Conversations",
			MimeType: "application/json",
		},
	}
}

func (s *MCPServer) handleResourceRead(ctx context.Context, uri string) (interface{}, error) {
	// Route to appropriate rate-limited handler
	switch uri {
	case "slack://channels":
		return s.channelsResourceLimiter.Handle(ctx, uri)
	case "slack://conversations":
		return s.conversationsResourceLimiter.Handle(ctx, uri)
	default:
		return nil, fmt.Errorf("unknown resource: %s", uri)
	}
}

// During server initialization
func (s *MCPServer) initialize(provider *provider.ApiProvider, logger *zap.Logger) {
	// ... existing code ...

	// Create rate-limited resource handlers
	s.channelsResourceLimiter = NewRateLimitedHandler(
		"channels",
		s.channelsHandler,
		float64(DefaultChannelsRPS),
		DefaultResourceBurst,
		logger,
	)

	s.conversationsResourceLimiter = NewRateLimitedHandler(
		"conversations",
		s.conversationsHandler,
		float64(DefaultConversationsRPS),
		DefaultResourceBurst,
		logger,
	)
}
```

#### Step 4: Per-Resource Rate Limit Tracking

```go
type ResourceRateLimitStats struct {
	Resource string
	RPS float64
	Burst int
	RequestCount int64
	LimitedCount int64
	LastReset time.Time
}

func (s *MCPServer) getResourceStats() []ResourceRateLimitStats {
	return []ResourceRateLimitStats{
		{
			Resource: "channels",
			RPS: float64(DefaultChannelsRPS),
			Burst: DefaultResourceBurst,
			RequestCount: s.channelsResourceLimiter.limiter.Limit(),
		},
		{
			Resource: "conversations",
			RPS: float64(DefaultConversationsRPS),
			Burst: DefaultResourceBurst,
			RequestCount: s.conversationsResourceLimiter.limiter.Limit(),
		},
	}
}
```

### Success Criteria

- ✅ Resource endpoints have rate limiting middleware
- ✅ Default: 5 RPS per resource, 10 burst
- ✅ Requests exceeding limit return error with clear message
- ✅ Rate limit violations logged at WARN level
- ✅ Consistent rate limiting between tools and resources
- ✅ Per-resource rate limiting configurable via environment variables
- ✅ Metrics available for monitoring resource access patterns

### Testing Strategy

```go
// Test resource rate limiting
func TestResourceRateLimiting(t *testing.T) {
	limiter := rate.NewLimiter(1, 1)  // 1 RPS, 1 burst
	handler := NewRateLimitedHandler("test", mockHandler, 1, 1, logger)

	// First request should succeed (within burst)
	_, err := handler.Handle(context.Background(), "slack://test")
	if err != nil {
		t.Errorf("First request failed: %v", err)
	}

	// Second request should fail (rate limited)
	_, err := handler.Handle(context.Background(), "slack://test")
	if err == nil {
		t.Error("Expected rate limit error, got nil")
	}
}
```

---

## 4. HIGH PRIORITY ISSUE #4: Missing Authentication on Resource Handlers (STDIO)

### Problem Analysis

**Location:** `pkg/server/auth/sse_auth.go:114-115`

**Current State:**
```go
func (a *SSEAuthenticator) IsAuthenticated(transport string) (bool, error) {
	switch transport {
	case "stdio":
		return true, nil  // ❌ ALWAYS returns true!
	case "sse":
		// ... proper validation ...
	case "http":
		// ... proper validation ...
	}
}
```

**Root Cause:**
- STDIO transport hardcoded to skip authentication checks
- No validation of STDIO connection origin
- Assumption that STDIO is always trusted (incorrect!)
- No middleware to enforce auth on STDIO resource handlers

**Vulnerability Impact:**
- **Unauthorized Access**: Any local process can access STDIO endpoint
- **Privilege Escalation**: Unprivileged processes bypass auth
- **Information Disclosure**: Slack data exposed without credentials
- **Inconsistent Security Model**: SSE/HTTP auth required, STDIO bypassed

### Design Solution

**Architecture Pattern:** Unified Authentication with STDIO-Specific Validation

#### Step 1: STDIO Authentication Enhancement

```go
type STDIOAuthenticator struct {
	logger *zap.Logger

	// Optional: whitelist of allowed local users/processes
	AllowedUsers []string
	AllowedPIDs []int

	// Authentication state
	requestID string
	startTime time.Time
}

func (a *STDIOAuthenticator) IsAuthenticated() (bool, error) {
	// Step 1: Verify STDIO is connected to a terminal or pipe (not arbitrary process)
	if !isValidSTDIOSource() {
		a.logger.Error("STDIO authentication failed: invalid source",
			zap.String("component", "auth"))
		return false, fmt.Errorf("STDIO connection not from valid source")
	}

	// Step 2: Optional - check process ownership
	if a.AllowedUsers != nil {
		currentUser := os.Getenv("USER")
		if !sliceContains(a.AllowedUsers, currentUser) {
			a.logger.Error("STDIO authentication failed: unauthorized user",
				zap.String("user", currentUser),
				zap.String("component", "auth"))
			return false, fmt.Errorf("user %q not authorized for STDIO access", currentUser)
		}
	}

	// Step 3: Optional - check parent process
	if a.AllowedPIDs != nil {
		ppid := os.Getppid()
		if !sliceContainsInt(a.AllowedPIDs, ppid) {
			a.logger.Warn("STDIO authentication warning: unexpected parent process",
				zap.Int("parent_pid", ppid),
				zap.String("component", "auth"))
		}
	}

	a.logger.Info("STDIO authentication successful",
		zap.String("user", os.Getenv("USER")),
		zap.Int("pid", os.Getpid()),
		zap.Int("ppid", os.Getppid()),
	)

	return true, nil
}

func isValidSTDIOSource() bool {
	// Check if stdin/stdout are connected to terminal or valid pipe
	stdinStat, _ := os.Stdin.Stat()
	stdoutStat, _ := os.Stdout.Stat()

	stdinMode := stdinStat.Mode()
	stdoutMode := stdoutStat.Mode()

	// Valid if connected to TTY (terminal) or pipe
	isStdinValid := (stdinMode & os.ModeCharDevice) != 0 || (stdinMode & os.ModeNamedPipe) != 0
	isStdoutValid := (stdoutMode & os.ModeCharDevice) != 0 || (stdoutMode & os.ModeNamedPipe) != 0

	return isStdinValid && isStdoutValid
}
```

#### Step 2: Unified Authenticator Interface

```go
type Authenticator interface {
	IsAuthenticated() (bool, error)
	GetTransport() string
}

type UnifiedAuthenticator struct {
	transport string
	sseAuth *SSEAuthenticator
	stdioAuth *STDIOAuthenticator
	httpAuth *HTTPAuthenticator
	logger *zap.Logger
}

func (ua *UnifiedAuthenticator) IsAuthenticated() (bool, error) {
	switch ua.transport {
	case "stdio":
		// STDIO now has proper authentication
		return ua.stdioAuth.IsAuthenticated()
	case "sse":
		return ua.sseAuth.IsAuthenticated()
	case "http":
		return ua.httpAuth.IsAuthenticated()
	default:
		ua.logger.Error("Unknown transport type",
			zap.String("transport", ua.transport))
		return false, fmt.Errorf("unknown transport: %s", ua.transport)
	}
}
```

#### Step 3: Resource Handler Authentication Middleware

```go
type AuthenticatedResourceHandler struct {
	auth Authenticator
	handler mcp.Handler
	logger *zap.Logger
	resource string
}

func (ar *AuthenticatedResourceHandler) Handle(ctx context.Context, uri string) (interface{}, error) {
	// Step 1: Authenticate before any processing
	authenticated, err := ar.auth.IsAuthenticated()
	if err != nil {
		ar.logger.Error("Resource authentication failed",
			zap.String("resource", ar.resource),
			zap.Error(err),
		)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if !authenticated {
		ar.logger.Warn("Unauthenticated resource access attempt",
			zap.String("resource", ar.resource),
			zap.String("uri", uri),
		)
		return nil, fmt.Errorf("access denied: authentication required")
	}

	// Step 2: Log successful authentication
	ar.logger.Debug("Authenticated resource access",
		zap.String("resource", ar.resource),
		zap.String("uri", uri),
	)

	// Step 3: Delegate to handler
	return ar.handler.Handle(ctx, uri)
}

func NewAuthenticatedResourceHandler(resource string,
	handler mcp.Handler, auth Authenticator, logger *zap.Logger) *AuthenticatedResourceHandler {
	return &AuthenticatedResourceHandler{
		auth: auth,
		handler: handler,
		logger: logger,
		resource: resource,
	}
}
```

#### Step 4: Server Integration

```go
func (s *MCPServer) NewWithAuth(provider *provider.ApiProvider,
	authenticator Authenticator, logger *zap.Logger) *MCPServer {

	// ... existing initialization ...

	// Wrap resource handlers with authentication
	s.channelsHandler = NewAuthenticatedResourceHandler(
		"channels",
		s.channelsHandler,
		authenticator,
		logger,
	)

	s.conversationsHandler = NewAuthenticatedResourceHandler(
		"conversations",
		s.conversationsHandler,
		authenticator,
		logger,
	)

	return s
}
```

### Success Criteria

- ✅ STDIO connections validated (not bypassed)
- ✅ Resource handlers require authentication before responding
- ✅ Authentication failures logged at ERROR level
- ✅ Clear error messages for authentication failures
- ✅ Optional: STDIO source validation (TTY/pipe check)
- ✅ Optional: Process whitelist support
- ✅ Consistent authentication across all transports

### Testing Strategy

```go
// Test STDIO authentication
func TestSTDIOAuthentication(t *testing.T) {
	auth := NewSTDIOAuthenticator(logger)

	authenticated, err := auth.IsAuthenticated()
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !authenticated {
		t.Error("Expected STDIO authentication to succeed")
	}
}

// Test resource handler authentication enforcement
func TestAuthenticatedResourceHandler(t *testing.T) {
	failAuth := NewMockAuthenticator(false)
	handler := NewAuthenticatedResourceHandler("test", mockHandler, failAuth, logger)

	_, err := handler.Handle(context.Background(), "slack://test")
	if err == nil {
		t.Error("Expected authentication error")
	}
}
```

---

## 5. HIGH PRIORITY ISSUE #5: Uncontrolled TLS Insecurity Option

### Problem Analysis

**Location:** `pkg/transport/transport.go:377-383, 396-430`

**Current State:**
```go
func (t *Transport) buildHTTPClient() {
	// ... code ...

	insecure := os.Getenv("SLACK_MCP_SERVER_CA_INSECURE")

	// ❌ PROBLEM: Any non-empty value enables insecure mode
	if insecure != "" {
		insecureSkipVerify = true
	}

	// ❌ RESULT:
	// SLACK_MCP_SERVER_CA_INSECURE=0 -> InsecureSkipVerify = true ❌
	// SLACK_MCP_SERVER_CA_INSECURE=false -> InsecureSkipVerify = true ❌
	// SLACK_MCP_SERVER_CA_INSECURE=disable -> InsecureSkipVerify = true ❌
	// SLACK_MCP_SERVER_CA_INSECURE=true -> InsecureSkipVerify = true ✓
	// SLACK_MCP_SERVER_CA_INSECURE="" -> InsecureSkipVerify = false ✓

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
	}
}
```

**Root Cause:**
- Non-strict boolean parsing: any non-empty value treated as "true"
- No explicit whitelist of valid values
- Common "false" value interpreted as enabling insecurity
- Difficult to disable once enabled (requires unsetting env var)

**Vulnerability Impact:**
- **Man-in-the-Middle Risk**: Mistaken config enables MITM attacks
- **Configuration Errors**: Admin intends `=false`, gets insecure mode
- **Hard to Detect**: Silent failure, no warnings when insecure mode enabled
- **Production Risk**: Typos in scripts enable MITM vulnerabilities

### Design Solution

**Architecture Pattern:** Strict Boolean Configuration with Explicit Validation

#### Step 1: Strict Configuration Parsing

```go
type TLSInsecurityOption struct {
	Enabled bool
	Source  string // Where this value came from
}

func parseTLSInsecurityOption() (TLSInsecurityOption, error) {
	envValue := os.Getenv("SLACK_MCP_SERVER_CA_INSECURE")

	if envValue == "" {
		// Default: secure
		return TLSInsecurityOption{
			Enabled: false,
			Source: "default",
		}, nil
	}

	// Strict parsing: only accept explicit boolean values
	switch strings.ToLower(strings.TrimSpace(envValue)) {
	case "true", "1", "yes", "on":
		return TLSInsecurityOption{
			Enabled: true,
			Source: fmt.Sprintf("SLACK_MCP_SERVER_CA_INSECURE=%q", envValue),
		}, nil

	case "false", "0", "no", "off":
		return TLSInsecurityOption{
			Enabled: false,
			Source: fmt.Sprintf("SLACK_MCP_SERVER_CA_INSECURE=%q", envValue),
		}, nil

	default:
		// REJECT invalid values - don't make assumptions
		return TLSInsecurityOption{},
			fmt.Errorf("invalid SLACK_MCP_SERVER_CA_INSECURE value: %q "+
				"(must be one of: true, false, 1, 0, yes, no, on, off)",
				envValue)
	}
}
```

#### Step 2: Validation at Startup

```go
func (t *Transport) validateAndConfigureTLS() error {
	// Step 1: Parse TLS insecurity option
	tlsOption, err := parseTLSInsecurityOption()
	if err != nil {
		// FATAL: Don't allow invalid config
		t.logger.Fatal("Invalid TLS configuration",
			zap.Error(err),
			zap.String("component", "transport"),
		)
		return err
	}

	// Step 2: Log the setting prominently
	if tlsOption.Enabled {
		t.logger.Error("⚠️  TLS VERIFICATION DISABLED ⚠️",
			zap.String("setting", tlsOption.Source),
			zap.String("component", "transport"),
			zap.String("warning", "MITM ATTACKS POSSIBLE - For development only"),
		)
	} else {
		t.logger.Info("TLS verification enabled (secure)",
			zap.String("component", "transport"),
		)
	}

	t.tlsInsecureSkipVerify = tlsOption.Enabled
	return nil
}

func (t *Transport) buildHTTPClient() error {
	// Step 1: Validate TLS configuration
	if err := t.validateAndConfigureTLS(); err != nil {
		return err
	}

	// Step 2: Build certificate bundle (separate from insecurity option)
	certBundle, err := t.buildAndValidateCertificateBundle()
	if err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// Step 3: Create TLS config with validated settings
	tlsConfig := &tls.Config{
		RootCAs: certBundle.SystemCAs,
		InsecureSkipVerify: t.tlsInsecureSkipVerify,
	}

	t.httpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return nil
}
```

#### Step 3: Runtime Validation

```go
type TLSConfiguration struct {
	InsecureEnabled     bool
	CertificateBundle   *CertificateBundle
	ValidatedAt         time.Time
	IsProduction        bool
}

func (t *Transport) GetTLSStatus() TLSConfiguration {
	isProduction := os.Getenv("ENVIRONMENT") == "production"

	return TLSConfiguration{
		InsecureEnabled: t.tlsInsecureSkipVerify,
		ValidatedAt: time.Now(),
		IsProduction: isProduction,
	}
}

func (t *Transport) ValidateTLSStatus() error {
	status := t.GetTLSStatus()

	// FATAL: Never allow insecure mode in production
	if status.InsecureEnabled && status.IsProduction {
		return fmt.Errorf(
			"InsecureSkipVerify cannot be enabled in production environment")
	}

	return nil
}
```

#### Step 4: Documentation and Logging

```go
const TLSConfigurationDoc = `
SLACK_MCP_SERVER_CA_INSECURE Configuration Guide

Purpose: Control whether to skip TLS certificate verification

Valid Values:
  - true, 1, yes, on   -> Disable TLS verification (INSECURE)
  - false, 0, no, off  -> Enable TLS verification (SECURE)
  - (unset)            -> Enable TLS verification (SECURE) [DEFAULT]

Examples:
  ✓ SLACK_MCP_SERVER_CA_INSECURE=true    # Disable verification
  ✓ SLACK_MCP_SERVER_CA_INSECURE=false   # Enable verification
  ✗ SLACK_MCP_SERVER_CA_INSECURE=0       # NOW INVALID - use false instead
  ✗ SLACK_MCP_SERVER_CA_INSECURE=1       # NOW INVALID - use true instead

Security Warning:
  - Only disable TLS verification in development/testing
  - NEVER disable in production environments
  - Disabling allows Man-in-the-Middle (MITM) attacks
  - Certificate validation is required for secure communication
`

func (t *Transport) logTLSConfiguration() {
	if t.tlsInsecureSkipVerify {
		t.logger.Error("⚠️  CRITICAL SECURITY ISSUE ⚠️",
			zap.String("issue", "TLS Certificate Verification Disabled"),
			zap.String("environment_variable", "SLACK_MCP_SERVER_CA_INSECURE=true"),
			zap.String("risk", "Man-in-the-Middle (MITM) attacks possible"),
			zap.String("recommendation", "Enable TLS verification in production"),
		)
	}
}
```

### Success Criteria

- ✅ Strict boolean parsing: only accept true/false/1/0/yes/no/on/off
- ✅ Invalid values cause startup failure with clear error message
- ✅ Default behavior is SECURE (verification enabled)
- ✅ Insecure mode logged prominently at startup (ERROR level)
- ✅ Production environment prevents insecure mode
- ✅ Configuration documented with examples
- ✅ Clear error messages guide users to valid values

### Testing Strategy

```go
// Test invalid configuration values
func TestInvalidTLSConfiguration(t *testing.T) {
	tests := []struct {
		envValue string
		shouldFail bool
	}{
		{"true", false},
		{"false", false},
		{"1", false},
		{"0", false},
		{"yes", false},
		{"no", false},
		{"on", false},
		{"off", false},
		{"invalid", true},      // ❌ Should fail
		{"maybe", true},        // ❌ Should fail
		{"nope", true},         // ❌ Should fail
		{"anything-else", true}, // ❌ Should fail
	}

	for _, tt := range tests {
		os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", tt.envValue)
		_, err := parseTLSInsecurityOption()

		if tt.shouldFail && err == nil {
			t.Errorf("Expected error for value %q, got nil", tt.envValue)
		}
		if !tt.shouldFail && err != nil {
			t.Errorf("Unexpected error for value %q: %v", tt.envValue, err)
		}
	}
}

// Test production environment protection
func TestProductionEnvPreventsInsecureMode(t *testing.T) {
	os.Setenv("ENVIRONMENT", "production")
	os.Setenv("SLACK_MCP_SERVER_CA_INSECURE", "true")

	transport := NewTransport("test", logger)
	err := transport.ValidateTLSStatus()

	if err == nil {
		t.Error("Expected error for insecure mode in production")
	}
}
```

---

## Implementation Roadmap

### Phase 3: Implementation (HIGH Priority)

1. **Issue #4: Missing Authentication (STDIO)** - FIRST
   - Highest security impact
   - Affects local access control

2. **Issue #5: TLS Insecurity Option** - SECOND
   - Configuration validation prevents MITM
   - Blocks production misconfigurations

3. **Issue #2: Silent TLS Failures** - THIRD
   - Fail-fast on certificate problems
   - Comprehensive validation

4. **Issue #3: No Rate Limiting (Resources)** - FOURTH
   - DoS protection for endpoints
   - Consistent with tools rate limiting

5. **Issue #1: Cache Refresh Concurrency** - FIFTH
   - API quota protection
   - Exponential backoff for reliability

### Success Metrics

- All rate limiters enforced and tested
- TLS configuration validated at startup
- Certificate failures fatal (not warnings)
- STDIO authentication required
- All features logged appropriately
- Zero new race conditions (verified with `go test -race`)

---

## References

- Go Rate Limiting: https://pkg.go.dev/golang.org/x/time/rate
- TLS in Go: https://pkg.go.dev/crypto/tls
- Go Context: https://pkg.go.dev/context
- Slack API Error Handling: https://api.slack.com/methods/users.list
