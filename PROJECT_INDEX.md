# Project Index: Slack MCP Server

**Generated:** 2026-01-09
**Language:** Go
**License:** MIT
**Author:** Dmitrii Korotovskii

## 📁 Project Structure

```
slack-mcp-server/
├── cmd/
│   └── slack-mcp-server/
│       ├── main.go              # Main entry point
│       ├── logger.go            # Logging setup
│       ├── watcher.go           # Cache watchers
│       └── config_validator.go  # Configuration validation
├── pkg/
│   ├── provider/                # Slack provider
│   │   ├── api.go               # Main API provider
│   │   ├── edge/                # Edge (stealth) client
│   │   │   ├── client.go        # Edge client implementation
│   │   │   ├── conversations.go # Conversation handling
│   │   │   ├── dms.go           # DM handling
│   │   │   ├── search.go        # Message search
│   │   │   ├── userlist.go      # User list handling
│   │   │   ├── fasttime/        # Performance optimization
│   │   │   └── slacker.go       # Slack client wrapper
│   │   └── resources.go         # Resource definitions
│   ├── handler/                 # MCP tool handlers
│   │   ├── conversations.go     # Conversation tools
│   │   ├── channels.go          # Channel tools
│   │   └── resources.go         # Resource handlers
│   ├── server/                  # MCP server implementation
│   ├── transport/               # Transport implementations (Stdio, SSE, HTTP)
│   └── limiter/                 # Rate limiting
├── docs/
│   ├── 01-authentication-setup.md
│   ├── 02-installation.md
│   └── 03-configuration-and-usage.md
├── build/                       # Build output
└── npm/                         # NPM packages (platform-specific binaries)
```

## 🚀 Entry Points

- **CLI**: `cmd/slack-mcp-server/main.go` - Main server entry point with transport support
- **API Provider**: `pkg/provider/api.go` - Core Slack API provider
- **MCP Server**: `pkg/server/` - Model Context Protocol server implementation

## 📦 Core Modules

### Provider Module (`pkg/provider/`)
**Purpose:** Abstracts Slack API interactions and manages authentication
**Key Features:**
- Multiple authentication modes: xoxc/xoxd (stealth), xoxp (user), xoxb (bot)
- User and channel caching system
- Rate limiting via `golang.org/x/time/rate`
- Support for OAuth and stealth modes

**Key Types:**
- `UsersCache` - Cached user data with inverse lookup
- `ChannelsCache` - Cached channel information
- Rate limiters for API calls

### Edge Client Module (`pkg/provider/edge/`)
**Purpose:** Stealth mode client implementation (no bot/permissions required)
**Key Components:**
- `client.go` - Main edge client with browser token auth
- `conversations.go` - Fetch messages from channels/threads
- `dms.go` - Direct message handling
- `search.go` - Message search functionality
- `userlist.go` - User list fetching
- `fasttime/` - Optimized timestamp handling for 386/x64 architectures

### Handler Module (`pkg/handler/`)
**Purpose:** Implements MCP tool handlers for Slack operations
**Tools Implemented:**
- `conversations_history` - Get channel/DM messages with pagination
- `conversations_replies` - Get thread messages
- `conversations_add_message` - Post messages (disabled by default)
- `conversations_search_messages` - Search messages with filters
- `channels_list` - List workspace channels

### Server Module (`pkg/server/`)
**Purpose:** MCP server implementation
**Responsibilities:**
- Tool registration and dispatch
- Resource serving (channels/users CSV directories)
- Request/response handling

### Transport Module (`pkg/transport/`)
**Purpose:** Multiple transport implementations
**Supported Transports:**
- Stdio (default)
- SSE (Server-Sent Events)
- HTTP

### Limiter Module (`pkg/limiter/`)
**Purpose:** Rate limiting for API calls
**Features:** Configurable limits for different API endpoints

## 🔧 Configuration

### Environment Variables (Key)
| Variable | Type | Default | Purpose |
|----------|------|---------|---------|
| `SLACK_MCP_XOXC_TOKEN` | string | - | Browser token (stealth mode) |
| `SLACK_MCP_XOXD_TOKEN` | string | - | Browser cookie (stealth mode) |
| `SLACK_MCP_XOXP_TOKEN` | string | - | User OAuth token |
| `SLACK_MCP_XOXB_TOKEN` | string | - | Bot token |
| `SLACK_MCP_PORT` | int | 13080 | Server port (SSE/HTTP) |
| `SLACK_MCP_HOST` | string | 127.0.0.1 | Server host (SSE/HTTP) |
| `SLACK_MCP_PROXY` | string | - | Proxy URL for requests |
| `SLACK_MCP_ADD_MESSAGE_TOOL` | string | - | Enable message posting (safety) |
| `SLACK_MCP_LOG_LEVEL` | string | info | Log level (debug/info/warn/error) |

### Files
- `docker-compose.yml` - Development Docker setup
- `docker-compose.dev.yml` - Development services
- `docker-compose.toolkit.yml` - HTTPToolkit debugging

## 📚 Documentation

- **01-authentication-setup.md** - Token extraction and authentication methods
- **02-installation.md** - Installation instructions for different platforms
- **03-configuration-and-usage.md** - Detailed configuration and usage guide
- **SECURITY.md** - Security vulnerability reporting

## 📊 Resources

The server exposes two MCP directory resources:

1. **`slack://<workspace>/channels`** - CSV directory of all channels
   - Fields: id, name, topic, purpose, memberCount

2. **`slack://<workspace>/users`** - CSV directory of all users
   - Fields: userID, userName, realName

## 🧪 Testing

**Test Files:**
- `pkg/handler/conversations_test.go` - Conversation handler tests
- `pkg/handler/channels_test.go` - Channel handler tests
- `pkg/handler/slack_error_test.go` - Error handling tests
- `pkg/provider/edge/fasttime/fasttime_test.go` - Timestamp tests

**Test Command:**
```bash
go test ./...
```

## 🔗 Key Dependencies

- **slack-go/slack** - Official Slack Go SDK
- **rusq/slackdump** - Authentication handling
- **go.uber.org/zap** - Structured logging
- **golang.org/x/time/rate** - Rate limiting
- **mattn/go-isatty** - TTY detection

## 💡 Key Features

1. **Stealth Mode** - No bot installation or workspace permissions required
2. **Multiple Auth Methods** - OAuth tokens, browser tokens, bot tokens
3. **Smart Caching** - User and channel caching for performance
4. **Message Search** - Full-text search with date/user filters
5. **Thread Support** - Access to thread conversations
6. **DM Support** - Direct messages and group DMs
7. **Rate Limiting** - Built-in API call throttling
8. **Multiple Transports** - Stdio, SSE, HTTP support
9. **Proxy Support** - Route requests through corporate proxies
10. **TLS Configuration** - Custom CA certificates and enterprise support

## 📝 Quick Start

```bash
# 1. Set authentication
export SLACK_MCP_XOXC_TOKEN=your_token_here

# 2. Run with stdio (default)
go run cmd/slack-mcp-server/main.go

# 3. Run with SSE transport
go run cmd/slack-mcp-server/main.go -transport sse

# 4. Run with HTTP transport
go run cmd/slack-mcp-server/main.go -transport http
```

## 🔍 Notable Implementation Details

- **Fasttime package**: Optimized timestamp handling with architecture-specific implementations
- **Cache watcher pattern**: Background goroutines sync cache data periodically
- **Message enrichment**: Embeds user information in messages for better LLM context
- **Cursor-based pagination**: Efficient message traversal without offset limitations
- **Error handling**: Slack-specific error mapping and recovery

## 📦 Build & Distribution

- **npm/slack-mcp-server/** - Platform-specific npm packages
  - darwin-amd64, darwin-arm64 (macOS)
  - linux-amd64, linux-arm64 (Linux)
  - windows-amd64, windows-arm64 (Windows)
- **build/** - Build output directory

---

**Version:** 1.1.0
**Repository:** https://github.com/korotovsky/slack-mcp-server
