# OpenEtradeMcp

[![build](https://github.com/kerryjiang/OpenEtradeMcp/actions/workflows/build.yml/badge.svg)](https://github.com/kerryjiang/OpenEtradeMcp/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

An MCP (Model Context Protocol) server that exposes E*TRADE API operations as tools for AI agents. This allows AI assistants like Claude and GitHub Copilot to read E*TRADE account and market data and preview orders.

### NuGet Packages

| Package | Version | Downloads |
|---------|---------|-----------|
| OpenEtradeMcp | [![NuGet](https://img.shields.io/nuget/v/OpenEtradeMcp.svg)](https://www.nuget.org/packages/OpenEtradeMcp) | [![NuGet Downloads](https://img.shields.io/nuget/dt/OpenEtradeMcp.svg)](https://www.nuget.org/packages/OpenEtradeMcp) |
| OpenEtradeMcp.Server | [![NuGet](https://img.shields.io/nuget/v/OpenEtradeMcp.Server.svg)](https://www.nuget.org/packages/OpenEtradeMcp.Server) | [![NuGet Downloads](https://img.shields.io/nuget/dt/OpenEtradeMcp.Server.svg)](https://www.nuget.org/packages/OpenEtradeMcp.Server) |

## Features

- **OAuth 1.0a Authentication**: Interactive OAuth flow designed to work seamlessly with AI agents
- **E*TRADE API Tools**: Auto-generated tools from E*TRADE's OpenAPI specification
- **Read-only policy**: Explicit operation allowlist and outbound method/route enforcement; both order previews remain available
- **Encrypted OAuth persistence**: Reuse unexpired credentials across restarts, reboots, and redeployments
- **Sandbox Support**: Test safely with E*TRADE's sandbox environment
- **Global Tool**: Install as a .NET global tool for easy access

## Prerequisites

- [.NET 8.0/9.0/10.0 SDK](https://dotnet.microsoft.com/download)
- Linux or macOS with a local filesystem supporting exclusive locks, atomic rename, and directory fsync
- E*TRADE Developer Account with API access
- Consumer Key and Consumer Secret from [E*TRADE Developer Portal](https://developer.etrade.com/)

## Installation

### As a .NET Global Tool

```bash
dotnet tool install --global OpenEtradeMcp.Server
```

### From Source

```bash
git clone https://github.com/kerryjiang/OpenEtradeMcp.git
cd OpenEtradeMcp
dotnet build
```

## Configuration

### Environment Variables

```bash
export ETRADE_ConsumerKey="your-consumer-key"
export ETRADE_ConsumerSecret="your-consumer-secret"
export ETRADE_UseSandbox="true"  # Optional: use sandbox environment
export ETRADE_TokenDirectory="/absolute/path/to/private/tokens"
export ETRADE_TokenKeyFile="/absolute/path/to/private/oauth.key"
```

### Command Line Arguments

```bash
etrade-mcp --UseSandbox=true --TokenDirectory=/absolute/path/to/private/tokens --TokenKeyFile=/absolute/path/to/private/oauth.key
# Supply consumer credentials through environment variables.
```

## Running the Server

### Using the Global Tool

```bash
etrade-mcp
```

### From Source

```bash
cd src/OpenEtradeMcp.Server
dotnet run
```

## MCP Client Configuration

### Claude Desktop

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json` 

```json
{
  "mcpServers": {
    "etrade": {
      "command": "/Users/{YourUserName}/.dotnet/tools/etrade-mcp",
      "env": {
        "ETRADE_ConsumerKey": "your-consumer-key",
        "ETRADE_ConsumerSecret": "your-consumer-secret",
        "ETRADE_UseSandbox": "true",
        "ETRADE_TokenDirectory": "/Users/{YourUserName}/.local/share/etrade/tokens",
        "ETRADE_TokenKeyFile": "/Users/{YourUserName}/.local/share/etrade/oauth.key"
      }
    }
  }
}
```

Windows hosts must run the server in a Linux container or WSL. Native Windows storage is rejected because POSIX permission enforcement is required.

### VS Code with GitHub Copilot

Configure in your VS Code MCP settings to use the `etrade-mcp` command with appropriate environment variables.

## OAuth Authentication Flow

The server provides interactive OAuth tools that allow an AI agent to guide users through authentication:

### 1. Start OAuth (`etrade_oauth_start`)

Begins the authentication process and returns an authorization URL.

```
Agent: "I'll start the E*TRADE authentication process."
[Calls etrade_oauth_start]
Agent: "Please click this link to authorize: https://us.etrade.com/e/t/etws/authorize?..."
```

### 2. Complete OAuth (`etrade_oauth_complete`)

After the user authorizes and receives the verifier code:

```
User: "I got the code: ABC123"
Agent: "Great, let me complete the authentication."
[Calls etrade_oauth_complete with verifierCode="ABC123"]
Agent: "Authentication successful! You can now use E*TRADE API tools."
```

### 3. Additional OAuth Tools

- `etrade_oauth_status` - Check authentication status
- `etrade_oauth_renew` - Renew inactive access token (midnight Eastern requires reauthorization)
- `etrade_oauth_revoke` - Log out and revoke access token

## Available Tools

### OAuth Tools
| Tool | Description |
|------|-------------|
| `etrade_oauth_start` | Start OAuth authentication flow |
| `etrade_oauth_complete` | Complete OAuth with verifier code |
| `etrade_oauth_status` | Check authentication status |
| `etrade_oauth_renew` | Renew access token |
| `etrade_oauth_revoke` | Revoke access token |

### E*TRADE API Tools

Tools are auto-generated from the E*TRADE OpenAPI specification and include:

- **Account Management** - List accounts, view account details
- **Portfolio** - View positions and holdings
- **Orders** - List order history, preview orders, and preview order changes
- **Market Data** - Get quotes, option chains, and market information
- **Transactions** - List transactions and view details

## Project Structure

```
OpenEtradeMcp/
├── src/
│   ├── OpenEtradeMcp/              # Core library with E*TRADE API definitions
│   │   └── etrade-api.yaml        # E*TRADE OpenAPI specification
│   └── OpenEtradeMcp.Server/       # MCP server executable
├── Directory.Build.props          # Shared build properties
├── Directory.Packages.props       # Centralized package management
└── OpenEtradeMcp.sln              # Solution file
```

## Persistent OAuth configuration

Persistence is mandatory. Provision a random 256-bit key outside the application and source tree. Both configuration paths must be absolute. For example, run as the service user:

```bash
umask 077
mkdir -p "$HOME/.local/share/etrade/tokens"
chmod 700 "$HOME/.local/share/etrade" "$HOME/.local/share/etrade/tokens"
# Run once; do not replace this key on restart or redeployment.
openssl rand 32 > "$HOME/.local/share/etrade/oauth.key"
chmod 600 "$HOME/.local/share/etrade/oauth.key"
export ETRADE_TokenDirectory="$HOME/.local/share/etrade/tokens"
export ETRADE_TokenKeyFile="$HOME/.local/share/etrade/oauth.key"
```

The key is exactly 32 raw bytes, not hexadecimal or base64. The directory must be mode 0700; the key, credential file, and lock file must have no group or other permissions (normally 0600). Paths must not contain symbolic links. Ensure the service user owns the files, and protect parent directories from replacement by other users. Unsupported platforms or filesystems fail startup; there is no memory-only fallback.

Credentials use versioned AES-256-GCM with fresh nonces and authenticated binding to the consumer-key fingerprint and sandbox/production environment. Atomic replacement and flushed file/directory writes protect acknowledged transitions. Keep the persistent volume and external key together across deployment changes. A wrong key, changed consumer key/environment, corruption, unsupported version, or insecure permissions fails startup with a sanitized error. Missing credentials start unauthenticated. Never commit or bake the key or token files into an image.

For containers, mount a durable, service-owned volume at `/var/lib/etrade/tokens` (0700) and mount the externally provisioned key read-only at `/run/etrade/oauth.key` (0600). Set `ETRADE_TokenDirectory` and `ETRADE_TokenKeyFile` to those paths, and retain both mounts when replacing the container. Use a filesystem that supports locks and fsync; do not use multiple replicas or a shared network store. The process holds an exclusive lock for its lifetime; a second process using that directory fails startup. Do not delete `store.lock` while a server runs.

On startup, expired credentials are deleted. Unexpired credentials are renewed before authentication becomes usable. Transient provider failures retain encrypted credentials and expose `recoveryStatus: recovery_required`; the next business request retries recovery before signing. Credentials renew after 110 minutes without a successful API request. Issuance, renewal, and expiration timestamps persist; renewal never moves expiration beyond midnight Eastern. OAuth status includes optional `expiresAt` and `recoveryStatus` fields. Pending browser authorization exists only in memory and must be restarted after process replacement.

[E*TRADE's documented default access-token expiration](https://apisb.etrade.com/docs/api/authorization/renew_access_token.html) is **midnight US Eastern**, including daylight-saving transitions. Persistence preserves usable credentials and does not eliminate daily reauthorization. Definitive OAuth token expiration/rejection/revocation clears local credentials; an unspecified authorization failure does not imply expiration. Confirmed remote revocation clears in-memory credentials before deleting the file. A deletion failure reports failure explicitly and leaves the running process unauthenticated. Fix storage permissions and remove the stale credential file before restarting. Normal shutdown preserves credentials.

## Validation

```bash
dotnet build -c Release
dotnet test -c Release
python3 tests/verify_stdio.py src/OpenEtradeMcp.Server/bin/Release/net10.0/OpenEtradeMcp.Server.dll
```

The automated tests use mocked E*TRADE responses and an injectable clock. They cover registration, outbound trade blocking, encryption/tampering, key/environment binding, permissions, interrupted-write remnants, a competing process lock, authentication followed by a fresh instance and signed requests, inactivity recovery, transient failures, invalidation, midnight/DST, and persistence/revocation failures. Unix lock tests require `python3`.

Manual deployment checks (require your own E*TRADE authorization):

1. Authenticate, verify OAuth status and a read request, then stop the process before midnight Eastern.
2. Recreate the container with the same volume, external key, consumer credentials, and environment. Verify startup renewal, authenticated status, and another read without a new verifier.
3. Reboot the host before midnight and verify the same behavior after restart. Stop the first process and confirm a replacement can acquire the store lock; a concurrent process must fail startup.
4. Repeat across midnight: expired credentials must be removed and a new OAuth flow required. A pending authorization must not survive a restart.

## Security Notes

- Keep consumer credentials and the external encryption key private.
- Order execution, cancellation, and modification tools are permanently removed; no configuration override enables trading. Previews do not submit trades.
- OAuth tool errors and startup diagnostics omit provider bodies, tokens, secrets, and stack traces.

## Troubleshooting

### "OpenAPI spec file not found"
Ensure the `etrade-api.yaml` file is in the output directory. Rebuild the project.

### "E*TRADE API credentials not provided"
Set the `ConsumerKey` and `ConsumerSecret` environment variables.

### Authentication fails
- Verify your credentials are correct
- Ensure sandbox credentials are used with `UseSandbox=true`
- Check that the verifier code is entered correctly (no extra spaces)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

**Kerry Jiang** - [GitHub](https://github.com/kerryjiang)
