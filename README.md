# Production E*TRADE read MCP

A .NET 10 authenticated Streamable HTTP server at `/mcp`, backed by separate authorization and brokerage gateway services. The adapter holds no E*TRADE credentials. Exactly ten read tools are published:

| Tool | Data |
|---|---|
| `listAccounts` | Accounts |
| `getAccountBalance` | Balances |
| `getPortfolio` | Positions |
| `listTransactions` | Transactions |
| `getTransactionDetails` | Transaction details |
| `getQuotes` | Quotes |
| `lookupProduct` | Product lookup |
| `getOptionChains` | Option chains |
| `getOptionExpireDates` | Option expiry dates |
| `listOrders` | Order history |

Unknown operations, order submissions/changes/cancellations, previews, money movement and brokerage authorization calls are unavailable to agents. Brokerage authorization is performed by the owner console. Brokerage data routes are constructed under `https://api.etrade.com/v1`; OAuth API calls use `https://api.etrade.com/oauth/*`. Legacy sandbox settings fail closed. All automated brokerage tests use mocks or nonfinancial fixtures.

## Security boundaries

An authorization grant identifies one approved credential connection, not a model. Every persistent agent requires its own client connection and grant. Shared platform connections are ineligible. An approved platform metadata document does not approve all agents on that platform. Enrollment and grants require explicit owner approval, Google sign-in pinned to the owner's subject and recent application TOTP MFA. Public registration and unrestricted dynamic client registration are absent.

External bearer tokens stay within ingress, MCP and authorization. The authorization service issues a dedicated RSA-signed assertion valid for ten seconds, binding the agent, grant, operation and canonical request digest. Gateway checks the assertion, then atomically consumes its persisted nonce and rechecks the originating token and approvals immediately before dispatch. Authorization outages deny requests. Revocation blocks subsequent checks; a request that already passed its dispatch check may finish.

The brokerage gateway owns OAuth signing, consumer credentials and the encrypted token store. AES-256-GCM persistence retains exclusive locking, atomic fsync-backed updates and fail-closed recovery. Expiration occurs at midnight US Eastern, including daylight-saving transitions. Renewal does not extend that expiration. Fresh production authorization is required; local credentials must not be copied into deployments.

The independent method/route/query policy and the controlled proxy restrict outbound reads. The proxy checks exact production hostname, port 443, public pinned IPv4 and matching TLS SNI, and preserves end-to-end provider TLS validation. Internal calls use service-specific mTLS with endpoint permissions. Containers have separate networks, non-root users, read-only roots, dropped capabilities and host firewall rules. A full host or gateway compromise can still expose brokerage credentials; this architecture isolates those credentials from MCP process compromise.

E*TRADE's [current developer guide](https://developer.etrade.com/getting-started/developer-guides) describes OAuth 1.0a and authorization privileges that may include submitting orders. The guide documents no OAuth scope parameter for requesting a read-only token. Provider-enforced read-only permission is therefore **unverified and not enabled**. This server enforces its own read-only boundary; confirm production key privileges with E*TRADE before live use. The owner browser login uses the provider's documented `us.etrade.com` authorization page; gateway OAuth API traffic uses only `api.etrade.com`.

## Build and verify

```bash
dotnet build OpenEtradeMcp.sln -c Release
dotnet test tests/OpenEtradeMcp.Tests -c Release
python3 -m unittest discover -s tests -p 'test_proxy.py'
terraform -chdir=deploy/terraform init -backend=false
terraform -chdir=deploy/terraform validate
python3 deploy/build-images.py
```

See [deployment instructions](docs/deployment.md), [acceptance status](docs/verification.md) and [operations](docs/operations.md). This branch replaces the credential-bearing stdio executable. Clients must use OAuth with the authenticated HTTPS endpoint. ChatGPT and Meta Muse compatibility has not been verified; keep them unenrolled until credential isolation is demonstrated with nonfinancial fixtures.
