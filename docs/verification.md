# Acceptance status

Local validation uses mock brokerage responses and isolated nonfinancial fixtures, never live write operations or E*TRADE's sandbox. This document must distinguish completed local tests from rollout checks that need real infrastructure or credentials.

Automated .NET tests cover the ten-tool discovery set and credential-free adapter assembly, production configuration, forbidden requests before network transmission, canonical fixed routes and argument validation, duplicate/unknown typed JSON, assertion signing/tampering/argument substitution/issuer/expiration, persisted nonce replay protection, online revocation after issuance, independent agent state, invalid/unapproved/expired tokens and unavailable authorization storage. OAuth integration covers S256, exact redirects/resource/scope, code replay, rotating refresh-token reuse and grant revocation. Owner tests cover Google subject pinning, application TOTP validation, single-use recovery codes and CSRF rejection. Existing encryption, corruption, key binding, locking, interrupted atomic writes, restart/renewal, storage failures and midnight Eastern tests remain.

Python proxy tests cover exact production authority, IP literals, private/link-local/IPv6 destinations, TLS SNI, duplicate/encrypted SNI, fragmented and malformed ClientHello records and DNS rebinding. Container fixture checks verify public TLS metadata, authenticated MCP entry, hidden internal routes, non-root users, read-only roots, dropped capabilities, no privileged/host-network/Docker-socket access, secret mounts and a gateway fixture without production credentials.

`deploy/verify-network.sh` applies the actual host firewall and probes each permitted connection plus forbidden services, direct IP/IPv6, metadata, host services, external DNS and proxy bypass. It needs root on a dedicated host. The current workstation requires a sudo password, so this test is **not locally verified**; CI/target-host execution is required. Public and internal certificate issuance/rotation, firewall behavior under the target Docker backend and audit/alert delivery require target-host verification.

Google Cloud apply, domain/public TLS issuance, Google sign-in against the real provider, owner device enrollment, fresh production E*TRADE authorization, production read smoke checks, provider-enforced read-only privileges and ChatGPT/Meta Muse/local-client isolation remain **unverified** without deployment inputs and credentials. Keep those clients unenrolled until fixture credential isolation is demonstrated.

Compatibility/operations limits: enrollment supports public `none` clients with exact HTTPS redirects; other auth methods/key sources/native redirects are rejected. CIMD destinations require manual exact URL/hostname approval; no unrestricted DCR. Both proxies authenticate callers with mTLS; the identity fetch service independently enforces exact URLs/methods and the brokerage tunnel independently enforces destination/SNI. Approval backups are local to the encrypted persistent disk and need an off-VM target for disk-loss recovery. The MFA-bound host credential-replacement workflow requires a target-host Secret Manager smoke test. These are explicit remaining production acceptance items; the PR must stay draft until resolved or the owner approves a revised scope.

## Recorded local checks — October 4, 2026

- Release solution build: success, zero warnings/errors.
- .NET acceptance: 67 passed, zero failed/skipped.
- Proxy boundaries: 10 passed.
- All four application/proxy image builds: success from recorded pinned bases; ingress uses the pinned nginx base.
- Container fixture TLS/security checks: passed, including independent mTLS proxy role and exact-destination denials. No live brokerage credentials were mounted.
- Terraform 1.13.5 init/fmt/validate: passed; rendered startup script and shell/Python syntax checks passed.
- NuGet dependency audit: no known vulnerable packages in the configured feed, including transitive dependencies.
- Diff/secret checks: passed; high-confidence staged token/private-key scan found no secrets. `.vscode/` and local `.env` are excluded.
- Host-firewall namespace acceptance: blocked locally by password-required sudo; target/CI execution pending.
