# Deployment

## Required inputs

Supply a Google Cloud project with billing/APIs enabled, a DNS domain, operator email for IAP/OS Login, alert email, the owner's immutable Google subject, a Google OAuth client ID and callback `https://DOMAIN/owner/google-callback`. Supply production E*TRADE consumer credentials, a new 32-byte token encryption key, an internal CA and separate mTLS leaf certificates for ingress, MCP, authorization, gateway and both proxies, a public TLS certificate/key, separate token signing/encryption certificates and a separate RSA assertion key. Each leaf needs its exact service DNS SAN and appropriate client/server EKUs. Never deploy the CA private key.

Create secret **containers** in Secret Manager administratively (or set `manage_secret_containers=true` to create empty containers), then add payload versions outside Terraform. Bootstrap the registry/secret containers before uploading images/payloads and creating the VM; use separate reviewed Terraform applies or import existing resources. `secret_ids` maps owning-service/filename to secret identifiers, never payloads. Host IAM grants access only to those secrets. Secret payloads, private keys, passwords, OAuth tokens and Google/E*TRADE secrets must never appear in Git, Terraform variables/state, VM metadata, image layers or deployment bundles.

| Owner | Mounted filenames |
|---|---|
| ingress | `ca.crt`, `ingress.pfx.pem` (leaf PEM), `ingress.key`, `public.crt`, `public.key` |
| mcp | `ca.crt`, `service.pfx` |
| authorization | `ca.crt`, `service.pfx`, `token-signing.pfx`, `token-encryption.pfx`, `assertion-private.pem`, `google-client-secret` |
| brokerage-proxy | `ca.crt`, `service.crt`, `service.key` |
| identity-proxy | `ca.crt`, `service.crt`, `service.key` |
| gateway | `ca.crt`, `service.pfx`, `assertion-public.pem`, `token-key`, `consumer-key`, `consumer-secret` |

PKCS#12 files have no container-side password and are protected by Secret Manager, host permissions and owning-container mounts. Token encryption and signing certificates must be distinct from mTLS and assertion keys. Mount secret files mode 0600, owning directories 0700 and application state owned by UID/GID 10001. The gateway token store requires Unix locks and fsync semantics; do not use a shared network filesystem.

## Build, infrastructure and fixture rollout

1. Review and test the branch. `deploy/base-images.json` pins linux/amd64 bases; build with `python3 deploy/build-images.py REGISTRY_PREFIX`. Push the three service images and the proxy image to your Artifact Registry and record repository digests. Both proxies may use the same pinned image with different hostname configuration. Pin ingress to the recorded nginx base digest. Re-run image vulnerability checks at rollout.
2. Place only reviewed deployment code/configuration in a tar bundle, excluding `.env`, `.git`, build output, secrets, keys and state. Upload to a private GCS bucket. Record its SHA256 and object generation; enable bucket object versioning or use an immutable object name. The VM downloads and verifies that exact bundle.
3. Supply Terraform inputs in a private ignored file. `images` must include `ingress`, `mcp`, `authorization`, `gateway`, `brokerage-proxy`, `identity-proxy`. Defaults are one Shielded `e2-medium`, `us-east4-a`, encrypted persistent disk, static IPv4, no autoscaling. Terraform also creates Artifact Registry, telemetry/audit retention and alerts. It never creates a secret payload version. Apply only after a reviewed plan. Set the domain's A record to the static IP and provide a valid public TLS certificate; renew that certificate through a host process and stop-before-start ingress replacement.
4. The host startup service downloads secrets, mounts persistent storage and boots **fixtures** by default. The fixture gateway mounts a separate directory containing only its mTLS certificate, CA and assertion public key; production brokerage secrets remain outside it. Startup fails closed until ownership is provisioned. Connect with `gcloud compute ssh etrade-mcp --tunnel-through-iap --zone us-east4-a`. SSH is reachable only through IAP and uses OS Login.
5. Provision the owner once, offline on the host:

   ```bash
   cd /opt/etrade/deploy
   docker compose -f compose.yaml -f compose.fixtures.yaml run --rm --no-deps authorization --provision-owner
   docker compose -f compose.yaml -f compose.fixtures.yaml create
   sudo ./firewall.sh
   docker compose -f compose.yaml -f compose.fixtures.yaml start
   ```

   Transfer the mode-0600 `/srv/etrade/state/authorization/owner-bootstrap.txt` over IAP, enroll the TOTP device, save recovery codes offline, then delete the bootstrap file. Provisioning never prints recovery secrets into Docker/application logs. There is no public registration or online owner recovery endpoint.
6. Run `sudo ./verify-network.sh` on the dedicated installation. Test public TLS, HTTPS-only ingress, owner subject/TOTP/CSRF, persistence/restart, all ten fixture tools, separate clients/grants, revocation and token reuse. Fixture data contains no financial information. Assert the gateway received no external bearer. Record the results. Test every intended hosted/local client's credential isolation; leave incompatible shared platforms unenrolled.

## Clients and CIMD

Owner console enrollment takes platform identity, unique client ID, exact HTTPS redirects and an explicit isolated-connection affirmation. It creates one client per agent, no wildcard redirects and no grant resurrection. Approving changes to client metadata revokes the old grant. Provision a fresh client/agent identity for a replacement connection. Grant lifetime is 30 days from owner approval; access tokens last five minutes and refresh tokens rotate without extending the grant lifetime. Reuse revokes that agent grant.

Supported clients use authorization code + S256 PKCE and the exact resource `https://DOMAIN/mcp`, with `etrade.read` and optional `offline_access`. Public clients using `token_endpoint_auth_method=none` are supported. Confidential/key-based methods and native non-HTTPS redirect schemes are intentionally rejected pending implementation and fixture verification. This is a compatibility limit, not an assertion that every MCP platform works.

For CIMD, manually approve each exact HTTPS metadata URL in `authorization-settings.json` and in the independent identity fetch service's `approved-urls.json`. Metadata is fetched through the restricted proxy, bounded to 32 KiB/five seconds with redirects disabled and public-IP checks/address pinning in the proxy. The document must match the client ID, supported flow, auth method and exact redirects. Every authorization compares the effective metadata hash to the owner's approved hash; changes require reapproval. Unknown properties, including unsupported key-source locations, fail closed. No endpoint auto-registers a discovered URL. Document approval never supplies an agent grant.

The identity fetch service independently fixes Google token/user-info URLs and permits only exact approved metadata URLs, GET or the fixed Google authorization-code POST, bounded bodies and allowed Google bearer use. It rejects redirects and pins checked public IPv4 addresses while validating provider TLS. Both proxies require their caller's service mTLS certificate. Brokerage traffic tunnels its original TLS session through the separately authenticated proxy connection.

## Production activation

After fixture acceptance, stop all containers. Remove only the fixture override, recreate containers, apply the host firewall **before** starting, and restart. Never run fixture and production stacks against the same state simultaneously. Sign in as the owner, verify TOTP, then start and complete a fresh E*TRADE authorization flow in the owner console. Pending flows are serialized and expire after ten minutes. The console displays expiry and recovery state; agents receive only sanitized reauthorization errors.

Perform minimal live reads (accounts, one balance/quote) and verify redacted telemetry. Never test a forbidden operation against live E*TRADE. Prove rejection exclusively using mocks/network tests. Live deployment, Google sign-in, real TOTP device setup, E*TRADE privileges and ChatGPT/Meta Muse compatibility require external credentials/infrastructure and must be recorded separately from local test results.

Brokerage credential versions are pinned on the host at first retrieval. Reboots do not silently adopt a new latest version; later replacements require the MFA-bound approval workflow in the operations runbook.
