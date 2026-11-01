# Deploying the ZT-next console

The console and the control plane are deployed together, behind a single
Caddy that terminates TLS.

```
                     ┌───────────────────────────────┐
  zt.hardening.dev   │  caddy  :443                  │
  ─────────────────▶│    /            → console      │
                     │    /api/        → controller  │
                     │    /auth/callback → console   │
                     └───────────────────────────────┘
                              │            │
                     ┌────────▼───┐  ┌─────▼──────────┐
                     │  console   │  │  controller    │
                     │  (nginx)   │  │  (Rust)        │
                     │  static    │  │  :8080         │
                     └────────────┘  └─────┬──────────┘
                                            │ verifies tokens
                                     ┌──────▼───────────┐
                                     │  Verity (OIDC)   │
                                     │  auth.prysm.sh   │
                                     └──────────────────┘
```

The controller is **not** published to the host. Only Caddy is, and it
reaches the controller over the compose network. The controller therefore
has no public socket to attack, and the only way in is through Caddy's TLS
termination.

## The three services

| Service | What it is | Published |
|---|---|---|
| `caddy` | TLS termination, routing | 80, 443 |
| `console` | The static bundle, served by nginx | No |
| `controller` | The control plane API | No |

## Deploying

```bash
cd deploy
cp .env.example .env
# Set ZT_PUBLIC_HOST and ACME_EMAIL.
./deploy.sh up
```

The first build compiles the Rust workspace, so it takes a few minutes.
Later builds reuse the layer cache.

### Commands

| Command | What it does |
|---|---|
| `./deploy.sh up` | Build and start |
| `./deploy.sh down` | Stop |
| `./deploy.sh rebuild` | Rebuild from scratch and restart |
| `./deploy.sh status` | Show what is running |
| `./deploy.sh logs` | Follow the logs |
| `./deploy.sh check` | Verify the deployment |

## Authentication

The controller requires a bearer token on every route except the health
check. Tokens are issued by Verity and verified against its JWKS.

| Tier | Routes | Requirement |
|---|---|---|
| Public | `/api/v1/health` | Nothing |
| Tenant | `/api/v1/t/{tenant}/...` | A token naming that tenant |
| Operator | `/api/v1/tenants/...` | The operator role |

A token for one tenant cannot reach another tenant's objects, and a token
without the operator role cannot create or delete tenants.

The controller **refuses to start** if it is unauthenticated and bound to
anything other than loopback. A misconfiguration cannot expose the master
console.

## Setting up Verity

The console needs three things in the OIDC provider: an application, a
scope, and a role.

### 1. The application

A single-page application that uses the authorization code flow with PKCE,
so the browser holds no client secret.

```sql
INSERT INTO applications (tenant_id, id, name, secret, type,
                           oidc_client_metadata, custom_client_metadata,
                           custom_data, is_third_party,
                           app_level_access_control_enabled)
VALUES ('default', 'zt-console-app-001', 'ZT Console', 'unused-for-pkce', 'SPA',
        '{"redirectUris": ["https://zt.hardening.dev/auth/callback"],
          "postLogoutRedirectUris": ["https://zt.hardening.dev/"],
          "grantTypes": ["authorization_code", "refresh_token"],
          "responseTypes": ["code"],
          "tokenEndpointAuthMethod": "none",
          "idTokenSignedResponseAlgorithm": "ES384",
          "scope": "openid profile email offline_access roles"}',
        '{"tenantId": "default"}', '{}', false, false);
```

The `scope` in the client metadata matters. A client may only be granted
the scopes listed there, and the `roles` scope is what puts the operator's
roles in the ID token.

### 2. The scope

```sql
INSERT INTO scopes (tenant_id, id, resource_id, name, description)
VALUES ('admin', 'zt-op-scope-000001', '<resource-id>', 'zt:operator',
        'Access to the ZT-next master console.');
```

The resource must be the one the console's token is minted for. Its
indicator is the `ZT_OIDC_AUDIENCE` value.

### 3. The role

Logto resolves an application's scopes through its roles, so the role is
what actually grants access.

```sql
INSERT INTO roles (tenant_id, id, name, description, type, is_default)
VALUES ('default', 'zt-operator-role-001', 'zt:operator',
        'Grants access to the ZT-next master console.', 'User', false);

INSERT INTO roles_scopes (tenant_id, id, role_id, scope_id)
VALUES ('default', 'zt-urs-0000000000001', 'zt-operator-role-001', 'zt-op-scope-000001');

INSERT INTO users_roles (tenant_id, id, user_id, role_id)
VALUES ('default', 'zt-ur-0000000000001', '<user-id>', 'zt-operator-role-001');
```

The role's `tenant_id` must match the tenant that owns the scope. The
scope's `tenant_id` must match the tenant that owns the resource. A
mismatch is silent: the role exists, the token is issued, and the claim is
simply missing.

### Verifying

```bash
# The provider must advertise the roles scope.
curl -s https://auth.prysm.sh/oidc/.well-known/openid-configuration | jq .scopes_supported

# A token must carry the role.
#   "roles": ["zt:operator"]
```

## The callback route

The console reads the authorization code from the URL's query string, so
Caddy serves the console's own page at `/auth/callback` rather than
redirecting. The code is a one-time credential, so the console removes it
from the URL as soon as the exchange succeeds.

## Behind Cloudflare

The console's hostname is proxied by Cloudflare, which means the origin has
to present a certificate for the hostname. ACME cannot validate through a
proxy: the challenge request reaches Cloudflare's edge, not the origin.

The origin therefore presents a self-signed certificate, and the zone's
**SSL/TLS encryption mode must be "Full"**, not "Strict". In "Full" mode
Cloudflare accepts any origin certificate. The browser still sees
Cloudflare's edge certificate, which is publicly trusted.

"Strict" mode rejects the self-signed origin certificate and returns
**526 Invalid SSL Certificate**. This is the one Cloudflare setting that has
to be right.

If the zone must stay in "Strict" mode, the origin needs a publicly-trusted
certificate, which means either a Cloudflare API token for DNS-01, or a
Cloudflare Origin CA certificate installed on the origin.

The certificate covers every hostname the origin serves:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem \
  -days 3650 -subj "/CN=auth.prysm.sh" \
  -addext "subjectAltName=DNS:auth.prysm.sh,DNS:*.auth.prysm.sh,DNS:prysm.sh,DNS:zt.hardening.dev"
```

## Routing the hostname

The host's ports 80 and 443 are held by the Verity stack, so the console
runs on its own port and the Verity Caddy routes the hostname to it.

The two stacks share a network, so the Verity Caddy can reach the
console's Caddy by name:

```yaml
# In the console's compose file.
networks:
  verity:
    external: true
    name: verity-deploy_default
```

```caddyfile
# In the Verity Caddyfile.
zt.hardening.dev {
	import admin-tls.caddy
	encode zstd gzip
	reverse_proxy zt-caddy:80
}
```

## Operating

The controller's state lives in the `controller-data` volume. It holds the
SQLite database and the controller's identity key. The identity key is the
controller's signing key: losing it means every credential it issued stops
verifying, and every node has to re-enroll.

```bash
# Back it up.
docker compose exec controller tar czf - /var/lib/zt-next > controller-backup.tar.gz
```

### Rotating the controller identity

```bash
docker compose down
docker compose run --rm controller zt-controller-init
docker compose up -d
```

Every node must then re-enroll.

## What this does not cover

- **The master console has no per-action audit of who did what.** The
  controller records the action and the tenant, but the acting operator is
  not yet attached to the audit entry.
- **There is no data plane.** The controller issues credentials and the
  nodes exchange packets, but there is no TUN device, so traffic does not
  actually route between the nodes.
- **The Tailscale dialect is not wire-compatible.** It uses BLAKE3 where
  upstream uses BLAKE2s.
