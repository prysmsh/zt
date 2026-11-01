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
                                     │  prysm.sh        │
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
VALUES ('default', 'zt-op-scope-000001', '<resource-id>', 'zt:operator',
        'Access to the ZT-next master console.');
```

### 3. The resource server

The API is a resource server. Registering it lets the console ask for a
token scoped to it, and lets the controller verify the token's audience.

```sql
INSERT INTO resources (tenant_id, id, name, indicator, is_default, access_token_ttl)
VALUES ('default', 'zt-console-api-res', 'ZT Console API',
        'https://zt.hardening.dev/api', false, 3600);
```

Without a resource server, the provider issues an **opaque** access token.
The controller verifies JWTs, so an opaque token is rejected.

### 4. The role

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

### The tenant must match

The resource, its scopes, the role, and the application must all live in
the tenant that serves the request. The provider resolves the resource
against the requesting tenant's rows, and the rows are protected by
row-level security, so a resource in another tenant is simply invisible.

A mismatch is silent. The application is registered, the sign-in works,
the token is issued, and the claim is missing — or the token is opaque, or
the scope is dropped.

The console's own `ZT_OIDC_ISSUER` must be the provider's issuer URL, so
the controller verifies the issuer the token actually carries.

### The admin console needs the cloud API

Verity's own admin console is a separate application, and it asks for the
Cloud API resource on its own origin. That resource needs a scope the
console's application may request and the operator's role carries, or the
console lists no tenants and refuses to go on.

`deploy/verity/grant-console-cloud-api.sql` registers the resource on the
admin origin, links it to the console's application, and grants it to the
admin tenant's `user` and `admin` roles. Run it once against the
provider's database:

```bash
docker cp grant-console-cloud-api.sql verity-deploy-postgres-1:/tmp/grant.sql
docker exec verity-deploy-postgres-1 psql -U postgres -d logto -f /tmp/grant.sql
```

It also clears the protected-app metadata of the applications that are not
protected apps. The console validates the shape of every application the
management API returns, and a partial metadata object fails that check, so
the application list shows an error instead of the applications.

The console's own `ZT_OIDC_AUDIENCE` must be the resource's indicator, so
the controller verifies the audience the token actually carries.

### Verifying

```bash
# The provider must advertise the roles scope.
curl -s https://prysm.sh/oidc/.well-known/openid-configuration | jq .scopes_supported

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
  -days 3650 -subj "/CN=prysm.sh" \
  -addext "subjectAltName=DNS:prysm.sh,DNS:*.prysm.sh,DNS:admin.prysm.sh,DNS:zt.hardening.dev"
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

## The Verity admin console

The admin console is at **`https://admin.prysm.sh/console`**, with the
username `admin`.

### Why it has its own hostname

Verity runs two HTTP listeners, and the **port selects the tenant**:

| Listener | Tenant | Issuer |
|---|---|---|
| `3001` | core (default) | `https://prysm.sh/oidc` |
| `3003` | admin | `https://admin.prysm.sh/oidc` |

Each tenant runs its own OIDC provider with its own issuer URL, so the two
must have **different origins**. If they shared one, an ID token minted by
the admin console would be indistinguishable from one minted for a normal
application, and the management API's CORS allowlist — which is built from
`ADMIN_ENDPOINT` — would collide with the core tenant's origin.

A separate hostname is the clean way to differ. A separate port also works,
and the stack listened on `:8443` while the hostname was settling; that
listener is retired now, and the stack publishes only 80 and 443.

### The origin is embedded in the resource indicators

The console derives the Me API and the Cloud API from the origin it is
served at, and asks for them as resource indicators. When the origin
changes, the indicators have to change with it, or the sign-in fails with
`invalid_target: resource indicator is missing, or unknown`.

Both origins are registered, so a client on either one resolves:

| Resource | Indicator |
|---|---|
| Me API (admin origin) | `https://admin.prysm.sh/me` |
| Cloud API (admin origin) | `https://admin.prysm.sh/api` |
| Me API (apex) | `https://prysm.sh/me` |
| Management API (admin tenant) | `https://prysm.sh/_tenants/admin/api` |
| Management API (default tenant) | `https://prysm.sh/_tenants/default/api` |

### Verity's own settings

These live in the Verity deployment, not in this repository:

| Setting | Value |
|---|---|
| `ENDPOINT` | `https://prysm.sh` |
| `ADMIN_ENDPOINT` | `https://admin.prysm.sh` |
| `ADMIN_PORT` | `3003` |
| `IS_CLOUD` | `1` |

`IS_CLOUD` has to be set. The console bundle is built for cloud mode: it
reads the current user through `/a` and lists the tenants through
`/api/tenants` on its own origin. The server only serves those routes when
it runs in the same mode. Without it the console never finishes loading and
stops at its spinner.

Two database grants follow from it. The console asks for the Cloud API
resource on its own origin, so that resource needs a scope the console's
application may request and the operator's role carries, and an application
that is not a protected app must have null protected-app metadata rather
than a partial one. `deploy/verity/grant-console-cloud-api.sql` does both.

The origin's certificate must cover both hostnames:

```bash
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout key.pem -out cert.pem \
  -days 3650 -subj "/CN=prysm.sh" \
  -addext "subjectAltName=DNS:prysm.sh,DNS:*.prysm.sh,DNS:admin.prysm.sh,DNS:zt.hardening.dev"
```

### The console's loading screen

While the console boots it shows the platform's logo above a spinner. That
splash is replaced as soon as the console mounts, so hiding it removes the
branding without changing anything the operator uses.

`deploy/verity/patch-console.js` injects a rule into the console's HTML
before the server starts:

```css
#app>div:has(>svg+span){display:none!important}
```

The selector matches the loading screen's shape — a div holding an svg and
a span — and nothing in the mounted console matches it. The patch is
idempotent, so it is safe on every start.

The Verity deployment runs it by mounting the script and calling it from
the service's command:

```yaml
    entrypoint: ["sh", "-c"]
    command:
      - npm run cli db seed -- --swe && npm run cli db alteration deploy "…" && node /etc/logto/zt-patch-console.js && npm start
    volumes:
      - ./patch-console.js:/etc/logto/zt-patch-console.js:ro
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
- **The interface is not configured by the agent.** The data plane routes
  packets between the nodes, but the virtual interface has to be set up by
  the operating system before the agent runs.
- **The Tailscale dialect is not wire-compatible end to end.** The
  handshake now matches upstream exactly — it is checked against a
  handshake captured from the Linux kernel's WireGuard implementation — but
  there is no control plane for a `tailscaled` peer to be pointed at.
