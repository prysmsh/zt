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

## Signing in to the forge

The forge at **`https://git.prysm.sh`** is a Forgejo instance, and it takes
the same identity from the same provider: a "Sign in with Verity" button on
its login page, backed by an OpenID Connect login source.

### The application

Forgejo is a confidential client: it holds a secret and exchanges the
authorization code with it, so it registers as a "Traditional" application
rather than a SPA. The client identifier is the application's id, which
Forgejo uses as its client key.

The redirect URI is not a choice. Forgejo builds its callback URL from the
name of the login source:

```
<ROOT_URL>/user/oauth2/<source name>/callback
```

so the source has to be named `Verity` for the registered URI to be the one
below. The scopes are what the identity is made of: `openid` makes the
provider issue an ID token, `profile` carries `preferred_username`, `email`
carries the address, and `roles` carries the Verity roles that map onto
Forgejo's administrator group.

`deploy/verity/forgejo-app.sql` writes the row. It is written directly
because the Management API path is broken on this instance — the quota guard
calls the admin tenant's Cloud API with a client that no longer
authenticates there, and the request fails with a 500.

The script generates the client secret rather than carrying one, and its
last query prints it. That value is what Forgejo is given below, and it is
the only one of the two secrets that leaves the machine: the provider keeps
an internal one of its own, behind the `#internal:` prefix.

### The login source

The source itself lives in Forgejo's database, added with its own CLI. The
secret is the one the script printed:

```bash
docker exec -u git gitea gitea admin auth add-oauth \
  --name Verity \
  --provider openidConnect \
  --key forgejoapp00000000001 \
  --secret '<the client secret>' \
  --auto-discover-url https://prysm.sh/oidc/.well-known/openid-configuration \
  --scopes openid --scopes profile --scopes email --scopes roles \
  --group-claim-name roles \
  --admin-group zt:operator \
  --skip-local-2fa
```

`--provider openidConnect` is the provider name the string has to be spelled
exactly; it is not a display name. `--auto-discover-url` points the source
at the provider's discovery document, so the endpoints are not configured by
hand.

`--group-claim-name roles` and `--admin-group zt:operator` are what make the
forge's administrator a Verity operator rather than a name on a list. The
`roles` claim is an array, and Forgejo reads the group out of it.

`--skip-local-2fa` is there because the forge account has no second factor
of its own: the provider is already the thing that proves who the user is.

### Registration stays closed

The forge has `DISABLE_REGISTRATION = true`, and it stays that way. Nothing
here turns it off.

That matters, because Forgejo's OpenID Connect login source would otherwise
create an account for anyone who authenticates against the provider. With
registration disabled, Forgejo has no account to give the returning user, and
its answer is the "Link to an existing account" page — which is not a
failure, it is the page where the user proves they own an existing forge
account by signing in to it with its password.

The result is that the forge's accounts are still made by its administrator,
and the provider only says *who* is signing in.

`ALLOW_ONLY_INTERNAL_REGISTRATION = true` is what closes the door on the
provider's side, and it is set for the same reason. Forgejo reads two
different flags here, and only the second one gates the OpenID Connect
source:

| Flag | What it gates |
|---|---|
| `DISABLE_REGISTRATION` | the forge's own sign-up form |
| `ALLOW_ONLY_INTERNAL_REGISTRATION` | account creation from an external provider |

The first one alone leaves the OpenID Connect source free to create an
account for any user the provider authenticates. The second one is the one
that has to be set for the forge's accounts to stay the administrator's to
make. It also takes the "Register new account" tab off the linking page, so
a user who arrives without a link is offered the one thing that works.

### Linking the accounts

The link is one row in Forgejo's `external_login_user` table, and it is
what makes the second sign-in a single click:

```
external_id      zt-console-user-001   -- the provider's subject
user_id          1                     -- the forge's administrator
login_source_id  1                     -- the "Verity" source
provider         Verity
email            zt-console@prysm.sh
```

The row is what Forgejo itself writes when the link is made through that
page, so making it by hand and making it through the page end in the same
place. Once it is there, signing in with Verity lands directly in the forge
account, with no password prompt and no link page.

The subject is the provider's `sub` claim, which is the user's id in the
tenant. It is stable, and it is what the provider puts in the ID token:

```bash
# The subject the provider issued.
docker exec verity-deploy-postgres-1 psql -U postgres -d logto \
  -c "SELECT id, tenant_id, username FROM users;"

# The link in the forge.
python3 -c "
import sqlite3
db = sqlite3.connect('/home/ubuntu/gitea-deploy/data/gitea/gitea.db')
for row in db.execute('SELECT external_id, user_id, login_source_id FROM external_login_user'):
    print(row)
"
```

### Verifying

```bash
# The button must be on the login page.
curl -s https://git.prysm.sh/user/login | grep -o 'user/oauth2/[A-Za-z]*'

# The source must be active.
docker exec -u git gitea gitea admin auth list
```

Signing in with Verity as a user holding the `zt:operator` role must land in
the forge as an administrator, and the forge's own administrator flag is
re-derived from the group claim on every sign-in.

### The operator's password

The provider stores the console operator's password as an Argon2i hash, so
it cannot be read back. It was reset on 2026-11-02, and the replacement is
in `~/verity-deploy/.console` on the host, next to the other credentials:

```bash
# The password must work.
TOKEN=$(curl -s -X POST https://prysm.sh/oidc/token \
  -d 'grant_type=client_credentials&client_id=m-default&client_secret=…&scope=all&resource=https://prysm.sh/api' \
  | jq -r .access_token)

curl -s -o /dev/null -w '%{http_code}\n' -X POST \
  https://prysm.sh/api/users/zt-console-user-001/password/verify \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"password":"…"}'
```

A `204` means the password is the right one.

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

## The landing page

`https://zt.hardening.dev` is the landing page: the product in front of
the console, which is at `https://zt.hardening.dev/console`.

It lives in `apps/landing` — a page, a stylesheet, a script, two fonts
and one image. There is no build step and no framework: the page is what
the browser gets.

The design is the brutalist terminal one from the v0 template
`brutalist-ai-saas-landing-page`, with the copy rewritten for ZT-next.
The tokens it uses are in `apps/landing/styles.css`: a warm off-white
ground, a near-black foreground, one orange accent, and no radii. The
display face is Geist Pixel over JetBrains Mono.

The files are content-addressed when the image is built, so a browser
that has one never asks again and a change produces a new name. Nothing
stale is ever served, not even from a cache in front of the container.

To change the copy, edit `apps/landing/index.html` and `app.js` and
rebuild. The build hashes the sources, so the browser picks the change up
at once.

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

## The admin console's grants, in the fork

The fork grants the admin console consent for the Cloud API and the Me
API in a database alteration, and that alteration names the origins of
one deployment directly. On any other deployment the console is granted
consent for resources the instance does not serve, so its request for
the Cloud API matches nothing: it lists no tenants and says the
operator's roles are wrong.

The alteration is also one-time, so a deployment that moves its admin
endpoint afterwards cannot be fixed by re-running it — the indicators
the resources carry came from the seed, and the alteration that re-points
them only matches a legacy fixed host.

`deploy/verity/patches/` has the fix for the fork: a new alteration that
takes the indicators from the admin endpoint the instance is running on
and matches the resources by name, and a script that does the same
statements on every start, so a later move is picked up.

`deploy/verity/grant-console-cloud-api.sql` is the deployment's own
remedy for a database that was seeded before the admin endpoint settled.

## Settle the admin endpoint before the provider's first start

The provider seeds a **Cloud API** resource whose indicator is the admin
endpoint's origin, and the admin console asks for that resource by
indicator. If the admin endpoint moves after the database was seeded, the
seeded resource keeps the old indicator and the console's request matches
nothing: the console lists no tenants and says the operator's roles are
wrong.

So the admin endpoint has to be settled before the provider's first
start. If the database was seeded earlier and the endpoint has since
moved, `deploy/verity/grant-console-cloud-api.sql` puts the resource
where the console expects it, links it to the console's application, and
grants it to the admin tenant's `user` and `admin` roles.

## The tenant must be out of development mode

A tenant that is in development mode says so in two places: the sign-in
page carries a "You're in development mode" banner, and the admin console
offers to create a production tenant instead. Neither belongs on a
deployment that is being used.

The provider decides this from the tenant's tag, and the banner only
appears when the provider runs in cloud mode — which it does, so that its
admin console works. `deploy/verity/production-tenant.sql` takes the
tenant out of development mode:

```bash
docker cp production-tenant.sql verity-deploy-postgres-1:/tmp/production-tenant.sql
docker exec verity-deploy-postgres-1 psql -U postgres -d logto -f /tmp/production-tenant.sql
```

The provider caches the answer, so it has to be restarted for the change
to take effect:

```bash
docker compose restart logto
```

## Metering and billing

A tenant is charged for the nodes it ran and the traffic it carried.

The node agent's data plane counts the bytes and packets it carries, and
reports them with its sighting. The controller keeps the samples, works
out the node-hours over the calendar month, and multiplies them by the
tenant's rates. The rates are on the tenant:

```json
{ "node_month_cents": 1200, "gigabyte_cents": 2, "currency": "EUR" }
```

The invoice is at `/api/v1/t/{tenant}/billing` for the tenant, and
`/api/v1/tenants/{id}/billing` for the operator. The master console shows
the estimate beside each tenant.

Nothing takes the money yet: the invoice is an estimate, not a debt.

## The node agent

A node is shown as online while it keeps talking to the controller, and as
offline once it stops. It talks to the controller by checking in, which
`zt-agent checkin` does.

```text
$ zt-agent checkin --controller https://zt.hardening.dev \
    --tenant <tenant-id> --state ~/zt-node/node.json --interval 30
```

`deploy/zt-agent.service` is that as a systemd unit. The node's identity
is created on first run:

```text
$ zt-agent identity --controller https://zt.hardening.dev --tenant <tenant-id>
public key: 3b2603764788463801053de34bb964b1bc03c84144a4b09da5865ab84db4a086
```

That key is what the operator enters in the console's "Enroll node"
dialog. The console then issues the node's credential, and the node
adopts it:

```text
$ zt-agent adopt --credential <credential> --controller https://zt.hardening.dev \
    --tenant <tenant-id> --state ~/zt-node/node.json
```

The credential is short-lived, and the agent renews it on its own: every
check-in renews it when three quarters of its life has elapsed. There is
nothing for an operator to do, and nothing to schedule. A node that is
renewing is healthy; the console's attention list only names a
credential once it is close enough to expiry that a failed renewal would
take the node off the mesh.

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
