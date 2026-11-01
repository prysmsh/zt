# The admin console's grants, for a fork of Verity

Two problems in the fork stop the admin console from working on a
deployment whose admin endpoint is not the one the fork's own alteration
names. Both are in the database, and both are one-time alterations, so
they cannot be fixed by re-running them.

## The problem

`packages/schemas/alterations/1.46.0-1792940000-admin-console-grants.ts`
grants the console application consent for the Cloud API and the Me API,
and it names their indicators directly:

```ts
const cloudApiIndicators = ['https://auth.prysm.sh:8443/api', 'https://auth.prysm.sh:8443/me'];
```

Those are the origins of one deployment. On any other deployment the
console is granted consent for resources the instance does not serve, so
its request for the Cloud API matches nothing, and the console:

- lists no tenants,
- says the operator's roles and permissions are wrong,
- never gets past its loading screen.

The same alteration also re-points the admin tenant's Management API at
`https://prysm.sh/_tenants/admin/api` — this deployment's own domain —
again by name.

## Why moving the endpoint does not help

The provider seeds the Cloud API resource at the admin endpoint's origin
**at seed time** (`createCloudApi(adminUrlSet.endpoint.origin)` in the
CLI's seed). If the admin endpoint moves after the first start, the
resource keeps the old indicator.

The alteration that re-points it,
`1.46.0-1792600000-cloud-api-indicator.ts`, only matches the legacy
fixed host:

```ts
const legacyIndicator = 'https://cloud.meshx.app/api';
```

So it never touches a resource whose indicator came from the seed. And
because alterations run once, it will not run again anyway.

## The fix

`1.46.0-admin-console-grants-follow-the-admin-endpoint.ts` is a new
alteration for the fork:

- it takes the indicators from the admin endpoint the instance is
  running on, rather than naming them;
- it matches the resources by **name**, so it works wherever the
  deployment pointed the endpoint;
- it re-points the Cloud API and the Me API if they are still under an
  old origin;
- it re-grants the console's consent for them.

Drop it into `packages/schemas/alterations/` and deploy it:

```bash
npm run cli db alteration deploy <version>
```

The fork's own README says a change to an alteration belongs in a new
file, so this is a new file rather than an edit.

## And after a later move

A one-time alteration still cannot survive an admin endpoint that moves
**after** it has run. The durable fix is to run the same statements on
every start, before the server:

```sql
-- Move the Cloud API and the Me API to the admin endpoint the instance
-- is running on, and grant the console consent for them.
```

`deploy/verity/patches/admin-console-grants.sql` is that, and it is
idempotent. The provider's compose runs the alterations before it starts
the server, so adding it there is enough:

```yaml
command:
  - npm run cli db seed -- --swe
  - npm run cli db alteration deploy "$(node -p "require('/etc/logto/packages/cli/package.json').version")"
  - psql "$DB_URL" -f /etc/logto/zt-admin-console-grants.sql
  - node /etc/logto/zt-patch-console.js
  - npm start
```

## The deployment's own remedy

Until the fork carries the fix, this repository's
`deploy/verity/grant-console-cloud-api.sql` does the same work by hand:
it adds the Cloud API resource at the admin endpoint's origin, links it
to the console's application, and grants it to the admin tenant's `user`
and `admin` roles.
