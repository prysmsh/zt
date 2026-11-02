-- Grant the admin console consent for the APIs it calls.
--
-- The provider seeds a Cloud API and a Me API for the admin tenant at
-- the admin endpoint's origin, and the admin console asks for them by
-- indicator. The fork's own alteration grants the console consent for
-- them, but it names the origins of one deployment, and it is a one-time
-- alteration, so a deployment that moved its admin endpoint afterwards
-- is left with a console that cannot use the Cloud API: it lists no
-- tenants and says the operator's roles are wrong.
--
-- This grants the consent for whatever the instance serves at the admin
-- endpoint's origin, without moving anything: a resource may already
-- hold that indicator, and the indicators are the deployment's business.
--
-- It is idempotent, so it can run on every start.

\set ON_ERROR_STOP on

BEGIN;

INSERT INTO application_user_consent_resource_scopes (tenant_id, application_id, scope_id)
SELECT 'admin', 'admin-console', s.id
FROM scopes s
JOIN resources res ON res.id = s.resource_id
WHERE res.tenant_id = 'admin'
  AND res.indicator IN ('https://admin.prysm.sh/api', 'https://admin.prysm.sh/me')
ON CONFLICT DO NOTHING;

-- The admin tenant's own machine, the one that calls the Management API
-- for the admin tenant, needs the scopes its role names. Without them it
-- authenticates and is then forbidden from every route: the machine's
-- role is bound, but no scope is attached to it.
INSERT INTO roles_scopes (tenant_id, id, role_id, scope_id)
VALUES ('admin', 'rs-mapi-admin', 'm-admin', 'scope-admin-mapi-all')
ON CONFLICT DO NOTHING;

-- The same machine, for the Cloud API at the admin origin. This is the
-- API the console lists the tenants through.
INSERT INTO roles_scopes (tenant_id, id, role_id, scope_id)
VALUES ('admin', 'rs-mapi-admin-cloud', 'm-admin', 'sc-prysm-admin-api')
ON CONFLICT DO NOTHING;

COMMIT;

-- What the console can now ask for.
SELECT application_id, scope_id FROM application_user_consent_resource_scopes WHERE application_id = 'admin-console';

-- What the admin tenant's machine can now ask for.
SELECT role_id, scope_id FROM roles_scopes WHERE role_id = 'm-admin';
