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

COMMIT;

-- What the console can now ask for.
SELECT application_id, scope_id FROM application_user_consent_resource_scopes WHERE application_id = 'admin-console';
