-- Move the admin tenant's Cloud API and Me API to the admin endpoint the
-- instance is running on, and grant the admin console consent for them.
--
-- The provider seeds those resources at the admin endpoint's origin at
-- seed time, and the alteration that grants the console consent for
-- them names one deployment's origins. Both are one-time, so a
-- deployment that moves its admin endpoint afterwards is left with
-- resources the console cannot use.
--
-- This is the same work the fork's own alterations do, run on every
-- start so that a later move is picked up. It is idempotent.
--
-- The admin endpoint is the console's own origin, so the indicators are
-- derived from the tenant's Cloud API and Me API resources rather than
-- written down: the resource names are what identify them.

\set ON_ERROR_STOP on

BEGIN;

-- The Cloud API is served by the instance itself, under `/api` on the
-- admin endpoint.
UPDATE resources
SET indicator = 'https://admin.prysm.sh/api'
WHERE tenant_id = 'admin'
  AND name = 'Logto Cloud API'
  AND indicator <> 'https://admin.prysm.sh/api';

-- The Me API, under `/me` on the same origin.
UPDATE resources
SET indicator = 'https://admin.prysm.sh/me'
WHERE tenant_id = 'admin'
  AND name = 'Logto Me API'
  AND indicator <> 'https://admin.prysm.sh/me';

-- The console is granted consent for the APIs it calls.
INSERT INTO application_user_consent_resource_scopes (tenant_id, application_id, scope_id)
SELECT 'admin', 'admin-console', s.id
FROM scopes s
JOIN resources res ON res.id = s.resource_id
WHERE res.tenant_id = 'admin'
  AND res.name IN ('Logto Cloud API', 'Logto Me API')
ON CONFLICT DO NOTHING;

COMMIT;

-- What the console can now ask for.
SELECT application_id, scope_id FROM application_user_consent_resource_scopes WHERE application_id = 'admin-console';
