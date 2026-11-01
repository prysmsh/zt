-- Give the admin console the Cloud API scope on its own origin.
--
-- The console is built for cloud mode. It reads the current user through
-- `/a` and lists the tenants through `/api/tenants` on its own origin.
-- Both are served by the Cloud API resource whose indicator is
-- `<admin endpoint>/api`, and both require a scope on that resource.
--
-- The resource itself is seeded with the CloudScope set, but the seeded
-- indicator follows the endpoint the instance was seeded with. This
-- instance serves the console from `https://admin.prysm.sh`, so the
-- resource is added for that origin, and the console is allowed to ask
-- for it.
--
-- The scope is named `all`, which the Cloud API accepts in place of any
-- single CloudScope.

\set ON_ERROR_STOP on

BEGIN;

-- The Cloud API at the console's origin.
INSERT INTO resources (id, tenant_id, name, indicator)
VALUES ('res-prysm-admin-api', 'admin', 'Logto Cloud API (admin origin)', 'https://admin.prysm.sh/api')
ON CONFLICT DO NOTHING;

-- Its scope.
INSERT INTO scopes (id, tenant_id, name, description, resource_id)
VALUES ('sc-prysm-admin-api', 'admin', 'all', 'Allow managing the tenants of this instance.', 'res-prysm-admin-api')
ON CONFLICT DO NOTHING;

-- The console may ask for it.
INSERT INTO application_user_consent_resource_scopes (tenant_id, application_id, scope_id)
VALUES ('admin', 'admin-console', 'sc-prysm-admin-api')
ON CONFLICT DO NOTHING;

-- The admin tenant's `user` role carries it, the way the seeded Cloud API
-- resource does. The `admin` role carries it too, so an operator of the
-- admin tenant can list and manage tenants.
INSERT INTO roles_scopes (tenant_id, id, role_id, scope_id)
VALUES
  ('admin', 'rs-prysm-user', 'stfkbax9ir683vnbkcgid', 'sc-prysm-admin-api'),
  ('admin', 'rs-prysm-admin', '976g84eownogfj6bswysm', 'sc-prysm-admin-api')
ON CONFLICT DO NOTHING;

COMMIT;

-- The protected-app metadata of an application that is not a protected app
-- has to be null. The console validates the shape of every application the
-- management API returns, and a partial object is not a valid one: it is
-- missing the host, the origin, the session duration, or the page rules.
-- The application list then fails to parse and the console shows an error.
UPDATE applications
SET protected_app_metadata = NULL
WHERE protected_app_metadata IS NOT NULL
  AND NOT (
    protected_app_metadata ? 'host'
    AND protected_app_metadata ? 'origin'
    AND protected_app_metadata ? 'sessionDuration'
    AND protected_app_metadata ? 'pageRules'
  );

-- What the console can now ask for.
SELECT application_id, scope_id FROM application_user_consent_resource_scopes WHERE application_id = 'admin-console';
