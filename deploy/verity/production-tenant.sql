-- Take the tenant out of development mode.
--
-- A tenant that is in development mode says so, in two places: the
-- sign-in page carries a "You're in development mode" banner, and the
-- admin console offers to create a production tenant instead. Neither
-- belongs on a deployment that is being used.
--
-- The tenant is in development mode because the tag says so. The tag is
-- what the provider reads to decide, and the admin tenant is exempt
-- either way.
--
-- The provider runs in cloud mode so that its admin console works, and
-- the banner only appears in cloud mode. That is why it showed up at
-- all.

\set ON_ERROR_STOP on

BEGIN;

UPDATE tenants
SET tag = 'production'
WHERE tag = 'development';

COMMIT;

-- The tenants and their tags.
SELECT id, name, tag FROM tenants ORDER BY id;
