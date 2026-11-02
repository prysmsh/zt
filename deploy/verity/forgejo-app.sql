-- Register Forgejo as an OpenID Connect client of Verity.
--
-- Forgejo's OpenID Connect login source is a confidential client: it holds a
-- secret and exchanges the authorization code with it. That makes it a
-- "Traditional" application here (a web application with a backend), not a
-- SPA.
--
-- The redirect URI is fixed by Forgejo. The callback URL is built from the
-- name of the authentication source:
--
--     <ROOT_URL>/user/oauth2/<source name>/callback
--
-- so the source has to be named `Verity` for the URI to be the one below.
--
-- The scopes matter. `openid` makes Verity issue an ID token, which is what
-- Forgejo reads the user's identity from; `profile` carries
-- `preferred_username`, which is where Forgejo takes the account name from;
-- `email` carries the address, which Forgejo requires to create an account;
-- `roles` carries the Verity roles, which the `zt:operator` role maps to a
-- Forgejo administrator.
--
-- The two secrets are different values, and both are generated here rather
-- than written down. `application_secrets.value` is the secret Forgejo
-- holds; `applications.secret` is the internal one the provider itself
-- authenticates against, behind the `#internal:` prefix. This is the shape
-- Logto's Management API produces, and the same shape the middleware that
-- rewrites an incoming secret expects.
--
-- Nothing in this repository holds a secret. Run it, and read the secret
-- off the last query.
--
-- The Management API path is broken on this instance: creating an application
-- goes through the quota guard, which calls the admin tenant's Cloud API with
-- a client that no longer authenticates there. The row is written directly
-- instead.

\set ON_ERROR_STOP on

BEGIN;

-- The client secret Forgejo will hold. Thirty-two characters of the
-- alphabet the client-secret grammar allows, from the generator in the
-- database rather than from a shell, so it is not in anyone's history.
-- `gen_random_uuid` is built in, so this needs no extension.
CREATE TEMPORARY TABLE forgejo_secrets AS
SELECT replace(gen_random_uuid()::text, '-', '') AS client_secret,
       '#internal:' || replace(gen_random_uuid()::text, '-', '') AS internal_secret;

-- The application. The client identifier is the id: Forgejo uses it as the
-- client key.
INSERT INTO applications (tenant_id, id, name, secret, type,
                           oidc_client_metadata, custom_client_metadata,
                           custom_data, is_third_party,
                           app_level_access_control_enabled)
SELECT 'default', 'forgejoapp00000000001', 'Forgejo',
       internal_secret, 'Traditional',
       '{"redirectUris": ["https://git.prysm.sh/user/oauth2/Verity/callback"],
         "postLogoutRedirectUris": ["https://git.prysm.sh/"],
         "grantTypes": ["authorization_code", "refresh_token"],
         "responseTypes": ["code"],
         "tokenEndpointAuthMethod": "client_secret_basic",
         "idTokenSignedResponseAlgorithm": "ES384",
         "scope": "openid profile email roles offline_access"}',
       '{"tenantId": "default"}', '{}', false, false
FROM forgejo_secrets;

-- The secret Forgejo holds.
INSERT INTO application_secrets (tenant_id, application_id, name, value)
SELECT 'default', 'forgejoapp00000000001', 'Default secret', client_secret
FROM forgejo_secrets;

COMMIT;

-- The application, as the provider now knows it.
SELECT id, name, type, oidc_client_metadata
FROM applications
WHERE id = 'forgejoapp00000000001';

-- The secret Forgejo holds. This is the value to give Forgejo's
-- `admin auth add-oauth --secret`, and it is the only one of the two that
-- leaves this machine.
SELECT application_id, name, value AS client_secret
FROM application_secrets
WHERE application_id = 'forgejoapp00000000001';

-- The link to the forge's account.
--
-- Forgejo's own "Link to an existing account" page writes this row, and it
-- is what lets the second sign-in be a single click: Forgejo matches the
-- subject in the ID token against `external_id` and signs in as `user_id`.
--
-- The subject is the user's id in the tenant, and it is stable.
--
-- The forge's `external_login_user` table, not this one:
--
--   external_id      zt-console-user-001
--   user_id          1
--   login_source_id  1
--   provider         Verity
--   email            zt-console@prysm.sh
