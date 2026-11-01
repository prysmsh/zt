import { GlobalValues } from '@logto/shared';
import { sql } from '@silverhand/slonik';

import type { AlterationScript } from '../lib/types/alteration.js';

/**
 * The admin console is granted consent for the Cloud API, the Me API and the admin tenant's
 * Management API, and those APIs are addressed by the admin endpoint's origin. The earlier grant
 * named the origins of one deployment, so on any other deployment the console was granted consent
 * for resources the instance does not serve, and could not use the Cloud API at all: it listed no
 * tenants and said the operator's roles were wrong.
 *
 * The indicators are taken from the admin endpoint the instance is running on, and the resources
 * are matched by name, so the grants hold wherever the deployment points.
 *
 * A resource is only moved when nothing else holds the indicator it is moving to. A deployment that
 * already has a resource at the admin endpoint — because it was seeded there, or because it moved
 * there once already — keeps it, and the grant below follows the indicator rather than the name.
 */
const adminTenantId = 'admin';
const adminConsoleAppId = 'admin-console';
const cloudApiName = 'Logto Cloud API';
const meApiName = 'Logto Me API';

const alteration: AlterationScript = {
  up: async (pool) => {
    const globalValues = new GlobalValues();
    const origin = globalValues.adminUrlSet.endpoint.origin;

    // The Cloud API is served by the instance itself, under `/api` on the admin endpoint. A
    // deployment that moved its admin endpoint after the database was seeded still has the resource
    // under the old origin, so it is moved back — unless something already holds the new one.
    await pool.query(sql`
      update resources set indicator = ${origin} || '/api'
      where tenant_id = ${adminTenantId} and name = ${cloudApiName}
        and indicator <> ${origin} || '/api'
        and not exists (
          select 1 from resources
          where tenant_id = ${adminTenantId} and indicator = ${origin} || '/api'
        )
    `);

    // The Me API, under `/me` on the same origin.
    await pool.query(sql`
      update resources set indicator = ${origin} || '/me'
      where tenant_id = ${adminTenantId} and name = ${meApiName}
        and indicator <> ${origin} || '/me'
        and not exists (
          select 1 from resources
          where tenant_id = ${adminTenantId} and indicator = ${origin} || '/me'
        )
    `);

    // The console is granted consent for the APIs it calls, by indicator: that is what the console
    // asks for, and a deployment may have more than one resource under a name.
    await pool.query(sql`
      insert into application_user_consent_resource_scopes (tenant_id, application_id, scope_id)
      select ${adminTenantId}, ${adminConsoleAppId}, s.id
      from scopes s
      join resources res on res.id = s.resource_id
      where res.tenant_id = ${adminTenantId}
        and res.indicator = any(${sql.array([`${origin}/api`, `${origin}/me`], 'text')})
      on conflict do nothing
    `);
  },
  down: async () => {
    // The consent records and the indicators may predate this alteration, so they are left in place.
  },
};

export default alteration;
