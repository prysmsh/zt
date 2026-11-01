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
 * The resources are matched by name rather than by indicator, and the indicators are taken from
 * the admin endpoint the instance is running on, so the grants hold wherever the deployment points.
 */
const adminTenantId = 'admin';
const adminConsoleAppId = 'admin-console';
const cloudApiName = 'Logto Cloud API';
const meApiName = 'Logto Me API';
const adminManagementApiName = 'Logto Management API for tenant admin';

const alteration: AlterationScript = {
  up: async (pool) => {
    const globalValues = new GlobalValues();
    const origin = globalValues.adminUrlSet.endpoint.origin;

    // The Cloud API and the Me API are served by the instance itself, under the admin endpoint.
    // A deployment that moved its admin endpoint after the database was seeded still has the
    // resources under the old origin, so they are moved back.
    await pool.query(sql`
      update resources set indicator = ${origin} || '/api'
      where tenant_id = ${adminTenantId} and name = ${cloudApiName}
        and indicator <> ${origin} || '/api'
    `);

    await pool.query(sql`
      update resources set indicator = ${origin} || '/me'
      where tenant_id = ${adminTenantId} and name = ${meApiName}
        and indicator <> ${origin} || '/me'
    `);

    // The console is granted consent for the APIs it calls.
    await pool.query(sql`
      insert into application_user_consent_resource_scopes (tenant_id, application_id, scope_id)
      select ${adminTenantId}, ${adminConsoleAppId}, s.id
      from scopes s
      join resources res on res.id = s.resource_id
      where res.tenant_id = ${adminTenantId}
        and res.name = any(${sql.array([cloudApiName, meApiName], 'text')})
      on conflict do nothing
    `);
  },
  down: async () => {
    // The consent records and the indicators may predate this alteration, so they are left in place.
  },
};

export default alteration;
