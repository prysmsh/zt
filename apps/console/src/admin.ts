import type { AuditEvent, Network } from './types'

/** A tenant of the control plane. */
export interface Tenant {
  id: string
  name: string
  slug: string
  deployment: 'shared' | 'dedicated'
  status: 'provisioning' | 'active' | 'suspended' | 'deleted'
  plan: string
  limits: {
    max_networks: number
    max_nodes: number
    max_policies: number
    max_relays: number
    max_credential_ttl_secs: number
  }
  controller_id: string | null
  controller_public_key: string | null
  created_at: number
  updated_at: number
  suspended_at: number | null
  deleted_at: number | null
}

/** Resource usage for a tenant. */
export interface TenantUsage {
  networks: number
  nodes: number
  policies: number
  relays: number
}

/** What a tenant owes for the period. */
export interface Invoice {
  tenant_id: string
  usage: {
    period_start: number
    period_end: number
    bytes_in: number
    bytes_out: number
    packets: number
    node_seconds: number
    samples: number
  }
  node_month_cents: number
  gigabyte_cents: number
  node_charges_cents: number
  traffic_charges_cents: number
  total_cents: number
  currency: string
}

/** Health of the control plane as a whole. */
export interface ControlPlaneHealth {
  status: string
  version: string
  uptime_seconds: number
  tenants: number
  active_tenants: number
  shared_tenants: number
  dedicated_tenants: number
  networks: number
  nodes: number
  policies: number
  relays: number
}

export interface CreateTenantInput {
  name: string
  slug: string
  deployment: 'shared' | 'dedicated'
  plan: string
  limits?: Partial<Tenant['limits']>
}

/**
 * Client for the master console API.
 *
 * This is separate from the tenant API client on purpose. The master
 * console talks to `/api/v1/tenants` and `/api/v1/control-plane`; a
 * tenant's own console talks to `/api/v1/t/{tenant}`. Mixing the two in one
 * client would make it easy to send a tenant-scoped request to the master
 * API by mistake.
 */
export interface AdminApiClient {
  health(): Promise<ControlPlaneHealth>
  listTenants(): Promise<Tenant[]>
  getTenant(id: string): Promise<Tenant>
  createTenant(input: CreateTenantInput): Promise<Tenant>
  updateTenant(id: string, changes: { plan?: string; limits?: Partial<Tenant['limits']> }): Promise<Tenant>
  suspendTenant(id: string, reason: string): Promise<Tenant>
  reactivateTenant(id: string): Promise<Tenant>
  deleteTenant(id: string): Promise<Tenant>
  tenantUsage(id: string): Promise<{ usage: TenantUsage; limits: Tenant['limits'] }>
  tenantInvoice(id: string): Promise<Invoice>
  tenantEvents(id: string): Promise<AuditEvent[]>
  tenantNetworks(id: string): Promise<Network[]>
}

export class AdminApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
    this.name = 'AdminApiError'
  }
}

/**
 * Create a client for the master console API.
 *
 * The bearer token is read on every request, because it is refreshed while
 * the console is open.
 */
export function createAdminClient(
  baseUrl = '/api/v1',
  tokenProvider: () => string | null = () => null,
): AdminApiClient {
  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response
    try {
      const headers: Record<string, string> = {
        Accept: 'application/json',
        ...Object.fromEntries(new Headers(init?.headers).entries()),
      }
      const token = tokenProvider()
      if (token) {
        headers.Authorization = `Bearer ${token}`
      }
      response = await fetch(`${baseUrl}${path}`, { ...init, headers })
    } catch {
      throw new AdminApiError(
        'The control plane is not reachable. Check that it is running.',
        0,
      )
    }
    if (response.status === 401) {
      throw new AdminApiError('You are signed out. Sign in again to continue.', 401)
    }
    if (response.status === 403) {
      throw new AdminApiError(
        'Your account does not have operator access to the master console.',
        403,
      )
    }
    if (!response.ok) {
      const body = await response.json().catch(() => ({ error: response.statusText }))
      throw new AdminApiError(body.error ?? `Request failed: ${response.statusText}`, response.status)
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }

  function post(body?: unknown): RequestInit {
    return {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
    }
  }

  function patch(body: unknown): RequestInit {
    return {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }
  }

  return {
    async health() {
      return request<ControlPlaneHealth>('/control-plane')
    },
    async listTenants() {
      const result = await request<{ items: Tenant[] }>('/tenants')
      return result.items
    },
    async getTenant(id) {
      return request<Tenant>(`/tenants/${encodeURIComponent(id)}`)
    },
    async createTenant(input) {
      return request<Tenant>('/tenants', post(input))
    },
    async updateTenant(id, changes) {
      return request<Tenant>(`/tenants/${encodeURIComponent(id)}`, patch(changes))
    },
    async suspendTenant(id, reason) {
      return request<Tenant>(`/tenants/${encodeURIComponent(id)}/suspend`, post({ reason }))
    },
    async reactivateTenant(id) {
      return request<Tenant>(`/tenants/${encodeURIComponent(id)}/reactivate`, post())
    },
    async deleteTenant(id) {
      return request<Tenant>(`/tenants/${encodeURIComponent(id)}`, { method: 'DELETE' })
    },
    async tenantUsage(id) {
      return request<{ usage: TenantUsage; limits: Tenant['limits'] }>(
        `/tenants/${encodeURIComponent(id)}/usage`,
      )
    },
    async tenantInvoice(id) {
      return request<Invoice>(`/tenants/${encodeURIComponent(id)}/billing`)
    },
    async tenantEvents(id) {
      const result = await request<{ items: AuditEvent[] }>(
        `/tenants/${encodeURIComponent(id)}/events`,
      )
      return result.items
    },
    async tenantNetworks(id) {
      const result = await request<{ items: Network[] }>(
        `/tenants/${encodeURIComponent(id)}/networks`,
      )
      return result.items
    },
  }
}
