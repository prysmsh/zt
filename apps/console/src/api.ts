import type { AuditEvent, MeshNode, Network, Policy, Relay } from './types'

export interface ApiEnvelope<T> {
  data: T
  requestId: string
  generatedAt: string
}

export interface ListResponse<T> {
  items: T[]
  total: number
  nextCursor?: string
}

/** Wire shape returned by the Rust controller. */
export interface ControllerNetwork {
  id: string
  name: string
  description: string
  network_id: number
  cidr: string
  credential_ttl_secs: number
  created_at: number
}

export interface ControllerNode {
  id: string
  network_id: string
  name: string
  address: string
  public_key: string
  fingerprint: string
  tags: string[]
  platform: string | null
  version: string | null
  status: 'pending' | 'online' | 'degraded' | 'offline' | 'revoked'
  credential_issued_at: number
  credential_not_after: number
  last_seen: number | null
  created_at: number
}

export interface ControllerPolicy {
  id: string
  network_id: string
  name: string
  description: string
  protocol: 'any' | 'tcp' | 'udp' | 'icmp'
  port:
    | { any: null }
    | { single: number }
    | { range: [number, number] }
  source: Record<string, unknown>
  destination: Record<string, unknown>
  enabled: boolean
  created_at: number
  updated_at: number
}

export interface ControllerRelay {
  id: string
  name: string
  node_id: string
  endpoint: string
  networks: string[]
  enabled: boolean
  status: 'healthy' | 'degraded' | 'offline' | 'draining'
  created_at: number
  updated_at: number
}

export interface ControllerHealth {
  status: string
  version: string
  uptime_seconds: number
  networks: number
  nodes: number
  policies: number
  relays: number
}

export interface CreateNetworkInput {
  name: string
  description?: string
  cidr: string
  credentialTtlSecs?: number
}

export interface EnrollNodeInput {
  networkId: string
  name: string
  publicKey: string
  tags?: string[]
}

export interface EnrollNodeResult {
  node: MeshNode
  credential: string
  credentialNotAfter: number
}

export interface ApiClient {
  listNetworks(): Promise<ListResponse<Network>>
  listNodes(networkId?: string): Promise<ListResponse<MeshNode>>
  listPolicies(networkId?: string): Promise<ListResponse<Policy>>
  listRelays(networkId?: string): Promise<ListResponse<Relay>>
  listEvents(): Promise<ListResponse<AuditEvent>>
  health(): Promise<{ status: 'healthy' | 'degraded'; version: string; uptimeSeconds: number }>
  createNetwork(input: CreateNetworkInput): Promise<Network>
  enrollNode(input: EnrollNodeInput): Promise<EnrollNodeResult>
  revokeNode(nodeId: string): Promise<void>
  renewCredential(nodeId: string): Promise<EnrollNodeResult>
  deletePolicy(policyId: string): Promise<void>
  createPolicy(input: CreatePolicyInput): Promise<Policy>
  createRelay(input: CreateRelayInput): Promise<Relay>
  drainRelay(relayId: string): Promise<Relay>
}

export interface CreatePolicyInput {
  networkId: string
  name: string
  description?: string
  protocol: 'any' | 'tcp' | 'udp' | 'icmp'
  port: ControllerPolicy['port']
  source: Record<string, unknown>
  destination: Record<string, unknown>
  enabled?: boolean
}

export interface CreateRelayInput {
  name: string
  nodeId: string
  endpoint: string
  networks: string[]
  enabled?: boolean
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly requestId?: string,
    options?: { cause?: unknown },
  ) {
    super(message, options)
    this.name = 'ApiError'
  }
}

/**
 * Create a client for the tenant API.
 *
 * Every path is scoped to a tenant. The tenant ID is fixed when the client
 * is created, so a request can never be addressed to another tenant by
 * accident.
 *
 * The token provider supplies the bearer token for each request. It is a
 * function rather than a string, because the token is refreshed while the
 * console is open.
 */
export function createHttpClient(
  tenantId: string,
  baseUrl = '/api/v1',
  tokenProvider: () => string | null = () => null,
): ApiClient {
  // The base URL may or may not already include the version prefix.
  const root = baseUrl.replace(/\/api\/v1\/?$/, '')
  const tenantBase = `${root}/api/v1/t/${encodeURIComponent(tenantId)}`

  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    let response: Response
    try {
      // Paths are absolute against the API root. They already carry the
      // version prefix, so they are not prefixed with `baseUrl` again.
      const headers: Record<string, string> = {
        Accept: 'application/json',
        ...Object.fromEntries(new Headers(init?.headers).entries()),
      }
      const token = tokenProvider()
      if (token) {
        headers.Authorization = `Bearer ${token}`
      }
      response = await fetch(path.startsWith('/') ? path : `${baseUrl}/${path}`, {
        ...init,
        headers,
      })
    } catch (cause) {
      throw new ApiError(
        'The controller is not reachable. Check that it is running and that the API URL is correct.',
        0,
        undefined,
        { cause },
      )
    }
    if (response.status === 401) {
      throw new ApiError('You are signed out. Sign in again to continue.', 401)
    }
    if (!response.ok) {
      const body = await response.json().catch(() => null) as { error?: string } | null
      // A 5xx without a JSON body usually means a proxy could not reach the
      // controller. Report that plainly instead of surfacing the status text.
      if (!body?.error && response.status >= 500) {
        throw new ApiError(
          'The controller did not respond. It may be restarting or unreachable.',
          response.status,
        )
      }
      throw new ApiError(body?.error ?? `Request failed: ${response.statusText}`, response.status)
    }
    if (response.status === 204) return undefined as T
    return response.json() as Promise<T>
  }

  function post(body: unknown): RequestInit {
    return {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }
  }

  return {
    async listNetworks() {
      const result = await request<{ items: ControllerNetwork[]; total: number }>(`${tenantBase}/networks`)
      return { items: result.items.map(mapNetwork), total: result.total }
    },
    async listNodes(networkId) {
      const suffix = networkId ? `?network=${encodeURIComponent(networkId)}` : ''
      const result = await request<{ items: ControllerNode[]; total: number }>(`${tenantBase}/nodes${suffix}`)
      return { items: result.items.map(mapNode), total: result.total }
    },
    async listPolicies(networkId) {
      const suffix = networkId ? `?network=${encodeURIComponent(networkId)}` : ''
      const result = await request<{ items: ControllerPolicy[]; total: number }>(`${tenantBase}/policies${suffix}`)
      return { items: result.items.map(mapPolicy), total: result.total }
    },
    async listRelays(networkId) {
      const suffix = networkId ? `?network=${encodeURIComponent(networkId)}` : ''
      const result = await request<{ items: ControllerRelay[]; total: number }>(`${tenantBase}/relays${suffix}`)
      return { items: result.items.map(mapRelay), total: result.total }
    },
    async listEvents() {
      const result = await request<{ items: AuditEvent[]; total: number }>(`${tenantBase}/events`)
      return { items: result.items, total: result.total }
    },
    async health() {
      const result = await request<ControllerHealth>(`${root}/api/v1/control-plane`)
      return {
        status: result.status === 'healthy' ? 'healthy' : 'degraded',
        version: result.version,
        uptimeSeconds: result.uptime_seconds,
      }
    },
    async createNetwork(input) {
      const result = await request<ControllerNetwork>(
        `${tenantBase}/networks`,
        post({
          name: input.name,
          description: input.description ?? '',
          cidr: input.cidr,
          credential_ttl_secs: input.credentialTtlSecs,
        }),
      )
      return mapNetwork(result)
    },
    async enrollNode(input) {
      const result = await request<{
        node: ControllerNode
        credential: string
        credential_not_after: number
      }>(
        `${tenantBase}/nodes`,
        post({
          network_id: input.networkId,
          name: input.name,
          public_key: input.publicKey,
          tags: input.tags ?? [],
        }),
      )
      return {
        node: mapNode(result.node),
        credential: result.credential,
        credentialNotAfter: result.credential_not_after,
      }
    },
    async revokeNode(nodeId) {
      await request<void>(`${tenantBase}/nodes/${encodeURIComponent(nodeId)}/revoke`, { method: 'POST' })
    },
    async renewCredential(nodeId) {
      const result = await request<{
        node: ControllerNode
        credential: string
        credential_not_after: number
      }>(`${tenantBase}/nodes/${encodeURIComponent(nodeId)}/credential`, { method: 'POST' })
      return {
        node: mapNode(result.node),
        credential: result.credential,
        credentialNotAfter: result.credential_not_after,
      }
    },
    async createPolicy(input) {
      const result = await request<ControllerPolicy>(
        `${tenantBase}/policies`,
        post({
          network_id: input.networkId,
          name: input.name,
          description: input.description ?? '',
          protocol: input.protocol,
          port: input.port,
          source: input.source,
          destination: input.destination,
          enabled: input.enabled ?? true,
        }),
      )
      return mapPolicy(result)
    },
    async deletePolicy(policyId) {
      await request<void>(`${tenantBase}/policies/${encodeURIComponent(policyId)}`, { method: 'DELETE' })
    },
    async createRelay(input) {
      const result = await request<ControllerRelay>(
        `${tenantBase}/relays`,
        post({
          name: input.name,
          node_id: input.nodeId,
          endpoint: input.endpoint,
          networks: input.networks,
          enabled: input.enabled ?? true,
        }),
      )
      return mapRelay(result)
    },
    async drainRelay(relayId) {
      const result = await request<ControllerRelay>(
        `/relays/${encodeURIComponent(relayId)}/drain`,
        { method: 'POST' },
      )
      return mapRelay(result)
    },
  }
}

/** Map a controller network into the console's view model. */
export function mapNetwork(network: ControllerNetwork): Network {
  return {
    id: network.id,
    name: network.name,
    description: network.description,
    cidr: network.cidr,
    nodeCount: 0,
    onlineCount: 0,
    relayCount: 0,
    status: 'healthy',
    accent: 'cyan',
  }
}

/** Map a controller node into the console's view model. */
export function mapNode(node: ControllerNode): MeshNode {
  return {
    id: node.id,
    name: node.name,
    address: node.address,
    network: node.network_id,
    status: node.status,
    role: node.tags[0] ?? 'Node',
    platform: node.platform ?? 'Unknown',
    version: node.version ?? '—',
    lastSeen: node.last_seen ? relativeTime(node.last_seen) : 'Never',
    directPeers: 0,
    relayedPeers: 0,
    credentialExpires: credentialExpiry(node.credential_not_after),
    tags: node.tags,
    fingerprint: node.fingerprint,
    endpoint: undefined,
  }
}

/** Render a credential expiry as an absolute state or a relative countdown. */
export function credentialExpiry(notAfter: number): string {
  const remaining = notAfter - Math.floor(Date.now() / 1000)
  if (remaining <= 0) return 'Expired'
  if (remaining < 3600) return `Expires in ${Math.max(1, Math.floor(remaining / 60))}m`
  if (remaining < 86400) return `Expires in ${Math.floor(remaining / 3600)}h`
  return `Expires in ${Math.floor(remaining / 86400)}d`
}

/** Map a controller policy into the console's view model. */
export function mapPolicy(policy: ControllerPolicy): Policy {
  return {
    id: policy.id,
    name: policy.name,
    description: policy.description,
    protocol: policy.protocol.toUpperCase(),
    port: formatPort(policy.port),
    source: formatSelector(policy.source),
    destination: formatSelector(policy.destination),
    enabled: policy.enabled,
    updated: relativeTime(policy.updated_at),
  }
}

/** Map a controller relay into the console's view model. */
export function mapRelay(relay: ControllerRelay): Relay {
  return {
    id: relay.id,
    name: relay.name,
    address: relay.node_id,
    endpoint: relay.endpoint,
    networks: relay.networks.length,
    sessions: 0,
    availability: 100,
    bandwidth: '—',
    status: relay.status,
    enabled: relay.enabled,
  }
}

function formatPort(port: ControllerPolicy['port']): string {
  if ('single' in port) return String(port.single)
  if ('range' in port) return `${port.range[0]}–${port.range[1]}`
  return 'Any'
}

function formatSelector(selector: Record<string, unknown>): string {
  const kind = selector.kind as string | undefined
  switch (kind) {
    case 'tag':
      return `tag:${selector.tag}`
    case 'node':
      return `node:${selector.node_id}`
    case 'platform':
      return `platform:${selector.platform}`
    case 'subnet':
      return `subnet:${selector.cidr}`
    case 'network':
      return `network:${selector.network_id}`
    default:
      return 'any'
  }
}

function relativeTime(unixSeconds: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - unixSeconds)
  if (seconds < 60) return `${seconds}s ago`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  return `${Math.floor(seconds / 86400)}d ago`
}
