import { describe, expect, it } from 'vitest'
import {
  mapNetwork,
  mapNode,
  mapPolicy,
  mapRelay,
  publicAddress,
  type ControllerNetwork,
  type ControllerNode,
  type ControllerPolicy,
  type ControllerRelay,
} from './api'

const network: ControllerNetwork = {
  id: 'net-1',
  name: 'Production',
  description: 'Core services',
  network_id: 42,
  cidr: '10.42.0.0/24',
  credential_ttl_secs: 86400,
  created_at: 1_700_000_000,
}

const node: ControllerNode = {
  id: 'node-1',
  network_id: 'net-1',
  name: 'web-01',
  address: 'aabbccddeeff001122',
  endpoint: '198.51.100.24:9994',
  public_key: 'aa'.repeat(32),
  fingerprint: '7A:4F:92:C1:08:DD',
  tags: ['web', 'production'],
  platform: 'Ubuntu 24.04',
  version: '0.3.1',
  status: 'online',
  credential_issued_at: 1_700_000_000,
  credential_not_after: Math.floor(Date.now() / 1000) + 3600,
  last_seen: Math.floor(Date.now() / 1000) - 10,
  created_at: 1_700_000_000,
}

describe('mapNetwork', () => {
  it('preserves identity fields and defaults counts', () => {
    const mapped = mapNetwork(network)
    expect(mapped.id).toBe('net-1')
    expect(mapped.name).toBe('Production')
    expect(mapped.cidr).toBe('10.42.0.0/24')
    expect(mapped.nodeCount).toBe(0)
    expect(mapped.onlineCount).toBe(0)
  })
})

describe('mapNode', () => {
  it('maps controller fields into the view model', () => {
    const mapped = mapNode(node)
    expect(mapped.id).toBe('node-1')
    expect(mapped.network).toBe('net-1')
    expect(mapped.status).toBe('online')
    expect(mapped.platform).toBe('Ubuntu 24.04')
    expect(mapped.tags).toEqual(['web', 'production'])
    expect(mapped.role).toBe('web')
    expect(mapped.fingerprint).toBe('7A:4F:92:C1:08:DD')
  })

  it('handles a node that has never checked in', () => {
    const mapped = mapNode({ ...node, last_seen: null, platform: null, version: null })
    expect(mapped.lastSeen).toBe('Never')
    expect(mapped.platform).toBe('Unknown')
    expect(mapped.version).toBe('—')
  })

  it('reports an expired credential as expired', () => {
    const mapped = mapNode({
      ...node,
      credential_not_after: Math.floor(Date.now() / 1000) - 60,
    })
    expect(mapped.credentialExpires).toBe('Expired')
  })

  it('carries the credential timestamps, so the console can reason on them', () => {
    const mapped = mapNode({
      ...node,
      credential_issued_at: 1_700_000_000,
      credential_not_after: 1_700_086_400,
    })
    expect(mapped.credentialIssuedAt).toBe(1_700_000_000)
    expect(mapped.credentialNotAfter).toBe(1_700_086_400)
  })

  it('preserves the revoked status', () => {
    const mapped = mapNode({ ...node, status: 'revoked' })
    expect(mapped.status).toBe('revoked')
  })

  it('tells a join request apart from a member that has not checked in', () => {
    // A join request: pending, no credential ever issued.
    const request = mapNode({ ...node, status: 'pending', credential_issued_at: 0 })
    expect(request.awaitingApproval).toBe(true)

    // A member: approved and holding a credential, but not seen yet.
    const member = mapNode({
      ...node,
      status: 'pending',
      credential_issued_at: Math.floor(Date.now() / 1000) - 30,
      credential_not_after: Math.floor(Date.now() / 1000) + 86_400,
    })
    expect(member.awaitingApproval).toBe(false)
  })

  it('carries the endpoint the node last reported', () => {
    const mapped = mapNode({ ...node, endpoint: '198.51.100.24:9994' })
    expect(mapped.endpoint).toBe('198.51.100.24:9994')
  })

  it('leaves the endpoint empty when the node has not reported one', () => {
    const mapped = mapNode({ ...node, endpoint: null })
    expect(mapped.endpoint).toBeUndefined()
    expect(mapped.publicAddress).toBeUndefined()
  })
})

describe('publicAddress', () => {
  it('drops the transport port', () => {
    expect(publicAddress('198.51.100.24:9994')).toBe('198.51.100.24')
  })

  it('leaves an address without a port alone', () => {
    expect(publicAddress('198.51.100.24')).toBe('198.51.100.24')
  })

  it('handles an IPv6 endpoint', () => {
    expect(publicAddress('[2001:db8::1]:9994')).toBe('[2001:db8::1]')
  })

  it('has nothing to say about a missing endpoint', () => {
    expect(publicAddress(undefined)).toBeUndefined()
    expect(publicAddress(null)).toBeUndefined()
    expect(publicAddress('')).toBeUndefined()
  })

  it('does not present the unspecified address as a route', () => {
    // A node that has never reported a reachable address carries the
    // unspecified one. It is not somewhere an operator can send traffic.
    expect(publicAddress('0.0.0.0:9994')).toBeUndefined()
    expect(publicAddress('0.0.0.0')).toBeUndefined()
  })
})

describe('mapPolicy', () => {
  const base: ControllerPolicy = {
    id: 'pol-1',
    network_id: 'net-1',
    name: 'Web to database',
    description: 'DB access',
    protocol: 'tcp',
    port: { single: 5432 },
    source: { kind: 'tag', tag: 'web' },
    destination: { kind: 'tag', tag: 'database' },
    enabled: true,
    created_at: 1_700_000_000,
    updated_at: 1_700_000_000,
  }

  it('formats a single port', () => {
    expect(mapPolicy(base).port).toBe('5432')
  })

  it('formats a port range', () => {
    const mapped = mapPolicy({ ...base, port: { range: [8000, 8080] } })
    expect(mapped.port).toBe('8000–8080')
  })

  it('formats any port', () => {
    const mapped = mapPolicy({ ...base, port: { any: null } })
    expect(mapped.port).toBe('Any')
  })

  it('formats every selector kind', () => {
    expect(mapPolicy(base).source).toBe('tag:web')
    expect(mapPolicy(base).destination).toBe('tag:database')
    expect(
      mapPolicy({ ...base, source: { kind: 'node', node_id: 'n1' } }).source,
    ).toBe('node:n1')
    expect(
      mapPolicy({ ...base, source: { kind: 'platform', platform: 'linux' } }).source,
    ).toBe('platform:linux')
    expect(
      mapPolicy({ ...base, source: { kind: 'subnet', cidr: '10.0.0.0/8' } }).source,
    ).toBe('subnet:10.0.0.0/8')
    expect(
      mapPolicy({ ...base, source: { kind: 'network', network_id: 'net-2' } }).source,
    ).toBe('network:net-2')
    expect(mapPolicy({ ...base, source: { kind: 'any' } }).source).toBe('any')
  })

  it('uppercases the protocol', () => {
    expect(mapPolicy(base).protocol).toBe('TCP')
    expect(mapPolicy({ ...base, protocol: 'icmp' }).protocol).toBe('ICMP')
  })
})

describe('mapRelay', () => {
  const relay: ControllerRelay = {
    id: 'relay-1',
    name: 'relay-ams',
    node_id: '10.42.0.2/24',
    endpoint: '198.51.100.2:9994',
    networks: ['net-1', 'net-2'],
    enabled: true,
    status: 'healthy',
    created_at: 1_700_000_000,
    updated_at: 1_700_000_000,
  }

  it('maps the relay and counts its networks', () => {
    const mapped = mapRelay(relay)
    expect(mapped.name).toBe('relay-ams')
    expect(mapped.endpoint).toBe('198.51.100.2:9994')
    expect(mapped.networks).toBe(2)
    expect(mapped.status).toBe('healthy')
    expect(mapped.enabled).toBe(true)
  })

  it('preserves the draining status', () => {
    expect(mapRelay({ ...relay, status: 'draining' }).status).toBe('draining')
  })
})
