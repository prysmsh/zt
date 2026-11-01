import { describe, expect, it } from 'vitest'

import { attentionItems, networkSummaries } from './useControllerData'
import type { ControllerSnapshot } from './useControllerData'
import type { MeshNode, Network, Relay } from '../types'

/** A node in the console's view model. */
const node = (overrides: Partial<MeshNode> & Pick<MeshNode, 'id' | 'name'>): MeshNode => ({
  address: 'a1b2c3',
  network: 'Production',
  status: 'online',
  role: 'Node',
  platform: 'linux',
  version: '1.0',
  lastSeen: 'now',
  directPeers: 0,
  relayedPeers: 0,
  credentialExpires: 'Expires in 12h',
  tags: [],
  fingerprint: 'ab cd',
  ...overrides,
})

/** A relay in the console's view model. */
const relay = (overrides: Partial<Relay> & Pick<Relay, 'id' | 'name'>): Relay => ({
  address: '10.0.0.1',
  endpoint: '198.51.100.1:9994',
  networks: 1,
  sessions: 2,
  availability: 99.9,
  bandwidth: '1 Gbps',
  status: 'healthy',
  enabled: true,
  ...overrides,
})

/** A network in the console's view model. */
const network = (overrides: Partial<Network> & Pick<Network, 'id' | 'name'>): Network => ({
  description: '',
  cidr: '10.42.0.0/24',
  nodeCount: 0,
  onlineCount: 0,
  relayCount: 0,
  status: 'healthy',
  accent: 'cyan',
  ...overrides,
})

/** A snapshot with the given nodes and relays. */
const snapshot = (
  nodes: MeshNode[],
  relays: Relay[] = [],
  networks: Network[] = []
): ControllerSnapshot => ({
  networks,
  nodes,
  relays,
  policies: [],
  events: [],
})

describe('the attention list', () => {
  it('reports a node that is offline', () => {
    const items = attentionItems(
      snapshot([node({ id: 'a', name: 'web-01', status: 'offline' })])
    )

    expect(items.some((item) => item.title === 'web-01 is offline')).toBe(true)
  })

  it('reports a credential that is about to expire', () => {
    const items = attentionItems(snapshot([node({ id: 'a', name: 'web-01' })]))

    expect(items.some((item) => item.detail.includes('needs a renewal'))).toBe(true)
  })

  it('leaves a revoked node out of the list', () => {
    // The operator withdrew the node, so there is nothing to do about it.
    // Its row on the node list says so, and the activity page records it.
    const items = attentionItems(
      snapshot([node({ id: 'a', name: 'web-01', status: 'revoked' })])
    )

    expect(items).toHaveLength(0)
  })

  it('says nothing about a node that is online and in credit', () => {
    const items = attentionItems(
      snapshot([
        node({
          id: 'a',
          name: 'web-01',
          status: 'online',
          credentialExpires: 'Expires in 12d',
        }),
      ])
    )

    expect(items).toHaveLength(0)
  })

  it('reports a credential that has expired', () => {
    const items = attentionItems(
      snapshot([
        node({ id: 'a', name: 'web-01', status: 'online', credentialExpires: 'Expired' }),
      ])
    )

    expect(items.some((item) => item.detail.includes('needs a renewal'))).toBe(true)
  })

  it('reports a credential that is hours from expiring', () => {
    const items = attentionItems(
      snapshot([
        node({ id: 'a', name: 'web-01', status: 'online', credentialExpires: 'Expires in 3h' }),
      ])
    )

    expect(items.some((item) => item.detail.includes('needs a renewal'))).toBe(true)
  })

  it('counts a revoked node out of the fleet', () => {
    // A revoked node cannot come online, so it is not part of the fleet
    // and must not make a network look degraded.
    const networks = networkSummaries(
      snapshot(
        [
          node({ id: 'a', name: 'web-01', status: 'online', network: 'n' }),
          node({ id: 'b', name: 'old-01', status: 'revoked', network: 'n' }),
        ],
        [],
        [network({ id: 'n', name: 'Production' })]
      )
    )

    expect(networks[0].nodeCount).toBe(1)
    expect(networks[0].onlineCount).toBe(1)
    expect(networks[0].status).toBe('healthy')
  })

  it('reports a relay that is degraded', () => {
    const items = attentionItems(
      snapshot([], [relay({ id: 'r', name: 'eu-1', status: 'degraded' })])
    )

    expect(items.some((item) => item.title === 'Relay eu-1 is degraded')).toBe(true)
  })
})
