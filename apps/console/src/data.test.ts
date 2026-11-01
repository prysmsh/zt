import { describe, expect, it } from 'vitest'
import { networks, nodes } from './data'

describe('console fixtures', () => {
  it('contains valid network summaries', () => {
    expect(networks.length).toBeGreaterThan(0)
    expect(networks.every((network) => network.nodeCount >= network.onlineCount)).toBe(true)
  })

  it('gives every node a network and valid status', () => {
    const networkNames = new Set(networks.map((network) => network.name))
    expect(nodes.every((node) => networkNames.has(node.network))).toBe(true)
    expect(nodes.every((node) => ['online', 'degraded', 'offline', 'pending'].includes(node.status))).toBe(true)
  })
})
