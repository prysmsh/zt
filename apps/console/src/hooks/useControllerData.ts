import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ApiClient } from '../api'
import type { AuditEvent, MeshNode, Network, Policy, Relay } from '../types'

export type LoadState = 'idle' | 'loading' | 'ready' | 'error'

export interface ControllerSnapshot {
  networks: Network[]
  nodes: MeshNode[]
  policies: Policy[]
  relays: Relay[]
  events: AuditEvent[]
}

export interface ControllerDataState {
  state: LoadState
  error: string | null
  data: ControllerSnapshot
  /** True while a background refresh is in flight over already-loaded data. */
  refreshing: boolean
  lastUpdated: Date | null
  refresh: () => void
}

const emptySnapshot: ControllerSnapshot = {
  networks: [],
  nodes: [],
  policies: [],
  relays: [],
  events: [],
}

/**
 * Load controller state and keep it refreshed.
 *
 * The first load shows a full-page skeleton. Subsequent refreshes keep the
 * previous data visible so the console never flashes empty while polling.
 */
export function useControllerData(api: ApiClient, intervalMs = 15_000): ControllerDataState {
  const [state, setState] = useState<LoadState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [data, setData] = useState<ControllerSnapshot>(emptySnapshot)
  const [refreshing, setRefreshing] = useState(false)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const mounted = useRef(true)

  const load = useCallback(async () => {
    setRefreshing(true)
    try {
      const [networks, nodes, policies, relays, events] = await Promise.all([
        api.listNetworks(),
        api.listNodes(),
        api.listPolicies(),
        api.listRelays(),
        api.listEvents(),
      ])
      if (!mounted.current) return
      setData({ networks: networks.items, nodes: nodes.items, policies: policies.items, relays: relays.items, events: events.items })
      setState('ready')
      setError(null)
      setLastUpdated(new Date())
    } catch (cause) {
      if (!mounted.current) return
      setState((current) => (current === 'ready' ? 'ready' : 'error'))
      setError(cause instanceof Error ? cause.message : 'Unable to reach the controller')
    } finally {
      if (mounted.current) setRefreshing(false)
    }
  }, [api])

  useEffect(() => {
    mounted.current = true
    void load()
    const timer = window.setInterval(() => {
      void load()
    }, intervalMs)
    return () => {
      mounted.current = false
      window.clearInterval(timer)
    }
  }, [load, intervalMs])

  const refresh = useCallback(() => {
    void load()
  }, [load])

  return useMemo(
    () => ({ state, error, data, refreshing, lastUpdated, refresh }),
    [state, error, data, refreshing, lastUpdated, refresh],
  )
}

/** Derive network summaries that include live node and relay counts. */
export function useNetworkSummaries(data: ControllerSnapshot): Network[] {
  return useMemo(() => {
    return data.networks.map((network) => {
      const nodes = data.nodes.filter((node) => node.network === network.id)
      const online = nodes.filter((node) => node.status === 'online').length
      const offline = nodes.filter((node) => node.status === 'offline' || node.status === 'revoked').length
      const relays = data.relays.filter((relay) => relay.networks > 0).length
      const status = offline > 0 ? 'attention' : online === 0 && nodes.length > 0 ? 'degraded' : 'healthy'
      return {
        ...network,
        nodeCount: nodes.length,
        onlineCount: online,
        relayCount: relays,
        status,
      }
    })
  }, [data.networks, data.nodes, data.relays])
}

/** Items that need operator attention. */
export function useAttentionItems(data: ControllerSnapshot) {
  return useMemo(() => {
    const items: Array<{ id: string; level: 'warning' | 'error'; title: string; detail: string; time: string }> = []

    for (const node of data.nodes) {
      if (node.status === 'revoked') {
        items.push({
          id: `revoked-${node.id}`,
          level: 'error',
          title: `${node.name} is revoked`,
          detail: 'Access has been withdrawn. Renewals are blocked.',
          time: node.lastSeen,
        })
      } else if (node.status === 'offline') {
        items.push({
          id: `offline-${node.id}`,
          level: 'error',
          title: `${node.name} is offline`,
          detail: `Last seen ${node.lastSeen}.`,
          time: node.lastSeen,
        })
      }
      if (node.credentialExpires.startsWith('Expires in ')) {
        items.push({
          id: `credential-${node.id}`,
          level: 'warning',
          title: `Credential ${node.credentialExpires.toLowerCase()}`,
          detail: `${node.name} needs a renewal before it drops off the mesh.`,
          time: node.lastSeen,
        })
      }
    }

    for (const relay of data.relays) {
      if (relay.status === 'degraded' || relay.status === 'offline') {
        items.push({
          id: `relay-${relay.id}`,
          level: 'warning',
          title: `Relay ${relay.name} is ${relay.status}`,
          detail: 'Peers that depend on this relay may lose connectivity.',
          time: 'now',
        })
      }
    }

    return items
  }, [data.nodes, data.relays])
}
