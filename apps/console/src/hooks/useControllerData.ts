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
export function networkSummaries(data: ControllerSnapshot): Network[] {
  return data.networks.map((network) => {
    // A revoked node is not part of the fleet: it cannot come online,
    // so counting it would make a healthy network look degraded.
    const nodes = data.nodes.filter(
      (node) => node.network === network.id && node.status !== 'revoked'
    )
    const online = nodes.filter((node) => node.status === 'online').length
    const offline = nodes.filter((node) => node.status === 'offline').length
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
}

/** Derive network summaries that include live node and relay counts. */
export function useNetworkSummaries(data: ControllerSnapshot): Network[] {
  return useMemo(() => networkSummaries(data), [data.networks, data.nodes, data.relays])
}

/** An item on the attention list. */
export interface AttentionItem {
  id: string
  level: 'warning' | 'error' | 'info'
  title: string
  detail: string
  time: string
}

/**
 * The current time, in seconds.
 *
 * The credential timestamps are Unix seconds, so the rules that work on
 * them work on this.
 */
function currentTime(): number {
  return Math.floor(Date.now() / 1000)
}

/**
 * The fraction of a credential's life after which the agent renews it.
 *
 * The agent renews a credential once three quarters of its life has
 * elapsed. The console must agree: a warning that fires before the agent
 * has renewed is a warning that is always on, because the agent renews
 * on its own schedule and the console cannot make it renew sooner.
 *
 * A credential is only worth flagging when it is close enough to expiry
 * that a failed renewal would take the node off the mesh, which is what
 * the agent leaves behind: the last quarter of the life.
 */
const RENEW_AFTER_FRACTION = 0.75

/**
 * Whether a credential is close enough to expiring to be worth flagging.
 *
 * A node that is not renewing keeps the same credential until it
 * expires, so the warning is raised when the credential is inside the
 * window in which the agent would have renewed it.
 *
 * The time is passed in rather than read from the clock, so the rule can
 * be exercised at a known moment.
 */
function needsAttention(node: MeshNode, now: number): boolean {
  if (node.credentialNotAfter === 0) {
    // A node that has never been issued a credential.
    return false
  }

  if (now >= node.credentialNotAfter) {
    return true
  }

  const total = node.credentialNotAfter - node.credentialIssuedAt
  if (total <= 0) {
    return true
  }

  const age = now - node.credentialIssuedAt
  return age / total >= RENEW_AFTER_FRACTION
}

/**
 * The items that need operator attention.
 *
 * This is the substance of the attention list, kept apart from the hook so
 * it can be reasoned about on its own.
 */
export function attentionItems(data: ControllerSnapshot, now = currentTime()): AttentionItem[] {
  const items: AttentionItem[] = []

  for (const node of data.nodes) {
    // A join request is the one thing on this list the operator must
    // decide about: until it is approved or rejected, a host is waiting.
    if (node.awaitingApproval) {
      items.push({
        id: `join-${node.id}`,
        level: 'info',
        title: `${node.name} asks to join`,
        detail: 'Approve or reject it on the nodes page.',
        time: 'now',
      })
    }
    // A revoked node is not on this list: the operator withdrew it, so
    // there is nothing to do about it. Its row on the node list says so,
    // and the activity page records when it happened.
    if (node.status === 'offline') {
      items.push({
        id: `offline-${node.id}`,
        level: 'error',
        title: `${node.name} is offline`,
        detail: `Last seen ${node.lastSeen}.`,
        time: node.lastSeen,
      })
    }
    // A revoked node's renewals are blocked, so its credential is not
    // going to be renewed. It is already reported above.
    //
    // A credential is only worth an operator's attention once it is close
    // enough to expiry that a failed renewal would take the node off the
    // mesh. The agent renews it before that point on its own, so a
    // credential that is merely old is not a problem.
    if (node.status !== 'revoked' && needsAttention(node, now)) {
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
}

/** Items that need operator attention. */
export function useAttentionItems(data: ControllerSnapshot) {
  return useMemo(() => attentionItems(data), [data.nodes, data.relays])
}
