export type NodeStatus = 'online' | 'degraded' | 'offline' | 'pending' | 'revoked'
export type NetworkStatus = 'healthy' | 'degraded' | 'attention'
export type RelayStatus = 'healthy' | 'degraded' | 'offline' | 'draining'
export type EventKind = 'node' | 'policy' | 'credential' | 'relay' | 'system'
export type EventLevel = 'info' | 'success' | 'warning' | 'error'

export interface Network {
  id: string
  name: string
  description: string
  cidr: string
  nodeCount: number
  onlineCount: number
  relayCount: number
  status: NetworkStatus
  accent: 'cyan' | 'violet' | 'amber' | 'blue'
}

export interface MeshNode {
  id: string
  name: string
  address: string
  network: string
  status: NodeStatus
  role: string
  platform: string
  version: string
  lastSeen: string
  directPeers: number
  relayedPeers: number
  credentialExpires: string
  /** When the credential was issued, as a Unix timestamp. */
  credentialIssuedAt: number
  /** When the credential expires, as a Unix timestamp. */
  credentialNotAfter: number
  tags: string[]
  fingerprint: string
  /** The UDP endpoint the node last reported, as `ip:port`. */
  endpoint?: string
  /** The endpoint's address without its port: the node's public side. */
  publicAddress?: string
  /** A join request waiting for the operator's decision. */
  awaitingApproval?: boolean
}

export interface Relay {
  id: string
  name: string
  address: string
  endpoint: string
  networks: number
  sessions: number
  availability: number
  bandwidth: string
  status: RelayStatus
  enabled: boolean
}

export interface Policy {
  id: string
  name: string
  description: string
  protocol: string
  port: string
  source: string
  destination: string
  enabled: boolean
  updated: string
}

export interface AuditEvent {
  id: string
  kind: EventKind
  level: EventLevel
  title: string
  detail: string
  actor: string
  time: string
}
