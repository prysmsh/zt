import { events } from './data'
import type { AuditEvent, MeshNode, Network, Policy, Relay } from './types'
import type {
  ApiClient,
  ControllerNetwork,
  ControllerNode,
  ControllerPolicy,
  ControllerRelay,
  ListResponse,
} from './api'
import { mapNetwork, mapNode, mapPolicy, mapRelay } from './api'

const delay = (ms = 120) => new Promise((resolve) => window.setTimeout(resolve, ms))

function list<T>(items: T[]): ListResponse<T> {
  return { items, total: items.length }
}

const controllerNetworks: ControllerNetwork[] = [
  {
    id: 'production',
    name: 'Production',
    description: 'Core production services and operator access',
    network_id: 1,
    cidr: '10.42.0.0/24',
    credential_ttl_secs: 86400,
    created_at: 1_700_000_000,
  },
  {
    id: 'staging',
    name: 'Staging',
    description: 'Pre-production workloads and integration tests',
    network_id: 2,
    cidr: '10.43.0.0/24',
    credential_ttl_secs: 86400,
    created_at: 1_700_100_000,
  },
  {
    id: 'development',
    name: 'Development',
    description: 'Developer laptops and sandbox environments',
    network_id: 3,
    cidr: '10.44.0.0/24',
    credential_ttl_secs: 43200,
    created_at: 1_700_200_000,
  },
  {
    id: 'edge',
    name: 'Edge sites',
    description: 'Branch offices, stores, and edge appliances',
    network_id: 4,
    cidr: '10.45.0.0/20',
    credential_ttl_secs: 172800,
    created_at: 1_700_300_000,
  },
]

const controllerNodes: ControllerNode[] = [
  {
    id: 'web-01',
    network_id: 'production',
    name: 'web-01',
    address: '9f2c1a0b4d6e8f102',
    public_key: 'aa'.repeat(32),
    fingerprint: '7A:4F:92:C1:08:DD',
    tags: ['web', 'production'],
    platform: 'Ubuntu 24.04',
    version: '0.3.1',
    status: 'online',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 18 * 86400,
    last_seen: Math.floor(Date.now() / 1000) - 4,
    created_at: 1_700_000_000,
  },
  {
    id: 'db-02',
    network_id: 'production',
    name: 'db-02',
    address: '1a2b3c4d5e6f708192',
    public_key: 'bb'.repeat(32),
    fingerprint: '91:2B:7E:45:CC:A0',
    tags: ['database', 'production'],
    platform: 'Debian 12',
    version: '0.3.1',
    status: 'online',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 21 * 86400,
    last_seen: Math.floor(Date.now() / 1000) - 7,
    created_at: 1_700_000_000,
  },
  {
    id: 'bastion-01',
    network_id: 'production',
    name: 'bastion-01',
    address: 'ffeeddccbbaa998877',
    public_key: 'cc'.repeat(32),
    fingerprint: '2F:81:16:B7:5A:EE',
    tags: ['admin', 'production'],
    platform: 'Alpine 3.21',
    version: '0.3.1',
    status: 'online',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 19 * 86400,
    last_seen: Math.floor(Date.now() / 1000) - 2,
    created_at: 1_700_000_000,
  },
  {
    id: 'worker-07',
    network_id: 'staging',
    name: 'worker-07',
    address: '102030405060708090',
    public_key: 'dd'.repeat(32),
    fingerprint: 'CB:32:91:0E:77:AF',
    tags: ['worker', 'staging'],
    platform: 'Ubuntu 24.04',
    version: '0.3.0',
    status: 'degraded',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 3 * 3600,
    last_seen: Math.floor(Date.now() / 1000) - 120,
    created_at: 1_700_100_000,
  },
  {
    id: 'laptop-mara',
    network_id: 'development',
    name: 'laptop-mara',
    address: '5566778899aabbccdd',
    public_key: 'ee'.repeat(32),
    fingerprint: '4D:18:AB:70:CE:39',
    tags: ['development', 'macos'],
    platform: 'macOS 15.3',
    version: '0.3.1',
    status: 'online',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 12 * 86400,
    last_seen: Math.floor(Date.now() / 1000) - 12,
    created_at: 1_700_200_000,
  },
  {
    id: 'store-berlin-02',
    network_id: 'edge',
    name: 'store-berlin-02',
    address: 'aabbccddeeff001122',
    public_key: 'ff'.repeat(32),
    fingerprint: '68:5C:41:B3:02:DF',
    tags: ['edge', 'retail'],
    platform: 'OpenWrt 24.10',
    version: '0.3.1',
    status: 'online',
    credential_issued_at: 1_767_000_000,
    credential_not_after: Math.floor(Date.now() / 1000) + 28 * 86400,
    last_seen: Math.floor(Date.now() / 1000) - 18,
    created_at: 1_700_300_000,
  },
  {
    id: 'mobile-17',
    network_id: 'development',
    name: 'mobile-17',
    address: '998877665544332211',
    public_key: '12'.repeat(32),
    fingerprint: 'B2:29:50:E1:BC:67',
    tags: ['development', 'android'],
    platform: 'Android 15',
    version: '0.3.0',
    status: 'offline',
    credential_issued_at: 1_700_200_000,
    credential_not_after: Math.floor(Date.now() / 1000) - 86400,
    last_seen: Math.floor(Date.now() / 1000) - 2 * 86400,
    created_at: 1_700_200_000,
  },
]

const controllerPolicies: ControllerPolicy[] = [
  {
    id: 'web-db',
    network_id: 'production',
    name: 'Web tier to database',
    description: 'Application servers may reach managed database services.',
    protocol: 'tcp',
    port: { single: 5432 },
    source: { kind: 'tag', tag: 'web' },
    destination: { kind: 'tag', tag: 'database' },
    enabled: true,
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000) - 7200,
  },
  {
    id: 'admin-ssh',
    network_id: 'production',
    name: 'Operator SSH access',
    description: 'Named administrators can SSH to Linux nodes.',
    protocol: 'tcp',
    port: { single: 22 },
    source: { kind: 'tag', tag: 'admin' },
    destination: { kind: 'platform', platform: 'linux' },
    enabled: true,
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000) - 86400,
  },
  {
    id: 'edge-internal',
    network_id: 'edge',
    name: 'Edge store traffic',
    description: 'Edge appliances access local store services.',
    protocol: 'any',
    port: { any: null },
    source: { kind: 'tag', tag: 'retail' },
    destination: { kind: 'subnet', cidr: '10.45.16.0/20' },
    enabled: true,
    created_at: 1_700_300_000,
    updated_at: Math.floor(Date.now() / 1000) - 3 * 86400,
  },
  {
    id: 'legacy-bridge',
    network_id: 'production',
    name: 'Legacy bridge access',
    description: 'Temporary compatibility rule for ZeroTier bridge.',
    protocol: 'any',
    port: { any: null },
    source: { kind: 'tag', tag: 'bridge' },
    destination: { kind: 'network', network_id: 'production' },
    enabled: false,
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000) - 5 * 86400,
  },
]

const controllerRelays: ControllerRelay[] = [
  {
    id: 'relay-ams',
    name: 'relay-ams',
    node_id: '10.42.0.2/24',
    endpoint: '198.51.100.2:9994',
    networks: ['production', 'staging'],
    enabled: true,
    status: 'healthy',
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000),
  },
  {
    id: 'relay-fra',
    name: 'relay-fra',
    node_id: '10.42.0.4/24',
    endpoint: '203.0.113.4:9994',
    networks: ['production'],
    enabled: true,
    status: 'healthy',
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000),
  },
  {
    id: 'relay-sin',
    name: 'relay-sin',
    node_id: '10.43.0.4/24',
    endpoint: '198.51.100.54:9994',
    networks: ['staging', 'development'],
    enabled: true,
    status: 'degraded',
    created_at: 1_700_000_000,
    updated_at: Math.floor(Date.now() / 1000),
  },
  {
    id: 'edge-lon',
    name: 'edge-lon',
    node_id: '10.45.0.4/20',
    endpoint: '192.0.2.104:9994',
    networks: ['edge'],
    enabled: true,
    status: 'healthy',
    created_at: 1_700_300_000,
    updated_at: Math.floor(Date.now() / 1000),
  },
]

export function createFixtureClient(): ApiClient {
  return {
    async listNetworks(): Promise<ListResponse<Network>> {
      await delay()
      const items = controllerNetworks.map(mapNetwork)
      const nodeItems = controllerNodes.map(mapNode)
      return list(
        items.map((network) => {
          const scoped = nodeItems.filter((node) => node.network === network.id)
          return {
            ...network,
            nodeCount: scoped.length,
            onlineCount: scoped.filter((node) => node.status === 'online').length,
            relayCount: controllerRelays.filter((relay) => relay.networks.includes(network.id)).length,
          }
        }),
      )
    },
    async listNodes(networkId): Promise<ListResponse<MeshNode>> {
      await delay()
      const items = controllerNodes
        .filter((node) => !networkId || node.network_id === networkId)
        .map(mapNode)
      return list(items)
    },
    async listPolicies(networkId): Promise<ListResponse<Policy>> {
      await delay()
      const items = controllerPolicies
        .filter((policy) => !networkId || policy.network_id === networkId)
        .map(mapPolicy)
      return list(items)
    },
    async listRelays(networkId): Promise<ListResponse<Relay>> {
      await delay()
      const items = controllerRelays
        .filter((relay) => !networkId || relay.networks.includes(networkId))
        .map(mapRelay)
      return list(items)
    },
    async listEvents(): Promise<ListResponse<AuditEvent>> {
      await delay()
      return list(events)
    },
    async health() {
      await delay(60)
      return { status: 'healthy', version: '0.1.0', uptimeSeconds: 1_555_200 }
    },
    async createNetwork(input) {
      await delay()
      const network: ControllerNetwork = {
        id: `network-${controllerNetworks.length + 1}`,
        name: input.name,
        description: input.description ?? '',
        network_id: controllerNetworks.length + 1,
        cidr: input.cidr,
        credential_ttl_secs: input.credentialTtlSecs ?? 86400,
        created_at: Math.floor(Date.now() / 1000),
      }
      controllerNetworks.push(network)
      return mapNetwork(network)
    },
    async enrollNode(input) {
      await delay()
      const node: ControllerNode = {
        id: `node-${controllerNodes.length + 1}`,
        network_id: input.networkId,
        name: input.name,
        address: '00'.repeat(10),
        public_key: input.publicKey,
        fingerprint: '00:00:00:00:00:00',
        tags: input.tags ?? [],
        platform: null,
        version: null,
        status: 'pending',
        credential_issued_at: Math.floor(Date.now() / 1000),
        credential_not_after: Math.floor(Date.now() / 1000) + 86400,
        last_seen: null,
        created_at: Math.floor(Date.now() / 1000),
      }
      controllerNodes.push(node)
      return {
        node: mapNode(node),
        credential: '00'.repeat(2560),
        credentialNotAfter: node.credential_not_after,
      }
    },
    async revokeNode(nodeId) {
      await delay()
      const node = controllerNodes.find((item) => item.id === nodeId)
      if (node) node.status = 'revoked'
    },
    async rejectPendingNodes() {
      await delay()
      let rejected = 0
      for (const node of controllerNodes) {
        if (node.status === 'pending') {
          node.status = 'revoked'
          rejected += 1
        }
      }
      return rejected
    },
    async approveNode(nodeId) {
      await delay()
      const node = controllerNodes.find((item) => item.id === nodeId)
      if (!node) throw new Error('node not found')
      node.status = 'pending'
      node.credential_not_after = Math.floor(Date.now() / 1000) + 86400
      return mapNode(node)
    },
    async renewCredential(nodeId) {
      await delay()
      const node = controllerNodes.find((item) => item.id === nodeId)
      if (!node) throw new Error('node not found')
      node.credential_not_after = Math.floor(Date.now() / 1000) + 86400
      return {
        node: mapNode(node),
        credential: '00'.repeat(2560),
        credentialNotAfter: node.credential_not_after,
      }
    },
    async createPolicy(input) {
      await delay()
      const policy: ControllerPolicy = {
        id: `policy-${controllerPolicies.length + 1}`,
        network_id: input.networkId,
        name: input.name,
        description: input.description ?? '',
        protocol: input.protocol,
        port: input.port,
        source: input.source,
        destination: input.destination,
        enabled: input.enabled ?? true,
        created_at: Math.floor(Date.now() / 1000),
        updated_at: Math.floor(Date.now() / 1000),
      }
      controllerPolicies.push(policy)
      return mapPolicy(policy)
    },
    async deletePolicy(policyId) {
      await delay()
      const index = controllerPolicies.findIndex((item) => item.id === policyId)
      if (index >= 0) controllerPolicies.splice(index, 1)
    },
    async createRelay(input) {
      await delay()
      const relay: ControllerRelay = {
        id: `relay-${controllerRelays.length + 1}`,
        name: input.name,
        node_id: input.nodeId,
        endpoint: input.endpoint,
        networks: input.networks,
        enabled: input.enabled ?? true,
        status: 'healthy',
        created_at: Math.floor(Date.now() / 1000),
        updated_at: Math.floor(Date.now() / 1000),
      }
      controllerRelays.push(relay)
      return mapRelay(relay)
    },
    async drainRelay(relayId) {
      await delay()
      const relay = controllerRelays.find((item) => item.id === relayId)
      if (!relay) throw new Error('relay not found')
      relay.status = 'draining'
      return mapRelay(relay)
    },
  }
}
