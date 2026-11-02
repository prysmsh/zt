import type { AuditEvent, MeshNode, Network, Policy, Relay } from './types'

export const networks: Network[] = [
  {
    id: 'production',
    name: 'Production',
    description: 'Core production services and operator access',
    cidr: '10.42.0.0/24',
    nodeCount: 130,
    onlineCount: 128,
    relayCount: 3,
    status: 'healthy',
    accent: 'cyan',
  },
  {
    id: 'staging',
    name: 'Staging',
    description: 'Pre-production workloads and integration tests',
    cidr: '10.43.0.0/24',
    nodeCount: 42,
    onlineCount: 42,
    relayCount: 1,
    status: 'degraded',
    accent: 'violet',
  },
  {
    id: 'development',
    name: 'Development',
    description: 'Developer laptops and sandbox environments',
    cidr: '10.44.0.0/24',
    nodeCount: 314,
    onlineCount: 302,
    relayCount: 2,
    status: 'attention',
    accent: 'amber',
  },
  {
    id: 'edge',
    name: 'Edge sites',
    description: 'Branch offices, stores, and edge appliances',
    cidr: '10.45.0.0/20',
    nodeCount: 18,
    onlineCount: 18,
    relayCount: 4,
    status: 'healthy',
    accent: 'blue',
  },
]

export const nodes: MeshNode[] = [
  {
    id: 'web-01', name: 'web-01', address: '10.42.0.18/24', network: 'Production', status: 'online', role: 'Web server', platform: 'Ubuntu 24.04', version: '0.3.1', lastSeen: '4s ago', directPeers: 12, relayedPeers: 0, credentialIssuedAt: 1700000000, credentialNotAfter: 1701555200, credentialExpires: '18 days', tags: ['production', 'web'], fingerprint: '7A:4F:92:C1:08:DD', endpoint: '198.51.100.24:9994', publicAddress: '198.51.100.24',
  },
  {
    id: 'db-02', name: 'db-02', address: '10.42.0.42/24', network: 'Production', status: 'online', role: 'Database', platform: 'Debian 12', version: '0.3.1', lastSeen: '7s ago', directPeers: 8, relayedPeers: 2, credentialIssuedAt: 1700000000, credentialNotAfter: 1701814400, credentialExpires: '21 days', tags: ['production', 'database'], fingerprint: '91:2B:7E:45:CC:A0', endpoint: '203.0.113.18:9994', publicAddress: '203.0.113.18',
  },
  {
    id: 'bastion-01', name: 'bastion-01', address: '10.42.0.3/24', network: 'Production', status: 'online', role: 'Bastion', platform: 'Alpine 3.21', version: '0.3.1', lastSeen: '2s ago', directPeers: 38, relayedPeers: 0, credentialIssuedAt: 1700000000, credentialNotAfter: 1701641600, credentialExpires: '19 days', tags: ['production', 'admin'], fingerprint: '2F:81:16:B7:5A:EE', endpoint: '192.0.2.16:9994', publicAddress: '192.0.2.16',
  },
  {
    id: 'worker-07', name: 'worker-07', address: '10.43.0.17/24', network: 'Staging', status: 'degraded', role: 'Worker', platform: 'Ubuntu 24.04', version: '0.3.0', lastSeen: '2m ago', directPeers: 4, relayedPeers: 6, credentialIssuedAt: 1700000000, credentialNotAfter: 1700010800, credentialExpires: '3 hours', tags: ['staging', 'worker'], fingerprint: 'CB:32:91:0E:77:AF', endpoint: '198.51.100.42:9994', publicAddress: '198.51.100.42',
  },
  {
    id: 'laptop-mara', name: 'laptop-mara', address: '10.44.3.81/24', network: 'Development', status: 'online', role: 'Workstation', platform: 'macOS 15.3', version: '0.3.1', lastSeen: '12s ago', directPeers: 2, relayedPeers: 0, credentialIssuedAt: 1700000000, credentialNotAfter: 1701036800, credentialExpires: '12 days', tags: ['development', 'macos'], fingerprint: '4D:18:AB:70:CE:39', endpoint: '203.0.113.88:9994', publicAddress: '203.0.113.88',
  },
  {
    id: 'store-berlin-02', name: 'store-berlin-02', address: '10.45.1.22/20', network: 'Edge sites', status: 'online', role: 'Edge appliance', platform: 'OpenWrt 24.10', version: '0.3.1', lastSeen: '18s ago', directPeers: 3, relayedPeers: 1, credentialIssuedAt: 1700000000, credentialNotAfter: 1702419200, credentialExpires: '28 days', tags: ['edge', 'retail'], fingerprint: '68:5C:41:B3:02:DF', endpoint: '192.0.2.64:9994', publicAddress: '192.0.2.64',
  },
  {
    id: 'mobile-17', name: 'mobile-17', address: '10.44.8.17/24', network: 'Development', status: 'offline', role: 'Mobile device', platform: 'Android 15', version: '0.3.0', lastSeen: '2d ago', directPeers: 0, relayedPeers: 0, credentialIssuedAt: 1700000000, credentialNotAfter: 1699913600, credentialExpires: 'Expired', tags: ['development', 'android'], fingerprint: 'B2:29:50:E1:BC:67', endpoint: '203.0.113.119:9994', publicAddress: '203.0.113.119',
  },
  {
    id: 'api-03', name: 'api-03', address: '10.42.0.33/24', network: 'Production', status: 'online', role: 'API server', platform: 'Ubuntu 24.04', version: '0.3.1', lastSeen: '5s ago', directPeers: 17, relayedPeers: 0, credentialIssuedAt: 1700000000, credentialNotAfter: 1702073600, credentialExpires: '24 days', tags: ['production', 'api'], fingerprint: '0F:73:CD:98:4A:21', endpoint: '198.51.100.33:9994', publicAddress: '198.51.100.33',
  },
]

export const relays: Relay[] = [
  { id: 'relay-ams', name: 'relay-ams', address: '10.42.0.2/24', endpoint: '198.51.100.2:9994', networks: 2, sessions: 14, availability: 99.998, bandwidth: '18.4 Mb/s', status: 'healthy', enabled: true },
  { id: 'relay-fra', name: 'relay-fra', address: '10.42.0.4/24', endpoint: '203.0.113.4:9994', networks: 1, sessions: 6, availability: 99.991, bandwidth: '8.2 Mb/s', status: 'healthy', enabled: true },
  { id: 'relay-sin', name: 'relay-sin', address: '10.43.0.4/24', endpoint: '198.51.100.54:9994', networks: 2, sessions: 11, availability: 98.742, bandwidth: '12.7 Mb/s', status: 'degraded', enabled: true },
  { id: 'edge-lon', name: 'edge-lon', address: '10.45.0.4/20', endpoint: '192.0.2.104:9994', networks: 1, sessions: 3, availability: 99.995, bandwidth: '2.1 Mb/s', status: 'healthy', enabled: true },
]

export const policies: Policy[] = [
  { id: 'web-db', name: 'Web tier to database', description: 'Application servers may reach managed database services.', protocol: 'TCP', port: '5432', source: 'tag:web', destination: 'tag:database', enabled: true, updated: '2 hours ago' },
  { id: 'admin-ssh', name: 'Operator SSH access', description: 'Named administrators can SSH to Linux nodes.', protocol: 'TCP', port: '22', source: 'group:administrators', destination: 'platform:linux', enabled: true, updated: 'Yesterday' },
  { id: 'edge-internal', name: 'Edge store traffic', description: 'Edge appliances access local store services.', protocol: 'Any', port: 'Any', source: 'tag:retail', destination: 'subnet:10.45.16.0/20', enabled: true, updated: '3 days ago' },
  { id: 'legacy-bridge', name: 'Legacy bridge access', description: 'Temporary compatibility rule for ZeroTier bridge.', protocol: 'Any', port: 'Any', source: 'tag:bridge', destination: 'network:production', enabled: false, updated: '5 days ago' },
]

export const events: AuditEvent[] = [
  { id: 'e1', kind: 'node', level: 'success', title: 'db-02 enrolled', detail: 'Joined Production using the Database access policy.', actor: 'mara@admin', time: '2 min ago' },
  { id: 'e2', kind: 'policy', level: 'info', title: 'Firewall policy updated', detail: 'Operator SSH access now includes node api-03.', actor: 'ops@admin', time: '18 min ago' },
  { id: 'e3', kind: 'credential', level: 'warning', title: 'Credential expires soon', detail: 'worker-07 credential expires in 3 hours.', actor: 'system', time: '31 min ago' },
  { id: 'e4', kind: 'relay', level: 'warning', title: 'Relay latency detected', detail: 'relay-sin median handshake latency increased to 184 ms.', actor: 'system', time: '46 min ago' },
  { id: 'e5', kind: 'system', level: 'info', title: 'Controller configuration reloaded', detail: 'Applied configuration revision 7c91.', actor: 'system', time: '1 hour ago' },
  { id: 'e6', kind: 'node', level: 'error', title: 'mobile-17 disconnected', detail: 'No successful handshake in the last 48 hours.', actor: 'system', time: '2 hours ago' },
]
