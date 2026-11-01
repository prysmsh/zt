import { useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, Boxes, Building2 as Building2Icon, ChevronRight, CircleGauge,
  FileKey2, Globe2, Menu, Network as NetworkIconLucide, Plus, RadioTower, RefreshCw, Search,
  Server, ShieldCheck, SlidersHorizontal, Sun, Moon, Waypoints, X, Zap,
} from 'lucide-react'
import type { MeshNode, Network } from './types'
import { createHttpClient } from './api'
import { loadSession } from './oidc'
import type { Session } from './oidc'
import { SignInGate } from './components/SignInGate'
import { createFixtureClient } from './fixtures'
import type { ApiClient } from './api'
import { applyTheme, initializeTheme, type Theme } from './theme'
import { createAdminClient, type Tenant } from './admin'
import { MasterConsole, useAdminData } from './components/AdminViews'
import { NodeInspector } from './components/NodeInspector'
import {
  CreateNetworkDialog,
  EnrollNodeDialog,
  EnrollmentResultView,
} from './components/OperatorDialogs'
import {
  useAttentionItems,
  useControllerData,
  useNetworkSummaries,
  type ControllerSnapshot,
} from './hooks/useControllerData'
import { EmptyView, ErrorView, LoadingView, StaleBanner } from './components/StateViews'
import './styles.css'

type Page =
  | 'overview'
  | 'networks'
  | 'nodes'
  | 'policies'
  | 'relays'
  | 'activity'
  | 'admin'
type Status = 'online' | 'degraded' | 'offline' | 'pending' | 'revoked'

const nav: Array<{ id: Page; label: string; icon: typeof Activity }> = [
  { id: 'overview', label: 'Overview', icon: CircleGauge },
  { id: 'networks', label: 'Networks', icon: NetworkIconLucide },
  { id: 'nodes', label: 'Nodes', icon: Server },
  { id: 'policies', label: 'Access rules', icon: ShieldCheck },
  { id: 'relays', label: 'Relays', icon: RadioTower },
  { id: 'activity', label: 'Activity', icon: Activity },
]

const adminNav: Array<{ id: Page; label: string; icon: typeof Activity }> = [
  { id: 'admin', label: 'Master console', icon: Building2Icon },
]

/**
 * Resolve the tenant this console operates on.
 *
 * A tenant console is scoped to exactly one tenant. The tenant is taken
 * from `VITE_ZT_TENANT` in development, and from the authenticated
 * session in production.
 */
function useTenantContext(
  session: Session | null,
): { tenant: Tenant | null; loading: boolean; error: string | null } {
  const [tenant, setTenant] = useState<Tenant | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // The tenant list comes from the master console API, so it needs the
    // operator's token. Without it the list request is refused and the
    // console has no tenant to work against.
    const admin = createAdminClient('/api/v1', () => session?.credential ?? null)
    const wanted = import.meta.env.VITE_ZT_TENANT as string | undefined

    async function resolve() {
      try {
        const tenants = await admin.listTenants()
        const match = wanted
          ? tenants.find((candidate) => candidate.slug === wanted || candidate.id === wanted)
          : tenants.find((candidate) => candidate.status === 'active')
        if (!match) {
          setError(
            wanted
              ? `No tenant matches "${wanted}".`
              : 'No active tenant is available for this console.',
          )
          return
        }
        setTenant(match)
        // A previous attempt may have failed, for example before the
        // session existed. The error is cleared once the tenant resolves,
        // so a stale failure is not reported as the current state.
        setError(null)
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : 'Unable to reach the control plane')
      } finally {
        setLoading(false)
      }
    }

    void resolve()
  }, [session])

  return { tenant, loading, error }
}

/**
 * Build the tenant API client for the resolved tenant.
 *
 * The bearer token comes from the session, so it is read on every request
 * rather than captured once. That way a refreshed token takes effect
 * without rebuilding the client.
 */
function useTenantApi(
  tenant: Tenant | null,
  session: Session | null,
): { api: ApiClient; live: boolean } {
  return useMemo(() => {
    const useFixtures = import.meta.env.VITE_ZT_USE_FIXTURES === '1'
    if (useFixtures) {
      return { api: createFixtureClient(), live: false }
    }
    const baseUrl = import.meta.env.VITE_ZT_CONTROLLER_URL
    const tokenProvider = () => session?.credential ?? null
    return { api: createHttpClient(tenant?.id ?? '', baseUrl, tokenProvider), live: true }
  }, [tenant, session])
}

function StatusPill({ status }: { status: Status }) {
  const labels: Record<Status, string> = {
    online: 'Online',
    degraded: 'Degraded',
    offline: 'Offline',
    pending: 'Not yet connected',
    revoked: 'Revoked',
  }
  return <span className={`status ${status}`}>{labels[status]}</span>
}

function NetworkIcon({ accent }: { accent: Network['accent'] }) {
  return (
    <div className={`network-icon ${accent}`}>
      <Waypoints size={17} />
    </div>
  )
}

function NetworkRows({ items, onOpen }: { items: Network[]; onOpen?: (network: Network) => void }) {
  if (items.length === 0) {
    return (
      <EmptyView
        title="No networks yet"
        detail="Create a network to give nodes an isolated address space and policy boundary."
        headingLevel={2}
      />
    )
  }
  return (
    <div className="network-list">
      {items.map((network) => (
        <button type="button" className="network-row" key={network.id} onClick={() => onOpen?.(network)}>
          <div className="network-name">
            <NetworkIcon accent={network.accent} />
            <div>
              <strong>{network.name}</strong>
              <span>{network.cidr}</span>
            </div>
          </div>
          <div>
            <span className="metric-label">Nodes</span>
            <span className="metric-value">
              {network.onlineCount}/{network.nodeCount} online
            </span>
          </div>
          <div>
            <span className="metric-label">Relays</span>
            <span className="metric-value">{network.relayCount} active</span>
          </div>
          <StatusPill status={network.status === 'healthy' ? 'online' : 'degraded'} />
          <ChevronRight size={15} color="#8e8e93" />
        </button>
      ))}
    </div>
  )
}

function NodeTable({
  items,
  onOpen,
  onApprove,
  onReject,
}: {
  items: MeshNode[]
  onOpen?: (node: MeshNode) => void
  /** Approve a pending node. Omitted where approval makes no sense. */
  onApprove?: (node: MeshNode) => void
  /** Reject a pending node, which revokes it. */
  onReject?: (node: MeshNode) => void
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Node</th>
            <th>Network</th>
            <th>Status</th>
            <th>Last seen</th>
            <th>Credential</th>
            <th>Platform</th>
            {onApprove || onReject ? <th aria-label="Actions" /> : null}
          </tr>
        </thead>
        <tbody>
          {items.map((node) => (
            <tr key={node.id} className={onOpen ? 'row-clickable' : undefined}>
              <td>
                <div className="cell-main">
                  {onOpen ? (
                    <button type="button" className="cell-link" onClick={() => onOpen(node)}>
                      {node.name}
                    </button>
                  ) : (
                    node.name
                  )}
                </div>
                <div className="cell-sub">{node.address}</div>
              </td>
              <td>{node.network}</td>
              <td>
                <StatusPill status={node.status} />
              </td>
              <td>{node.lastSeen}</td>
              <td>{node.credentialExpires}</td>
              <td>{node.platform}</td>
              {onApprove || onReject ? (
                <td>
                  {node.status === 'pending' ? (
                    <span className="cell-actions">
                      {onApprove ? (
                        <button
                          type="button"
                          className="button primary"
                          onClick={(event) => {
                            event.stopPropagation()
                            onApprove(node)
                          }}
                        >
                          Approve
                        </button>
                      ) : null}
                      {onReject ? (
                        <button
                          type="button"
                          className="button"
                          onClick={(event) => {
                            event.stopPropagation()
                            onReject(node)
                          }}
                        >
                          Reject
                        </button>
                      ) : null}
                    </span>
                  ) : null}
                </td>
              ) : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Overview({
  data,
  goTo,
  onOpenNetwork,
}: {
  data: ControllerSnapshot
  goTo: (page: Page) => void
  onOpenNetwork: (network: Network) => void
}) {
  const networks = useNetworkSummaries(data)
  const attention = useAttentionItems(data)

  // A revoked node is not part of the fleet: it cannot come online, so
  // counting it would understate how much of the mesh is up.
  const fleet = data.nodes.filter((node) => node.status !== 'revoked')
  const totalNodes = fleet.length
  const onlineNodes = fleet.filter((node) => node.status === 'online').length
  const healthyRelays = data.relays.filter((relay) => relay.status === 'healthy').length
  const onlinePercent = totalNodes === 0 ? 0 : Math.round((onlineNodes / totalNodes) * 100)

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Control plane</div>
          <h1>Network overview</h1>
          <p className="page-description">Live operational status across your ZT-next networks.</p>
        </div>
        <div className="head-actions">
          <button type="button" className="button ghost" onClick={() => goTo('activity')}>
            <FileKey2 size={14} />
            Export
          </button>
          <button type="button" className="button primary" onClick={() => goTo('nodes')}>
            <Plus size={15} />
            Add node
          </button>
        </div>
      </div>

      <div className="stats">
        <div className="stat-card">
          <div className="stat-label">Networks</div>
          <div className="stat-row">
            <div className="stat-value">{networks.length}</div>
            <div className="stat-delta">configured</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Nodes online</div>
          <div className="stat-row">
            <div className="stat-value">
              {onlineNodes}{' '}
              <span style={{ color: 'var(--muted-2)', fontSize: 13 }}>/ {totalNodes}</span>
            </div>
            <div className="stat-delta good">{onlinePercent}%</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Healthy relays</div>
          <div className="stat-row">
            <div className="stat-value">
              {healthyRelays} <span style={{ color: 'var(--muted-2)', fontSize: 13 }}>/ {data.relays.length}</span>
            </div>
            <div className="stat-delta">available</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Needs attention</div>
          <div className="stat-row">
            <div className="stat-value">{attention.length}</div>
            <div className="stat-delta warn">
              {attention.filter((item) => item.level === 'error').length} critical
            </div>
          </div>
        </div>
      </div>

      <div className="grid-main">
        <section className="panel">
          <div className="panel-head">
            <div>
              <div className="panel-title">Network health</div>
              <div className="panel-subtitle">Availability and connection posture</div>
            </div>
            <button type="button" className="text-button" onClick={() => goTo('networks')}>
              View all networks
            </button>
          </div>
          <NetworkRows items={networks} onOpen={onOpenNetwork} />
        </section>

        <div style={{ display: 'grid', gap: 16, alignContent: 'start' }}>
          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="panel-title">Attention required</div>
                <div className="panel-subtitle">{attention.length} items need review</div>
              </div>
              <button type="button" className="text-button" onClick={() => goTo('activity')}>
                Review all
              </button>
            </div>
            {attention.length === 0 ? (
              <EmptyView
                icon={<ShieldCheck size={20} />}
                title="Everything looks healthy"
                detail="No offline nodes, expiring credentials, or degraded relays."
                headingLevel={2}
              />
            ) : (
              <div className="attention-list">
                {attention.slice(0, 6).map((item) => (
                  <div className="attention-item" key={item.id}>
                    <div className={`attention-icon ${item.level === 'error' ? 'red' : ''}`}>
                      <AlertTriangle size={14} />
                    </div>
                    <div>
                      <div className="attention-title">{item.title}</div>
                      <div className="attention-detail">{item.detail}</div>
                    </div>
                    <div className="attention-time">{item.time}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="panel">
            <div className="panel-head">
              <div>
                <div className="panel-title">Recent activity</div>
                <div className="panel-subtitle">Latest control-plane events</div>
              </div>
              <button type="button" className="text-button" onClick={() => goTo('activity')}>
                Open audit log
              </button>
            </div>
            {data.events.length === 0 ? (
              <EmptyView
                title="No events yet"
                detail="Administrative changes will appear here."
                headingLevel={2}
              />
            ) : (
              <div className="event-list">
                {data.events.slice(-4).reverse().map((event) => (
                  <div className="event-item" key={event.id}>
                    <div className={`event-dot ${event.level}`}>
                      <Activity size={12} />
                    </div>
                    <div>
                      <div className="event-title">{event.title}</div>
                      <div className="event-detail">{event.detail}</div>
                      <div className="event-meta">
                        {event.actor} · {event.time}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      </div>

      <h2 className="section-title">Recently active nodes</h2>
      <section className="panel">
        {data.nodes.length === 0 ? (
          <EmptyView title="No nodes enrolled" detail="Enroll the first node to start building the mesh." />
        ) : (
          <NodeTable items={data.nodes.slice(0, 5)} />
        )}
      </section>
    </>
  )
}

function NetworksPage({
  data,
  api,
  onChanged,
  onOpenNetwork,
}: {
  data: ControllerSnapshot
  api: ApiClient
  onChanged: () => void
  onOpenNetwork: (network: Network) => void
}) {
  const [creating, setCreating] = useState(false)
  const networks = useNetworkSummaries(data)
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Security boundaries</div>
          <h1>Networks</h1>
          <p className="page-description">
            Manage isolated address spaces, membership, and relay availability.
          </p>
        </div>
        <div className="head-actions">
          <button type="button" className="button primary" onClick={() => setCreating(true)}>
            <Plus size={15} />
            Create network
          </button>
        </div>
      </div>
      <section className="panel">
        <NetworkRows items={networks} onOpen={onOpenNetwork} />
      </section>
      {creating ? (
        <CreateNetworkDialog
          api={api}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false)
            onChanged()
          }}
        />
      ) : null}
    </>
  )
}

function NodesPage({
  data,
  api,
  onChanged,
  scope,
  onClearScope,
}: {
  data: ControllerSnapshot
  api: ApiClient
  onChanged: () => void
  /** The network the list is narrowed to, when one was picked. */
  scope: string | null
  onClearScope: () => void
}) {
  const [query, setQuery] = useState('')
  const [enrolling, setEnrolling] = useState(false)
  const [selected, setSelected] = useState<MeshNode | null>(null)
  const [busy, setBusy] = useState(false)
  const [enrolled, setEnrolled] = useState<{ result: import('./api').EnrollNodeResult; networkName: string } | null>(null)
  const networks = useNetworkSummaries(data)
  const scoped = scope ? data.nodes.filter((node) => node.network === scope) : data.nodes
  const filtered = useMemo(
    () =>
      scoped.filter((node) =>
        `${node.name} ${node.address} ${node.network} ${node.tags.join(' ')}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [scoped, query],
  )
  const scopeName = scope ? networks.find((network) => network.id === scope)?.name : undefined

  // The cleanup for a flood of fake join requests: one call instead of
  // one click each. The count is over the whole tenant, because the
  // endpoint is tenant-wide.
  const pendingCount = data.nodes.filter((node) => node.status === 'pending').length
  const [rejecting, setRejecting] = useState(false)

  const handleApprove = async (node: MeshNode) => {
    setBusy(true)
    try {
      await api.approveNode(node.id)
      onChanged()
    } finally {
      setBusy(false)
    }
  }

  const handleReject = async (node: MeshNode) => {
    setBusy(true)
    try {
      await api.revokeNode(node.id)
      onChanged()
    } finally {
      setBusy(false)
    }
  }

  const handleRejectAll = async () => {
    setRejecting(true)
    try {
      await api.rejectPendingNodes()
      onChanged()
    } finally {
      setRejecting(false)
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Fleet / {data.nodes.length} enrolled</div>
          <h1>Nodes</h1>
          <p className="page-description">Enrollment, approval, connectivity, and credential lifecycle.</p>
        </div>
        <div className="head-actions">
          {pendingCount > 0 ? (
            <button type="button" className="button" onClick={handleRejectAll} disabled={rejecting}>
              Reject pending ({pendingCount})
            </button>
          ) : null}
          <button type="button" className="button primary" onClick={() => setEnrolling(true)}>
            <Plus size={15} />
            Add node
          </button>
        </div>
      </div>
      <div className="toolbar">
        <div className="filter">
          <Search size={13} />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search nodes"
            aria-label="Search nodes"
          />
        </div>
        <button type="button" className="filter">
          <SlidersHorizontal size={13} />
          Status
        </button>
        {scopeName ? (
          <button type="button" className="filter scope" onClick={onClearScope}>
            {scopeName}
            <X size={12} />
          </button>
        ) : (
          <button type="button" className="filter">
            {networks.length} networks
          </button>
        )}
      </div>
      <section className="panel">
        {filtered.length === 0 ? (
          <EmptyView
            icon={<Search size={20} />}
            title={query ? 'No matching nodes' : 'No nodes enrolled'}
            detail={
              query
                ? 'Try a node name, address, network, or tag.'
                : scopeName
                  ? `This network has no nodes yet.`
                  : 'Enroll a node to issue its first short-lived credential.'
            }
          />
        ) : (
          <NodeTable items={filtered} onOpen={setSelected} onApprove={handleApprove} onReject={handleReject} />
        )}
      </section>
      {selected ? (
        <NodeInspector
          node={selected}
          networkName={
            networks.find((network) => network.id === selected.network)?.name ?? selected.network
          }
          busy={busy}
          onClose={() => setSelected(null)}
          onRenew={async () => {
            setBusy(true)
            try {
              await api.renewCredential(selected.id)
              onChanged()
            } finally {
              setBusy(false)
            }
          }}
          onRevoke={async () => {
            setBusy(true)
            try {
              await api.revokeNode(selected.id)
              setSelected(null)
              onChanged()
            } finally {
              setBusy(false)
            }
          }}
        />
      ) : null}
      {enrolling ? (
        <EnrollNodeDialog
          api={api}
          networks={networks}
          onClose={() => setEnrolling(false)}
          onEnrolled={(result) => {
            setEnrolling(false)
            const network = networks.find((candidate) => candidate.id === result.node.network)
            setEnrolled({ result, networkName: network?.name ?? result.node.network })
            onChanged()
          }}
        />
      ) : null}
      {enrolled ? (
        <EnrollmentResultView
          result={enrolled.result}
          networkName={enrolled.networkName}
          onClose={() => setEnrolled(null)}
        />
      ) : null}
    </>
  )
}

function PoliciesPage({ data }: { data: ControllerSnapshot }) {
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Default deny</div>
          <h1>Access rules</h1>
          <p className="page-description">
            Control who can reach which services across every network.
          </p>
        </div>
        <div className="head-actions">
          <button type="button" className="button ghost">
            <Zap size={14} />
            Simulate
          </button>
          <button type="button" className="button primary">
            <Plus size={15} />
            New rule
          </button>
        </div>
      </div>
      <div className="tabs">
        <button type="button" className="tab active">
          All rules
        </button>
        <button type="button" className="tab">Enabled</button>
        <button type="button" className="tab">Disabled</button>
        <button type="button" className="tab">Policy templates</button>
      </div>
      <section className="panel">
        {data.policies.length === 0 ? (
          <EmptyView
            icon={<ShieldCheck size={20} />}
            title="No access rules"
            detail="Traffic is denied by default. Add a rule to permit access."
          />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Status</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {data.policies.map((policy) => (
                  <tr key={policy.id}>
                    <td>
                      <div className="cell-main">{policy.name}</div>
                      <div className="cell-sub">{policy.description}</div>
                    </td>
                    <td className="mono">{policy.source}</td>
                    <td className="mono">{policy.destination}</td>
                    <td>
                      {policy.protocol} {policy.port}
                    </td>
                    <td>
                      <StatusPill status={policy.enabled ? 'online' : 'offline'} />
                    </td>
                    <td>{policy.updated}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}

function RelaysPage({
  data,
  api,
  onChanged,
}: {
  data: ControllerSnapshot
  api: ApiClient
  onChanged: () => void
}) {
  const healthy = data.relays.filter((relay) => relay.status === 'healthy').length
  const draining = data.relays.filter((relay) => relay.status === 'draining').length
  const [enrolling, setEnrolling] = useState(false)

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Per-network infrastructure</div>
          <h1>Relays</h1>
          <p className="page-description">
            Monitor relay health, capacity, and dependency across your mesh.
          </p>
        </div>
        <div className="head-actions">
          <button type="button" className="button primary" onClick={() => setEnrolling(true)}>
            <Plus size={15} />
            Add relay
          </button>
        </div>
      </div>
      {enrolling ? (
        <EnrollNodeDialog
          api={api}
          networks={useNetworkSummaries(data)}
          presetName="relay"
          presetTags={['relay', 'public']}
          onClose={() => setEnrolling(false)}
          onEnrolled={() => {
            setEnrolling(false)
            onChanged()
          }}
        />
      ) : null}
      <div className="stats">
        <div className="stat-card">
          <div className="stat-label">Healthy relays</div>
          <div className="stat-row">
            <div className="stat-value">
              {healthy}{' '}
              <span style={{ color: 'var(--muted-2)', fontSize: 13 }}>/ {data.relays.length}</span>
            </div>
            <div className="stat-delta good">available</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Draining</div>
          <div className="stat-row">
            <div className="stat-value">{draining}</div>
            <div className="stat-delta">in maintenance</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Networks served</div>
          <div className="stat-row">
            <div className="stat-value">
              {new Set(data.relays.flatMap((relay) => relay.networks)).size}
            </div>
            <div className="stat-delta">total</div>
          </div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Total relays</div>
          <div className="stat-row">
            <div className="stat-value">{data.relays.length}</div>
            <div className="stat-delta">registered</div>
          </div>
        </div>
      </div>
      <section className="panel">
        {data.relays.length === 0 ? (
          <EmptyView
            icon={<RadioTower size={20} />}
            title="No relays registered"
            detail="Add a relay so peers behind restrictive NATs can still connect."
          />
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Relay</th>
                  <th>Status</th>
                  <th>Public endpoint</th>
                  <th>Networks</th>
                  <th>Enabled</th>
                </tr>
              </thead>
              <tbody>
                {data.relays.map((relay) => (
                  <tr key={relay.id}>
                    <td>
                      <div className="cell-main">{relay.name}</div>
                      <div className="cell-sub">{relay.address}</div>
                    </td>
                    <td>
                      <StatusPill
                        status={relay.status === 'healthy' ? 'online' : relay.status === 'offline' ? 'offline' : 'degraded'}
                      />
                    </td>
                    <td className="mono">{relay.endpoint}</td>
                    <td>{relay.networks}</td>
                    <td>{relay.enabled ? 'Yes' : 'No'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  )
}

function ActivityPage({ data }: { data: ControllerSnapshot }) {
  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Immutable audit trail</div>
          <h1>Activity</h1>
          <p className="page-description">
            Operational events and administrative changes across the control plane.
          </p>
        </div>
        <div className="head-actions">
          <button type="button" className="button ghost">
            Export log
          </button>
        </div>
      </div>
      <section className="panel">
        {data.events.length === 0 ? (
          <EmptyView title="No events recorded" detail="Administrative changes will appear here." />
        ) : (
          <div className="event-list">
            {data.events
              .slice()
              .reverse()
              .map((event) => (
                <div className="event-item" key={event.id}>
                  <div className={`event-dot ${event.level}`}>
                    <Activity size={12} />
                  </div>
                  <div>
                    <div className="event-title">{event.title}</div>
                    <div className="event-detail">{event.detail}</div>
                    <div className="event-meta">
                      {event.actor} · {event.time}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        )}
      </section>
    </>
  )
}

export default function App() {
  const [page, setPage] = useState<Page>('overview')
  const [networkScope, setNetworkScope] = useState<string | null>(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const [theme, setTheme] = useState<Theme>(() => initializeTheme())
  const [session, setSession] = useState<Session | null>(() => loadSession())
  const adminApi = useMemo(
    () => createAdminClient('/api/v1', () => session?.credential ?? null),
    [session],
  )
  const adminState = useAdminData(adminApi)
  const tenantContext = useTenantContext(session)
  const { api, live } = useTenantApi(tenantContext.tenant, session)
  const { state, error, data, refreshing, lastUpdated, refresh } = useControllerData(api)

  // Without a session, the console shows the sign-in gate. The fixtures
  // mode is exempt, because it never talks to the controller.
  const useFixtures = import.meta.env.VITE_ZT_USE_FIXTURES === '1'
  if (!session && !useFixtures) {
    return <SignInGate onSignedIn={setSession} />
  }

  const title = nav.find((item) => item.id === page)?.label ?? 'Overview'

  function openNetwork(network: Network) {
    setNetworkScope(network.id)
    setPage('nodes')
  }

  function toggleTheme() {
    const next: Theme = theme === 'dark' ? 'light' : 'dark'
    applyTheme(next)
    setTheme(next)
  }

  const content =
    page === 'admin' ? (
      <MasterConsole api={adminApi} state={adminState} />
    ) : page === 'overview' ? (
      <Overview data={data} goTo={setPage} onOpenNetwork={openNetwork} />
    ) : page === 'networks' ? (
      <NetworksPage data={data} api={api} onChanged={refresh} onOpenNetwork={openNetwork} />
    ) : page === 'nodes' ? (
      <NodesPage
        data={data}
        api={api}
        onChanged={refresh}
        scope={networkScope}
        onClearScope={() => setNetworkScope(null)}
      />
    ) : page === 'policies' ? (
      <PoliciesPage data={data} />
    ) : page === 'relays' ? (
      <RelaysPage data={data} api={api} onChanged={refresh} />
    ) : (
      <ActivityPage data={data} />
    )

  return (
    <div className="app-shell">
      <aside className={`sidebar ${menuOpen ? 'open' : ''}`}>
        <div className="brand">
          <div className="brand-mark">
            <Boxes size={19} />
          </div>
          <div className="brand-copy">
            <div className="brand-name">ZT-next</div>
            <div className="brand-sub">Control console</div>
          </div>
        </div>
        <div className="nav-label">Workspace</div>
        <nav className="nav">
          {nav.map(({ id, label, icon: Icon }) => (
            <button
              type="button"
              className={`nav-item ${page === id ? 'active' : ''}`}
              key={id}
              onClick={() => {
                setPage(id)
                setMenuOpen(false)
              }}
            >
              <Icon size={16} />
              <span>{label}</span>
              {id === 'networks' && data.networks.length > 0 ? (
                <div className="count">{data.networks.length}</div>
              ) : null}
              {id === 'nodes' && data.nodes.length > 0 ? (
                <div className="count">{data.nodes.length}</div>
              ) : null}
              {id === 'relays' && data.relays.length > 0 ? (
                <div className="count">{data.relays.length}</div>
              ) : null}
            </button>
          ))}
        </nav>
        <div className="nav-label nav-label-spaced">Operations</div>
        <nav className="nav">
          {adminNav.map(({ id, label, icon: Icon }) => (
            <button
              type="button"
              className={`nav-item ${page === id ? 'active' : ''}`}
              key={id}
              onClick={() => {
                setPage(id)
                setMenuOpen(false)
              }}
            >
              <Icon size={16} />
              <span>{label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="controller-card">
            <div className="controller-head">
              <Zap size={13} />
              {live ? 'Controller connected' : 'Demo data'}
            </div>
            <div className="controller-meta">
              {live ? 'live api · polling 15s' : 'fixtures · set VITE_ZT_CONTROLLER_URL'}
            </div>
          </div>
          {tenantContext.tenant ? (
            <div className="tenant-context">
              <span className="tenant-context-label">Tenant</span>
              <span className="tenant-context-name">{tenantContext.tenant.name}</span>
              <span className="tenant-context-slug">{tenantContext.tenant.slug}</span>
            </div>
          ) : null}
          <div className="profile">
            <div className="avatar">MA</div>
            <div className="profile-copy">
              <div className="profile-name">Mara Admin</div>
              <div className="profile-role">Network administrator</div>
            </div>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button
            type="button"
            className="icon-button mobile-menu"
            onClick={() => setMenuOpen(!menuOpen)}
            aria-label={menuOpen ? 'Close navigation' : 'Open navigation'}
          >
            {menuOpen ? <X size={17} /> : <Menu size={17} />}
          </button>
          <div className="crumbs">
            <Globe2 size={14} />
            <span>ZT-next</span>
            <ChevronRight size={12} />
            <strong>{title}</strong>
          </div>
          <div className="search">
            <Search size={13} />
            <input
              aria-label="Search nodes, networks, and policies"
              placeholder="Search nodes, networks, policies…"
            />
            <span className="key">⌘ K</span>
          </div>
          <button
            type="button"
            className="icon-button"
            onClick={refresh}
            aria-label="Refresh controller data"
            title={lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : 'Refresh'}
          >
            <RefreshCw size={15} className={refreshing ? 'spin' : ''} />
          </button>
          <button
            type="button"
            className="icon-button theme-toggle"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
          </button>
          <button type="button" className="icon-button" aria-label="Notifications" title="Notifications">
            <AlertTriangle size={15} />
          </button>
        </header>

        <div className="content">
          {state === 'loading' ? <LoadingView /> : null}
          {tenantContext.error ? (
            <ErrorView
              message={tenantContext.error}
              onRetry={refresh}
            />
          ) : null}
          {state === 'error' ? (
            <ErrorView message={error ?? 'The controller did not respond.'} onRetry={refresh} />
          ) : null}
          {state === 'ready' && error ? (
            <StaleBanner message={`Showing cached data — ${error}`} onRetry={refresh} />
          ) : null}
          {state === 'ready' && !tenantContext.error ? content : null}
        </div>
      </main>
    </div>
  )
}
