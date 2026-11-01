import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, Building2, Check, ChevronRight, CircleSlash, Cloud,
  HardDrive, Pause, Play, Plus, RefreshCw, Server, ShieldAlert, Trash2, Users,
} from 'lucide-react'
import type { AdminApiClient, ControlPlaneHealth, Invoice, Tenant, TenantUsage } from '../admin'
import { EmptyView, ErrorView, LoadingView } from './StateViews'

export interface AdminState {
  health: ControlPlaneHealth | null
  tenants: Tenant[]
  usage: Record<string, TenantUsage>
  invoices: Record<string, Invoice>
  loading: boolean
  error: string | null
}

/** An amount in cents, as money. */
function formatMoney(cents: number, currency: string): string {
  const symbol = currency === 'EUR' ? '€' : currency === 'USD' ? '$' : `${currency} `
  return `${symbol}${(cents / 100).toFixed(2)}`
}

export function useAdminData(api: AdminApiClient): AdminState & { refresh: () => void } {
  const [health, setHealth] = useState<ControlPlaneHealth | null>(null)
  const [tenants, setTenants] = useState<Tenant[]>([])
  const [usage, setUsage] = useState<Record<string, TenantUsage>>({})
  const [invoices, setInvoices] = useState<Record<string, Invoice>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  async function load() {
    setLoading(true)
    try {
      const [nextHealth, nextTenants] = await Promise.all([
        api.health(),
        api.listTenants(),
      ])
      setHealth(nextHealth)
      setTenants(nextTenants)

      // Usage is fetched per tenant. These are small requests against the
      // control plane, so fetching them together is fine at this scale.
      const entries = await Promise.all(
        nextTenants.map(async (tenant) => {
          try {
            const result = await api.tenantUsage(tenant.id)
            return [tenant.id, result.usage] as const
          } catch {
            return [tenant.id, null] as const
          }
        }),
      )
      const nextUsage: Record<string, TenantUsage> = {}
      for (const [id, value] of entries) {
        if (value) nextUsage[id] = value
      }
      setUsage(nextUsage)

      // What each tenant owes for the period. It is fetched alongside the
      // usage, because it is the same question.
      const billed = await Promise.all(
        nextTenants.map(async (tenant) => {
          try {
            return [tenant.id, await api.tenantInvoice(tenant.id)] as const
          } catch {
            return [tenant.id, null] as const
          }
        }),
      )
      const nextInvoices: Record<string, Invoice> = {}
      for (const [id, value] of billed) {
        if (value) nextInvoices[id] = value
      }
      setInvoices(nextInvoices)
      setError(null)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to reach the control plane')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api])

  return {
    health,
    tenants,
    usage,
    invoices,
    loading,
    error,
    refresh: () => void load(),
  }
}

function TenantStatus({ status }: { status: Tenant['status'] }) {
  const labels: Record<Tenant['status'], string> = {
    provisioning: 'Provisioning',
    active: 'Active',
    suspended: 'Suspended',
    deleted: 'Deleted',
  }
  return <span className={`status ${status === 'active' ? 'online' : status === 'suspended' ? 'degraded' : 'offline'}`}>{labels[status]}</span>
}

function DeploymentBadge({ deployment }: { deployment: Tenant['deployment'] }) {
  return (
    <span className={`deployment-badge ${deployment}`}>
      {deployment === 'shared' ? <Cloud size={12} /> : <HardDrive size={12} />}
      {deployment === 'shared' ? 'Shared' : 'Dedicated'}
    </span>
  )
}

function UsageBar({
  used,
  limit,
  label,
}: {
  used: number
  limit: number
  label: string
}) {
  const percent = limit === 0 ? 0 : Math.min(100, Math.round((used / limit) * 100))
  const over = used > limit
  return (
    <div className="usage-bar">
      <div className="usage-label">
        <span>{label}</span>
        <span className={over ? 'over' : ''}>
          {used} / {limit}
        </span>
      </div>
      <div className="usage-track">
        <div className={`usage-fill ${over ? 'over' : ''}`} style={{ width: `${percent}%` }} />
      </div>
    </div>
  )
}

/**
 * The master console: tenant lifecycle, plans, limits, and control-plane
 * health.
 */
export function MasterConsole({
  api,
  state,
}: {
  api: AdminApiClient
  state: AdminState & { refresh: () => void }
}) {
  const [busy, setBusy] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const activeTenants = useMemo(
    () => state.tenants.filter((tenant) => tenant.status === 'active'),
    [state.tenants],
  )

  async function act(tenant: Tenant, action: 'suspend' | 'reactivate' | 'delete') {
    setBusy(tenant.id)
    setActionError(null)
    try {
      if (action === 'suspend') {
        await api.suspendTenant(tenant.id, 'Suspended from the master console')
      } else if (action === 'reactivate') {
        await api.reactivateTenant(tenant.id)
      } else {
        await api.deleteTenant(tenant.id)
      }
      state.refresh()
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : 'Action failed')
    } finally {
      setBusy(null)
    }
  }

  if (state.loading && !state.health) {
    return <LoadingView label="Loading control plane…" />
  }
  if (state.error && !state.health) {
    return <ErrorView message={state.error} onRetry={state.refresh} />
  }

  const health = state.health

  return (
    <>
      <div className="page-head">
        <div>
          <div className="eyebrow">Control plane</div>
          <h1>Master console</h1>
          <p className="page-description">
            Administer tenants, plans, limits, and the health of the control plane.
          </p>
        </div>
        <div className="head-actions">
          <button type="button" className="button ghost" onClick={state.refresh}>
            <RefreshCw size={14} />
            Refresh
          </button>
          <button type="button" className="button primary" onClick={() => setShowCreate(true)}>
            <Plus size={15} />
            New tenant
          </button>
        </div>
      </div>

      {actionError ? (
        <div className="stale-banner" role="alert">
          <ShieldAlert size={14} />
          <span>{actionError}</span>
        </div>
      ) : null}

      {health ? (
        <div className="stats">
          <div className="stat-card">
            <div className="stat-label">Tenants</div>
            <div className="stat-row">
              <div className="stat-value">{health.tenants}</div>
              <div className="stat-delta good">{health.active_tenants} active</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Deployment</div>
            <div className="stat-row">
              <div className="stat-value">{health.shared_tenants}</div>
              <div className="stat-delta">shared · {health.dedicated_tenants} dedicated</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Managed resources</div>
            <div className="stat-row">
              <div className="stat-value">{health.networks + health.nodes}</div>
              <div className="stat-delta">networks · nodes</div>
            </div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Control plane</div>
            <div className="stat-row">
              <div className="stat-value" style={{ fontSize: 20 }}>
                {health.status === 'healthy' ? 'Healthy' : health.status}
              </div>
              <div className="stat-delta">v{health.version}</div>
            </div>
          </div>
        </div>
      ) : null}

      <h2 className="section-title">Tenants</h2>
      <section className="panel">
        {state.tenants.length === 0 ? (
          <EmptyView
            icon={<Users size={20} />}
            title="No tenants yet"
            detail="Create a tenant to give it an isolated address space and policy boundary."
            headingLevel={3}
            action={
              <button type="button" className="button primary" onClick={() => setShowCreate(true)}>
                <Plus size={14} />
                Create tenant
              </button>
            }
          />
        ) : (
          <div className="tenant-list">
            {state.tenants.map((tenant) => {
              const tenantUsage = state.usage[tenant.id]
              return (
                <div className="tenant-row" key={tenant.id}>
                  <div className="tenant-identity">
                    <div className="tenant-icon">
                      <Building2 size={17} />
                    </div>
                    <div>
                      <div className="tenant-name">{tenant.name}</div>
                      <div className="tenant-slug">{tenant.slug}</div>
                    </div>
                  </div>
                  <DeploymentBadge deployment={tenant.deployment} />
                  <TenantStatus status={tenant.status} />
                  <div className="tenant-plan">{tenant.plan}</div>
                  <div className="tenant-estimate">
                    {state.invoices[tenant.id] ? (
                      <>
                        <span className="estimate-amount">
                          {formatMoney(state.invoices[tenant.id].total_cents, state.invoices[tenant.id].currency)}
                        </span>
                        <span className="estimate-note">this period</span>
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </div>
                  <div className="tenant-usage">
                    {tenantUsage ? (
                      <>
                        <UsageBar
                          used={tenantUsage.networks}
                          limit={tenant.limits.max_networks}
                          label="Networks"
                        />
                        <UsageBar
                          used={tenantUsage.nodes}
                          limit={tenant.limits.max_nodes}
                          label="Nodes"
                        />
                      </>
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </div>
                  <div className="tenant-actions">
                    {tenant.status === 'active' ? (
                      <button
                        type="button"
                        className="button ghost"
                        disabled={busy === tenant.id}
                        onClick={() => void act(tenant, 'suspend')}
                      >
                        <Pause size={13} />
                        Suspend
                      </button>
                    ) : tenant.status === 'suspended' ? (
                      <button
                        type="button"
                        className="button ghost"
                        disabled={busy === tenant.id}
                        onClick={() => void act(tenant, 'reactivate')}
                      >
                        <Play size={13} />
                        Reactivate
                      </button>
                    ) : null}
                    {tenant.status !== 'deleted' ? (
                      <button
                        type="button"
                        className="button danger"
                        disabled={busy === tenant.id}
                        onClick={() => void act(tenant, 'delete')}
                        aria-label={`Delete ${tenant.name}`}
                        title={`Delete ${tenant.name}`}
                      >
                        <Trash2 size={13} />
                      </button>
                    ) : null}
                    <ChevronRight size={15} color="#8e8e93" />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </section>

      {showCreate ? (
        <CreateTenantDialog
          api={api}
          onClose={() => setShowCreate(false)}
          onCreated={() => {
            setShowCreate(false)
            state.refresh()
          }}
        />
      ) : null}
    </>
  )
}

function CreateTenantDialog({
  api,
  onClose,
  onCreated,
}: {
  api: AdminApiClient
  onClose: () => void
  onCreated: () => void
}) {
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [deployment, setDeployment] = useState<'shared' | 'dedicated'>('shared')
  const [plan, setPlan] = useState('starter')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      await api.createTenant({ name, slug: slug || name.toLowerCase().replace(/\s+/g, '-'), deployment, plan })
      onCreated()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the tenant')
      setBusy(false)
    }
  }

  const valid = name.trim().length > 0

  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div className="dialog" onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true">
        <div className="dialog-head">
          <div>
            <div className="panel-title">New tenant</div>
            <div className="panel-subtitle">Create an isolated control-plane tenant</div>
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
            <CircleSlash size={15} />
          </button>
        </div>
        <div className="dialog-body">
          <label className="field">
            <span className="field-label">Name</span>
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="Acme Corporation"
              autoFocus
            />
          </label>
          <label className="field">
            <span className="field-label">Slug</span>
            <input
              value={slug}
              onChange={(event) => setSlug(event.target.value)}
              placeholder="acme"
            />
            <span className="field-hint">Used in URLs and CLI commands.</span>
          </label>
          <label className="field">
            <span className="field-label">Deployment</span>
            <select
              value={deployment}
              onChange={(event) => setDeployment(event.target.value as 'shared' | 'dedicated')}
            >
              <option value="shared">Shared — one control plane, isolated data</option>
              <option value="dedicated">Dedicated — own process, database, and key</option>
            </select>
          </label>
          <label className="field">
            <span className="field-label">Plan</span>
            <select value={plan} onChange={(event) => setPlan(event.target.value)}>
              <option value="starter">Starter</option>
              <option value="team">Team</option>
              <option value="business">Business</option>
              <option value="enterprise">Enterprise</option>
            </select>
          </label>
          {error ? (
            <div className="dialog-error" role="alert">
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          ) : null}
        </div>
        <div className="dialog-actions">
          <button type="button" className="button ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="button" className="button primary" disabled={!valid || busy} onClick={() => void submit()}>
            {busy ? 'Creating…' : 'Create tenant'}
          </button>
        </div>
      </div>
    </div>
  )
}
