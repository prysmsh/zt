import { useEffect, useMemo, useState } from 'react'
import { AlertTriangle, Check, Copy, Plus } from 'lucide-react'
import type { ApiClient, EnrollNodeResult } from '../api'
import type { Network } from '../types'

/** A one-time enrollment secret handed to a node. */
export interface EnrollmentSecret {
  nodeName: string
  networkName: string
  address: string
  credential: string
  expiresAt: number
  /** The command a node operator runs to enroll. */
  command: string
}

function formatExpiry(unixSeconds: number): string {
  const remaining = unixSeconds - Math.floor(Date.now() / 1000)
  if (remaining <= 0) return 'expired'
  if (remaining < 3600) return `expires in ${Math.max(1, Math.floor(remaining / 60))} minutes`
  if (remaining < 86400) return `expires in ${Math.floor(remaining / 3600)} hours`
  return `expires in ${Math.floor(remaining / 86400)} days`
}

/**
 * Dialog for creating a network.
 *
 * The CIDR is the network's address space. It must not overlap another
 * network in the same tenant.
 */
export function CreateNetworkDialog({
  api,
  onClose,
  onCreated,
}: {
  api: ApiClient
  onClose: () => void
  onCreated: (network: Network) => void
}) {
  const [name, setName] = useState('')
  const [cidr, setCidr] = useState('')
  const [description, setDescription] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const cidrError = useMemo(() => {
    if (!cidr.trim()) return null
    const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr.trim())
    if (!match) return 'Use the form 10.42.0.0/24.'
    const octets = match.slice(1, 5).map(Number)
    if (octets.some((octet) => octet > 255)) return 'Each address part must be 0–255.'
    const prefix = Number(match[5])
    if (prefix > 32) return 'The prefix must be 0–32.'
    return null
  }, [cidr])

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const network = await api.createNetwork({
        name: name.trim(),
        cidr: cidr.trim(),
        description: description.trim(),
      })
      onCreated(network)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not create the network')
      setBusy(false)
    }
  }

  const valid = name.trim().length > 0 && cidr.trim().length > 0 && !cidrError

  return (
    <DialogShell title="New network" subtitle="Create an isolated address space" onClose={onClose}>
      <div className="dialog-body">
        <label className="field">
          <span className="field-label">Name</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Production"
            autoFocus
          />
        </label>
        <label className="field">
          <span className="field-label">CIDR</span>
          <input
            value={cidr}
            onChange={(event) => setCidr(event.target.value)}
            placeholder="10.42.0.0/24"
            aria-invalid={cidrError ? true : undefined}
          />
          {cidrError ? (
            <span className="field-error">{cidrError}</span>
          ) : (
            <span className="field-hint">The address range nodes in this network receive.</span>
          )}
        </label>
        <label className="field">
          <span className="field-label">Description</span>
          <input
            value={description}
            onChange={(event) => setDescription(event.target.value)}
            placeholder="Core production services"
          />
        </label>
        {error ? <DialogError message={error} /> : null}
      </div>
      <div className="dialog-actions">
        <button type="button" className="button ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="button primary" disabled={!valid || busy} onClick={() => void submit()}>
          {busy ? 'Creating…' : 'Create network'}
        </button>
      </div>
    </DialogShell>
  )
}

/**
 * Dialog for enrolling a node.
 *
 * Enrollment needs the node's Ed25519 public key. The node generates its
 * own keypair and sends only the public half, so the private key never
 * leaves the node.
 */
export function EnrollNodeDialog({
  api,
  networks,
  onClose,
  onEnrolled,
}: {
  api: ApiClient
  networks: Network[]
  onClose: () => void
  onEnrolled: (result: EnrollNodeResult) => void
}) {
  const [name, setName] = useState('')
  const [networkId, setNetworkId] = useState(networks[0]?.id ?? '')
  const [publicKey, setPublicKey] = useState('')
  const [tags, setTags] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const keyError = useMemo(() => {
    const trimmed = publicKey.trim()
    if (!trimmed) return null
    if (!/^[0-9a-fA-F]+$/.test(trimmed)) return 'The key must be hex.'
    if (trimmed.length !== 64) return 'The key must be 32 bytes (64 hex characters).'
    return null
  }, [publicKey])

  async function submit() {
    setBusy(true)
    setError(null)
    try {
      const result = await api.enrollNode({
        networkId,
        name: name.trim(),
        publicKey: publicKey.trim().toLowerCase(),
        tags: tags
          .split(',')
          .map((tag) => tag.trim())
          .filter(Boolean),
      })
      onEnrolled(result)
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not enroll the node')
      setBusy(false)
    }
  }

  const valid =
    name.trim().length > 0 && networkId.length > 0 && publicKey.trim().length === 64 && !keyError

  return (
    <DialogShell title="Enroll node" subtitle="Issue a short-lived credential" onClose={onClose}>
      <div className="dialog-body">
        <label className="field">
          <span className="field-label">Node name</span>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="web-01"
            autoFocus
          />
        </label>
        <label className="field">
          <span className="field-label">Network</span>
          <select value={networkId} onChange={(event) => setNetworkId(event.target.value)}>
            {networks.length === 0 ? (
              <option value="">No networks available</option>
            ) : null}
            {networks.map((network) => (
              <option key={network.id} value={network.id}>
                {network.name} — {network.cidr}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span className="field-label">Ed25519 public key</span>
          <input
            value={publicKey}
            onChange={(event) => setPublicKey(event.target.value)}
            placeholder="64 hex characters"
            spellCheck={false}
            aria-invalid={keyError ? true : undefined}
          />
          {keyError ? (
            <span className="field-error">{keyError}</span>
          ) : (
            <span className="field-hint">
              Generated by the node. The private key never leaves the node.
            </span>
          )}
        </label>
        <label className="field">
          <span className="field-label">Tags</span>
          <input
            value={tags}
            onChange={(event) => setTags(event.target.value)}
            placeholder="web, production"
          />
          <span className="field-hint">Comma separated. Used by access policies.</span>
        </label>
        {error ? <DialogError message={error} /> : null}
      </div>
      <div className="dialog-actions">
        <button type="button" className="button ghost" onClick={onClose}>
          Cancel
        </button>
        <button type="button" className="button primary" disabled={!valid || busy} onClick={() => void submit()}>
          {busy ? 'Enrolling…' : 'Enroll node'}
        </button>
      </div>
    </DialogShell>
  )
}

/**
 * Shows the one-time credential returned by enrollment.
 *
 * The credential is displayed once. It cannot be retrieved again, because
 * the controller does not store it.
 */
export function EnrollmentResultView({
  result,
  networkName,
  onClose,
}: {
  result: EnrollNodeResult
  networkName: string
  onClose: () => void
}) {
  const [copied, setCopied] = useState<'credential' | 'command' | null>(null)

  const command = `zt-agent adopt --credential ${result.credential}`

  async function copy(what: 'credential' | 'command', value: string) {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(what)
      window.setTimeout(() => setCopied(null), 2000)
    } catch {
      // Clipboard access can be denied. The value stays visible for manual
      // copying, so there is nothing to recover from.
    }
  }

  return (
    <DialogShell title="Node enrolled" subtitle="Copy the credential now" onClose={onClose}>
      <div className="dialog-body">
        <div className="enroll-success">
          <div className="enroll-success-icon">
            <Check size={16} />
          </div>
          <div>
            <div className="enroll-success-title">{result.node.name} enrolled</div>
            <div className="enroll-success-detail">
              {networkName} · {result.node.address} · {formatExpiry(result.credentialNotAfter)}
            </div>
          </div>
        </div>

        <div className="field">
          <span className="field-label">Credential</span>
          <div className="secret-box">
            <code className="secret-value">{result.credential}</code>
            <button
              type="button"
              className="button ghost secret-copy"
              onClick={() => void copy('credential', result.credential)}
              aria-label="Copy credential"
            >
              {copied === 'credential' ? <Check size={13} /> : <Copy size={13} />}
              {copied === 'credential' ? 'Copied' : 'Copy'}
            </button>
          </div>
          <span className="field-hint">
            Shown once. The controller does not store it and cannot show it again.
          </span>
        </div>

        <div className="field">
          <span className="field-label">Enroll command</span>
          <div className="secret-box">
            <code className="secret-value secret-command">{command}</code>
            <button
              type="button"
              className="button ghost secret-copy"
              onClick={() => void copy('command', command)}
              aria-label="Copy enroll command"
            >
              {copied === 'command' ? <Check size={13} /> : <Copy size={13} />}
              {copied === 'command' ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      </div>
      <div className="dialog-actions">
        <button type="button" className="button primary" onClick={onClose}>
          Done
        </button>
      </div>
    </DialogShell>
  )
}

/** Shared dialog chrome. */
export function DialogShell({
  title,
  subtitle,
  children,
  onClose,
}: {
  title: string
  subtitle?: string
  children: React.ReactNode
  onClose: () => void
}) {
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="dialog-backdrop" onClick={onClose}>
      <div className="dialog" onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true">
        <div className="dialog-head">
          <div>
            <div className="panel-title">{title}</div>
            {subtitle ? <div className="panel-subtitle">{subtitle}</div> : null}
          </div>
          <button type="button" className="icon-button" onClick={onClose} aria-label="Close">
            <Plus size={15} style={{ transform: 'rotate(45deg)' }} />
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

function DialogError({ message }: { message: string }) {
  return (
    <div className="dialog-error" role="alert">
      <AlertTriangle size={14} />
      <span>{message}</span>
    </div>
  )
}
