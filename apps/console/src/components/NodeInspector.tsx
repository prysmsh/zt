import { useEffect, useState } from 'react'
import { KeyRound, RotateCw, Trash2, X } from 'lucide-react'

import type { MeshNode } from '../types'

/**
 * The inspector for a node.
 *
 * A sheet that slides in from the right, the way macOS shows details
 * beside a list. It does not take the list away: the operator can pick
 * another node while this one is open.
 */
export function NodeInspector({
  node,
  networkName,
  onClose,
  onRenew,
  onRevoke,
  onDelete,
  busy,
}: {
  node: MeshNode
  networkName: string
  onClose: () => void
  onRenew: () => void
  onRevoke: () => void
  /** Delete a revoked node outright. Omitted for live nodes. */
  onDelete?: () => void
  busy: boolean
}) {
  const [confirmingRevoke, setConfirmingRevoke] = useState(false)
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  // A different node was picked, so the confirmations do not carry over.
  useEffect(() => {
    setConfirmingRevoke(false)
    setConfirmingDelete(false)
  }, [node.id])

  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        onClose()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <aside className="inspector" aria-label={`${node.name} details`}>
      <div className="inspector-head">
        <div className="inspector-title">
          <strong>{node.name}</strong>
          <span className="inspector-sub">{networkName}</span>
        </div>
        <button type="button" className="icon-button" onClick={onClose} aria-label="Close details">
          <X size={15} />
        </button>
      </div>

      {node.status === 'pending' ? (
        <p className="inspector-pending">
          This node holds a credential but has never contacted the
          controller. It will show as online as soon as it does.
        </p>
      ) : null}
      <dl className="inspector-grid">
        <Detail label="Address" value={node.address} mono />
        <Detail label="Network" value={networkName} />
        <Detail label="Role" value={node.role} />
        <Detail label="Platform" value={`${node.platform} ${node.version}`.trim()} />
        <Detail label="Last seen" value={node.lastSeen} />
        <Detail label="Credential" value={node.credentialExpires} />
        <Detail label="Fingerprint" value={node.fingerprint} mono />
        <Detail label="Endpoint" value={node.endpoint ?? 'Not reported'} mono />
        <Detail
          label="Peers"
          value={`${node.directPeers} direct, ${node.relayedPeers} relayed`}
        />
        {node.tags.length > 0 ? (
          <Detail label="Tags" value={node.tags.join(', ')} />
        ) : null}
      </dl>

      <div className="inspector-actions">
        <button
          type="button"
          className="button"
          onClick={onRenew}
          disabled={busy || node.status === 'revoked'}
        >
          <RotateCw size={14} />
          Renew credential
        </button>
        <button
          type="button"
          className="button danger"
          onClick={() => {
            if (confirmingRevoke) {
              onRevoke()
              return
            }
            setConfirmingRevoke(true)
          }}
          onBlur={() => setConfirmingRevoke(false)}
          disabled={busy || node.status === 'revoked'}
        >
          <KeyRound size={14} />
          {confirmingRevoke ? 'Confirm revoke' : 'Revoke'}
        </button>
        {confirmingRevoke ? (
          <p className="inspector-note">
            Revoking withdraws access. The node cannot renew its credential, and it stops being part
            of the mesh.
          </p>
        ) : null}
        {onDelete && node.status === 'revoked' ? (
          <>
            <button
              type="button"
              className="button danger"
              disabled={busy}
              onClick={() => {
                if (confirmingDelete) {
                  onDelete()
                  return
                }
                setConfirmingDelete(true)
              }}
              onBlur={() => setConfirmingDelete(false)}
            >
              <Trash2 size={14} />
              {confirmingDelete ? 'Confirm delete' : 'Delete'}
            </button>
            {confirmingDelete ? (
              <p className="inspector-note">
                Deleting removes the node from the console for good. The activity page keeps the
                record of it.
              </p>
            ) : null}
          </>
        ) : null}
      </div>
    </aside>
  )
}

/** One row of the details. */
function Detail({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="inspector-row">
      <dt>{label}</dt>
      <dd className={mono ? 'mono' : undefined}>{value}</dd>
    </div>
  )
}
