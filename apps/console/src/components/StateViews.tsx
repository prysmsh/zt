import { AlertTriangle, PlugZap, RefreshCw, ServerCrash } from 'lucide-react'
import type { ReactNode } from 'react'

/** Full-page loading state shown during the first controller fetch. */
export function LoadingView({ label = 'Loading controller state…' }: { label?: string }) {
  return (
    <div className="state-view" role="status" aria-live="polite">
      <div className="state-spinner" aria-hidden="true" />
      <div className="state-title">{label}</div>
      <div className="state-detail">Fetching networks, nodes, policies, and relays.</div>
    </div>
  )
}

/** Full-page error state shown when the controller cannot be reached. */
export function ErrorView({
  message,
  onRetry,
}: {
  message: string
  onRetry: () => void
}) {
  return (
    <div className="state-view" role="alert">
      <div className="state-icon error">
        <ServerCrash size={22} />
      </div>
      <div className="state-title">Controller unreachable</div>
      <div className="state-detail">{message}</div>
      <div className="state-actions">
        <button type="button" className="button primary" onClick={onRetry}>
          <RefreshCw size={14} />
          Try again
        </button>
      </div>
    </div>
  )
}

/** Empty state for a collection with no items. */
export function EmptyView({
  icon,
  title,
  detail,
  action,
  headingLevel = 3,
}: {
  icon?: ReactNode
  title: string
  detail: string
  action?: ReactNode
  headingLevel?: 2 | 3
}) {
  const Heading = headingLevel === 2 ? 'h2' : 'h3'
  return (
    <div className="empty">
      <div>
        <div className="empty-icon">{icon ?? <PlugZap size={20} />}</div>
        <Heading>{title}</Heading>
        <p>{detail}</p>
        {action ? <div className="state-actions">{action}</div> : null}
      </div>
    </div>
  )
}

/** Inline warning shown when live data is stale but still displayed. */
export function StaleBanner({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="stale-banner" role="status">
      <AlertTriangle size={14} />
      <span>{message}</span>
      <button type="button" className="text-button" onClick={onRetry}>
        Retry
      </button>
    </div>
  )
}
