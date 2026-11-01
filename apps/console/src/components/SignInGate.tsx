import { useEffect, useState } from 'react'
import { Loader2, LogIn, ShieldAlert } from 'lucide-react'
import { AuthError, beginSignIn, completeSignIn, loadSession, oidcConfig, storeSession } from '../oidc'
import type { Session } from '../oidc'

/**
 * The sign-in gate.
 *
 * The console shows this until there is a session. It also handles the
 * callback: when the provider sends the browser back with a code, the
 * exchange happens here and the console takes over.
 */
export function SignInGate({ onSignedIn }: { onSignedIn: (session: Session) => void }) {
  const config = oidcConfig()
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [session, setSession] = useState<Session | null>(null)

  useEffect(() => {
    // An existing session skips the gate entirely.
    const existing = loadSession()
    if (existing) {
      setSession(existing)
      onSignedIn(existing)
      return
    }

    // The callback: the provider sent the browser back with a code.
    if (!window.location.pathname.startsWith('/auth/callback')) return

    setBusy(true)
    void completeSignIn(config)
      .then((established) => {
        setSession(established)
        onSignedIn(established)
        // The code is in the URL. It must not stay there, because it is a
        // one-time credential and the browser history keeps it.
        window.history.replaceState({}, document.title, '/')
      })
      .catch((cause: unknown) => {
        setError(
          cause instanceof AuthError
            ? cause.message
            : 'The sign-in could not be completed. Please try again.',
        )
      })
      .finally(() => setBusy(false))
    // The config is derived from the build's environment and does not change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (session) {
    return (
      <div className="auth-gate" role="status">
        <Loader2 size={18} className="spin" />
        <span>Signing in…</span>
      </div>
    )
  }

  return (
    <div className="auth-gate">
      <div className="auth-card">
        <div className="auth-icon">
          <ShieldAlert size={20} />
        </div>
        <h1 className="auth-title">ZT-next Console</h1>
        <p className="auth-description">
          Sign in with your operator account to manage networks, nodes, and access policies.
        </p>

        {error ? (
          <div className="auth-error" role="alert">
            {error}
          </div>
        ) : null}

        <button
          type="button"
          className="button primary auth-button"
          disabled={busy}
          onClick={() => {
            setError(null)
            void beginSignIn(config)
          }}
        >
          <LogIn size={15} />
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </div>
    </div>
  )
}
