/**
 * OpenID Connect sign-in for the console.
 *
 * The console uses the authorization code flow with PKCE. The browser holds
 * no client secret: the code is exchanged with a verifier that only exists
 * in this tab.
 *
 * The token is kept in `sessionStorage`, not `localStorage`. A session token
 * that survives a browser restart is a token that can be replayed from a
 * shared machine, which is not worth the convenience of staying signed in.
 *
 * The token is refreshed silently when it is about to expire, and the user
 * signs in again when the refresh fails.
 */

/** The OIDC provider's settings. */
export interface OidcConfig {
  /** The issuer, including the `/oidc` path. */
  issuer: string
  /** The SPA application's client identifier. */
  clientId: string
  /**
   * The API resource the token is minted for.
   *
   * This is the audience the controller verifies. When it is an absolute
   * URI it is also sent as the `resource` parameter, which is how the
   * provider knows which resource server the token is for. A bare
   * identifier is not a valid resource indicator, so it is only ever sent
   * when it looks like a URL.
   */
  audience: string
  /** Where the provider sends the browser back to. */
  redirectUri: string
  /** The scopes the console asks for. */
  scopes: string[]
}

/** The token and its metadata. */
export interface Session {
  /**
   * The bearer credential the API accepts.
   *
   * This is the ID token, not the access token. The provider issues an
   * opaque access token for this flow, and the controller verifies JWTs, so
   * the ID token is the one that can be checked against the provider's
   * signing keys. It carries the same facts the API needs: the subject,
   * the roles, the audience, and the expiry.
   */
  credential: string
  /** The ID token, as issued. */
  idToken: string
  /** The access token, as issued. */
  accessToken: string
  /** When the credential expires, as a Unix timestamp in seconds. */
  expiresAt: number
  /** The roles the provider granted. */
  roles: string[]
  /** The tenant the token belongs to, when the provider names one. */
  tenantId?: string
}

/** Where the console keeps its session. */
const STORAGE_KEY = 'zt-next.session'

/** The console's own routes. */
export const SIGN_IN_PATH = '/auth/sign-in'
export const CALLBACK_PATH = '/auth/callback'

/**
 * Read the OIDC settings from the build's environment.
 *
 * The settings are baked in at build time, because they are not secrets and
 * because the console is a static bundle with no server to ask.
 */
export function oidcConfig(env: Record<string, string | undefined> = import.meta.env): OidcConfig {
  const issuer = (env.VITE_ZT_OIDC_ISSUER ?? 'https://prysm.sh/oidc').replace(/\/+$/, '')
  // The scheme matters: the redirect URI has to be the one the browser
  // actually used, or the provider refuses the exchange. When TLS is
  // terminated upstream, the page is served over HTTPS even though the
  // console's own Caddy speaks plain HTTP.
  const scheme = env.VITE_ZT_PUBLIC_SCHEME ?? window.location.protocol.replace(':', '')
  const origin =
    env.VITE_ZT_PUBLIC_ORIGIN ?? `${scheme}://${window.location.host}`
  return {
    issuer,
    clientId: env.VITE_ZT_OIDC_CLIENT_ID ?? 'zt-console-app-001',
    audience: env.VITE_ZT_OIDC_AUDIENCE ?? 'https://zt.hardening.dev/api',
    redirectUri: env.VITE_ZT_OIDC_REDIRECT_URI ?? `${origin}${CALLBACK_PATH}`,
    // The roles scope is what makes the provider put the user's roles in
    // the ID token. The console reads them to decide whether the operator
    // may use the master console.
    scopes: (
      env.VITE_ZT_OIDC_SCOPES ??
      'openid profile email offline_access roles'
    )
      .split(/\s+/)
      .filter(Boolean),
  }
}

/** The error raised when sign-in cannot complete. */
export class AuthError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message)
    this.name = 'AuthError'
  }
}

// ---------------------------------------------------------------------------
// PKCE
// ---------------------------------------------------------------------------

/**
 * Encode bytes as base64url, without padding.
 */
function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * The SHA-256 of the verifier, as base64url.
 */
async function challengeOf(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64Url(new Uint8Array(digest))
}

/** The verifier and the state, kept for the length of the redirect. */
interface PendingExchange {
  verifier: string
  state: string
  returnTo: string
}

const PENDING_KEY = 'zt-next.pending'

/**
 * Begin the sign-in flow.
 *
 * The browser is sent to the provider's authorization endpoint. The provider
 * sends it back to the redirect URI with a code and a state.
 */
export async function beginSignIn(config: OidcConfig, returnTo = '/'): Promise<void> {
  const verifier = base64Url(crypto.getRandomValues(new Uint8Array(32)))
  const state = base64Url(crypto.getRandomValues(new Uint8Array(16)))
  const challenge = await challengeOf(verifier)

  const pending: PendingExchange = { verifier, state, returnTo }
  sessionStorage.setItem(PENDING_KEY, JSON.stringify(pending))

  const url = new URL(`${config.issuer}/auth`)
  url.searchParams.set('client_id', config.clientId)
  url.searchParams.set('response_type', 'code')
  url.searchParams.set('redirect_uri', config.redirectUri)
  url.searchParams.set('scope', config.scopes.join(' '))
  url.searchParams.set('state', state)
  url.searchParams.set('code_challenge', challenge)
  url.searchParams.set('code_challenge_method', 'S256')

  // The resource indicator must be an absolute URI. A bare identifier is
  // not one, and the provider rejects it.
  const resource = resourceIndicator(config.audience)
  if (resource) {
    url.searchParams.set('resource', resource)
  }

  window.location.assign(url.toString())
}

/**
 * The resource indicator for an audience, when there is one.
 *
 * RFC 8707 defines the resource parameter as an absolute URI. When the
 * audience is a bare identifier, the provider derives the audience from
 * the client, and no resource parameter is sent.
 */
function resourceIndicator(audience: string): string | null {
  return /^https?:\/\//i.test(audience) ? audience : null
}

/**
 * Finish the sign-in flow, exchanging the code for a token.
 */
export async function completeSignIn(config: OidcConfig): Promise<Session> {
  const params = new URLSearchParams(window.location.search)
  const code = params.get('code')
  const state = params.get('state')

  if (!code) {
    throw new AuthError('The provider did not return an authorization code.')
  }

  const raw = sessionStorage.getItem(PENDING_KEY)
  if (!raw) {
    throw new AuthError('This sign-in attempt has expired. Please try again.')
  }
  const pending = JSON.parse(raw) as PendingExchange
  sessionStorage.removeItem(PENDING_KEY)

  if (!state || state !== pending.state) {
    throw new AuthError('The sign-in response did not match the request.')
  }

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.redirectUri,
    client_id: config.clientId,
    code_verifier: pending.verifier,
  })

  // The resource parameter is echoed on the exchange only when it was sent
  // on the authorization request.
  const resource = resourceIndicator(config.audience)
  if (resource) {
    body.set('resource', resource)
  }

  const response = await fetch(`${config.issuer}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })

  if (!response.ok) {
    const detail = await response.text().catch(() => '')
    throw new AuthError(`The provider rejected the sign-in: ${detail || response.statusText}`)
  }

  const tokens = (await response.json()) as {
    access_token: string
    id_token: string
    expires_in: number
    refresh_token?: string
  }

  const session = sessionFromTokens(tokens)
  storeSession(session)
  return session
}

/**
 * Read the claims out of a token.
 *
 * The token is not verified here. It is verified by the controller, which is
 * the only party that acts on it. The console only reads the claims to
 * decide what to show, so a forged token would mislead the operator briefly
 * and would be rejected at the first request.
 */
export function readClaims(token: string): Record<string, unknown> {
  const parts = token.split('.')
  if (parts.length !== 3) return {}
  try {
    const payload = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = payload + '='.repeat((4 - (payload.length % 4)) % 4)
    return JSON.parse(atob(padded)) as Record<string, unknown>
  } catch {
    return {}
  }
}

/**
 * Build a session from a token response.
 */
function sessionFromTokens(tokens: {
  access_token: string
  id_token: string
  expires_in: number
}): Session {
  const claims = readClaims(tokens.id_token)
  const rolesClaim = claims.roles
  const roles = Array.isArray(rolesClaim) ? rolesClaim.filter((r): r is string => typeof r === 'string') : []
  const tenantId = typeof claims.tenant_id === 'string' ? claims.tenant_id : undefined

  return {
    // The ID token is the credential. The access token this provider
    // issues for the authorization code flow is opaque, so it cannot be
    // verified against the provider's signing keys.
    credential: tokens.id_token,
    accessToken: tokens.access_token,
    idToken: tokens.id_token,
    expiresAt: Math.floor(Date.now() / 1000) + tokens.expires_in,
    roles,
    tenantId,
  }
}

/**
 * The stored session, if there is one.
 */
export function loadSession(): Session | null {
  const raw = sessionStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const session = JSON.parse(raw) as Session
    // A session that has already expired is not a session.
    if (session.expiresAt <= Math.floor(Date.now() / 1000)) {
      clearSession()
      return null
    }
    return session
  } catch {
    clearSession()
    return null
  }
}

/**
 * Keep the session.
 */
export function storeSession(session: Session): void {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(session))
}

/**
 * Forget the session.
 */
export function clearSession(): void {
  sessionStorage.removeItem(STORAGE_KEY)
}

/**
 * Whether the session is about to expire.
 *
 * A token is refreshed a minute before it lapses, so a request never goes
 * out with a token that expires in flight.
 */
export function needsRefresh(session: Session, withinSeconds = 60): boolean {
  return session.expiresAt - Math.floor(Date.now() / 1000) <= withinSeconds
}
