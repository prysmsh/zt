export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'zt-next-console-theme'

function systemTheme(): Theme {
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function preferredTheme(): Theme {
  const stored = window.localStorage.getItem(STORAGE_KEY)
  return stored === 'light' || stored === 'dark' ? stored : systemTheme()
}

export function applyTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme
  document.documentElement.style.colorScheme = theme
  window.localStorage.setItem(STORAGE_KEY, theme)
}

export function initializeTheme() {
  const theme = preferredTheme()
  applyTheme(theme)
  return theme
}
