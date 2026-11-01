/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL of the Rust controller API. Leave unset to use the Vite dev
   * server proxy, which forwards /api to a local controller.
   */
  readonly VITE_ZT_CONTROLLER_URL?: string
  /** Set to "1" to run the console against bundled demo data. */
  readonly VITE_ZT_USE_FIXTURES?: string
  /**
   * Where the console is served from. The landing page is the front door,
   * so the console lives under a path of its own.
   */
  readonly VITE_ZT_BASE_PATH?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
