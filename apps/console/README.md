# ZT-next Console

Self-hosted network operations console for ZT-next.

## Requirements

- Node.js 20 or newer
- A running ZT-next controller (optional — see below)

## Local development

```bash
cd apps/console
npm install
npm run dev
```

The console is served on <http://127.0.0.1:4173>.

### Connecting to the controller

The Vite dev server proxies `/api` to a local Rust controller on
`http://127.0.0.1:8080`. Start one in another terminal:

```bash
cargo run -p zt-controller --bin zt-controller
```

No console configuration is needed — it detects the live controller
automatically and shows **Controller connected** in the sidebar.

To point at a different controller:

```bash
# Change the proxy upstream (dev server only)
VITE_ZT_CONTROLLER_PROXY=http://controller.internal:8080 npm run dev

# Or set an absolute API base URL (e.g. behind a reverse proxy)
VITE_ZT_CONTROLLER_URL=https://zt.example.com/api/v1 npm run dev
```

To explore the UI without a backend, run against the bundled demo data:

```bash
VITE_ZT_USE_FIXTURES=1 npm run dev
```

See `.env.example` for all options.

### Data flow

- `src/api.ts` — typed client for the Rust controller API, including
  mutations for networks, nodes, credentials, policies, and relays.
- `src/hooks/useControllerData.ts` — loads controller state, polls every 15
  seconds, and preserves the previous snapshot during background refreshes.
- `src/components/StateViews.tsx` — loading, error, empty, and stale states.
- `src/fixtures.ts` — in-memory client used when `VITE_ZT_USE_FIXTURES=1`.

Domain types live in `src/types.ts`. The controller wire shapes and the
mappers that convert them into view models live in `src/api.ts`.

### Scripts

```bash
npm run dev        # start the dev server
npm run build      # typecheck and produce a production bundle
npm run preview    # serve the production bundle
npm run typecheck  # typecheck only
npm test           # run the unit tests
```

## Visual language

The console follows Apple's Human Interface Guidelines closely: a macOS-style
translucent sidebar, unified toolbar, system typography, restrained materials,
rounded controls, inset-list tables, and generous whitespace.

## Themes

The console supports dark and light themes. The selected theme is stored in
`localStorage` under `zt-next-console-theme`; on a first visit the console
follows the operating system's `prefers-color-scheme` setting. The sun/moon
button in the top bar switches themes immediately.

Both themes meet WCAG AA contrast requirements.
