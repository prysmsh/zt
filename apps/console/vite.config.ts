import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const controllerUrl = env.VITE_ZT_CONTROLLER_PROXY ?? 'http://127.0.0.1:8080'

  return {
    plugins: [react()],
    server: {
      host: '127.0.0.1',
      port: 4173,
      // The console calls /api/v1; forward it to the local Rust controller.
      proxy: {
        '/api': {
          target: controllerUrl,
          changeOrigin: true,
        },
      },
    },
    preview: {
      host: '127.0.0.1',
      port: 4173,
      proxy: {
        '/api': {
          target: controllerUrl,
          changeOrigin: true,
        },
      },
    },
  }
})
