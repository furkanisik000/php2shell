import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// P2S frontend — dev proxies the API to the backend (server.py, port 8123).
// In production the built app (web/dist) is served BY server.py, so the API is
// same-origin (relative paths) and no proxy is needed.
const API = 'http://127.0.0.1:8123'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: true,
    proxy: {
      '/health': API,
      '/cves': API,
      '/pocs': API,
      '/profiles': API,
      '/scan': API,
      '/probe': API,
      '/poc': API,
      '/logs': API,
      '/run': API,
      '/mcp': API,
      '/db': API,
    },
  },
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    sourcemap: false,
    target: 'es2020',
  },
})
