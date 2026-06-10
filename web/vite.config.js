import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// In dev, the API runs as a separate process (cmd/api). Proxy /api and
// /healthz to it so the browser sees a single origin (no CORS). Override the
// target with SSHBROKER_API_URL. In production, your ingress should route /api
// to the API and everything else to this app's built static files.
const apiTarget = process.env.SSHBROKER_API_URL || 'http://localhost:8081';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': { target: apiTarget, changeOrigin: true },
      '/healthz': { target: apiTarget, changeOrigin: true },
    },
  },
});
