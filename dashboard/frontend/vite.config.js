import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

const proxy = { '/api': { target: process.env.DASHBOARD_API || 'http://127.0.0.1:8000', changeOrigin: true } }
const headers = {
  'X-Content-Type-Options': 'nosniff',
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self' ws://127.0.0.1:5173; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
}
export default defineConfig({
  plugins: [vue()],
  server: { host: '127.0.0.1', port: 5173, strictPort: true, allowedHosts: ['localhost'], cors: false, proxy, headers },
  preview: { host: '127.0.0.1', port: 5173, strictPort: true, allowedHosts: ['localhost'], proxy, headers },
  test: { environment: 'jsdom', include: ['tests/**/*.test.js'] }
})
