import { defineConfig } from '@playwright/test'
export default defineConfig({
  testDir: './tests/e2e', workers: 1, fullyParallel: false, retries: 0, timeout: 60000,
  outputDir: process.env.P5_EVIDENCE_DIR || '../../artifacts/phase5-browser',
  reporter: [['list'], ['json', { outputFile: (process.env.P5_EVIDENCE_DIR || '../../artifacts/phase5-browser') + '/results.json' }]],
  use: { baseURL: 'http://127.0.0.1:5173', channel: 'msedge', viewport: { width: 1440, height: 1000 }, screenshot: 'only-on-failure', trace: 'retain-on-failure' }
})
