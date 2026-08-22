/**
 * End-to-end configuration.
 *
 * Chromium only, no retries, no arbitrary waits: every view in this app is a
 * pure function of a virtual clock the tests set explicitly, so there is nothing
 * to wait for once the page has rendered. Animations are killed in `use.launchOptions`
 * for the same reason — a screenshot taken twice must be byte-identical.
 */

import { defineConfig, devices } from '@playwright/test'

const PORT = 4173
const BASE_URL = `http://127.0.0.1:${PORT}/packetViz/`

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: process.env.CI === 'true',
  retries: 0,
  workers: process.env.CI === 'true' ? 1 : undefined,
  reporter: process.env.CI === 'true' ? [['github'], ['list']] : 'list',
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: BASE_URL,
    reuseExistingServer: process.env.CI !== 'true',
    timeout: 180_000,
  },
})
