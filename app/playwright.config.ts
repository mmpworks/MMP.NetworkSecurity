// Lesson 0 end to end: the built renderer on `vite preview` and a real NetSec.Host process. One worker, because the Host keeps one session store.
// NETSEC_HOST_DLL points at NetSec.Host.dll when the Host sits outside this checkout.
import { defineConfig } from '@playwright/test'
import path from 'node:path'

export const HOST_PORT = 5190
export const TOKEN = 'lesson0-token'
const hostDll = process.env.NETSEC_HOST_DLL ?? path.resolve(__dirname, '..', 'src', 'NetSec.Host', 'bin', 'Release', 'net10.0', 'NetSec.Host.dll')

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4180', viewport: { width: 1440, height: 900 }, trace: 'retain-on-failure' },
  webServer: [
    { command: 'npx vite preview --port 4180 --strictPort', port: 4180, reuseExistingServer: true, timeout: 60_000 },
    { command: `dotnet "${hostDll}"`, port: HOST_PORT, reuseExistingServer: false, timeout: 60_000, env: { NETSEC_PORT: String(HOST_PORT), NETSEC_TOKEN: TOKEN } },
  ],
})
