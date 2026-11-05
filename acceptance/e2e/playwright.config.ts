import { defineConfig } from '@playwright/test';

// One worker. The Host keeps one session store and the lesson walks share it (program-design.md section 9).
// Environment from acceptance/run.ps1:
//   ACC_ROOT    repo root of the product (the folder that holds app/ and src/)
//   ACC_HOST    path of NetSec.Host.dll
//   ACC_OUT     folder for screenshots and the state file
export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.ts/,
  workers: 1,
  fullyParallel: false,
  timeout: 180_000,
  retries: 0,
  reporter: [['list'], ['json', { outputFile: process.env.ACC_OUT ? process.env.ACC_OUT + '/playwright.json' : 'test-results/playwright.json' }]],
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  use: { baseURL: 'http://localhost:4180', screenshot: 'off', trace: 'off', viewport: { width: 1440, height: 900 } },
});
