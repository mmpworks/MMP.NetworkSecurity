import { defineConfig } from '@playwright/test';

// One worker. The Host keeps one session store and the lesson walks share it (program-design.md section 9).
// Environment from acceptance/run.ps1:
//   ACC_ROOT    repo root of the product (the folder that holds app/ and src/)
//   ACC_HOST    path of NetSec.Host.dll
//   ACC_OUT     folder for screenshots and the state file
//   ACC_E2E_GREP  the selected clause ids as one regular expression. Absent means every clause. A test outside the selection does not run,
//                 so its result cannot be lost from a report that lists only the selection
export default defineConfig({
  testDir: '.',
  grep: process.env.ACC_E2E_GREP ? new RegExp(process.env.ACC_E2E_GREP) : undefined,
  testMatch: /.*\.spec\.ts/,
  workers: 1,
  fullyParallel: false,
  timeout: 60_000,          // a step that needs more than a minute is a failure, and 15 tests must end inside the 900 s tool limit
  retries: 0,
  reporter: [['list'], ['json', { outputFile: process.env.ACC_OUT ? process.env.ACC_OUT + '/playwright.json' : 'test-results/playwright.json' }]],
  globalSetup: './global-setup.ts',
  globalTeardown: './global-teardown.ts',
  use: { baseURL: `http://localhost:${process.env.ACC_PREVIEW_PORT ?? 4180}`, screenshot: 'off', trace: 'off', viewport: { width: 1440, height: 900 } },
});
