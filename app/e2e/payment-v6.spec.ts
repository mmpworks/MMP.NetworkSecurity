import { expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { startOwnHost, type OwnHost } from './own-host'
import { open } from './walk'

// V6 UI against a real Host: the files branch of My payment keys, with the optional vendor check value. The Host owns every rule. This spec types
// the path and the check value, and reads what the Host sent. The 3 check values are for the published X9.24-3 test BDK, computed by OpenSSL 3:
// AES over a zero block gives ed6429, and CMAC over a zero block gives ff0bd7c455.
const PUBLISHED_BDK = 'fedcba9876543210f1f1f1f1f1f1f1f1'

test.describe.configure({ mode: 'serial' })

let host: OwnHost
test.beforeAll(async () => { host = await startOwnHost() })
test.afterAll(async () => { await host.stop() })

test('the payment files branch shows the check value field, refuses a wrong value and a short key by name, and takes a matching value', async ({ page }) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'v6-bdk-'))
  const bdk = path.join(dir, 'bdk.txt')
  const short = path.join(dir, 'short.txt')
  fs.writeFileSync(bdk, PUBLISHED_BDK + '\n')
  fs.writeFileSync(short, PUBLISHED_BDK.slice(0, 30) + '\n')

  await open(page, host)
  await page.getByTestId('security-setup-button').click()
  await page.getByTestId('flow-my-payment').click()
  await page.getByTestId('wizard-next').click()
  await page.getByTestId('flow-files-link').click()
  await expect(page.getByTestId('flow-my-payment-files')).toBeVisible()
  const checkValue = page.getByTestId('flow-file-check-value').locator('input')
  await expect(checkValue).toBeVisible()

  const send = async (file: string, value: string) => {
    await page.getByTestId('flow-file-path-dukpt.bdk').fill(file)
    await checkValue.fill(value)
    await page.getByTestId('flow-files-send').click()
  }

  await send(bdk, '000000')
  await expect(page.getByTestId('wizard-error-code')).toHaveText('DUKPT_KCV_MISMATCH')
  await expect(page.getByTestId('flow-my-payment-files')).toBeVisible()

  await send(short, '')
  await expect(page.getByTestId('wizard-error-code')).toHaveText('DUKPT_KEY_SIZE')

  await send(bdk, 'FF0BD7C455')
  await expect(page.getByTestId('flow-my-payment-review')).toBeVisible()
  await expect(page.getByTestId('wizard-error')).toHaveCount(0)
  await page.getByTestId('wizard-cancel').click()
  await page.getByTestId('wizard-cancel-discard').click()
})

test('the check value field shows on the payment flow only', async ({ page }) => {
  await open(page, host)
  await page.getByTestId('security-setup-button').click()
  await page.getByTestId('flow-my-login').click()
  await page.getByTestId('wizard-next').click()
  await page.getByTestId('flow-files-link').click()
  await expect(page.getByTestId('flow-my-login-files')).toBeVisible()
  await expect(page.getByTestId('flow-file-check-value')).toHaveCount(0)
  await page.getByTestId('wizard-cancel').click()
  await page.getByTestId('wizard-cancel-discard').click()
})
