import { expect, test } from '@playwright/test';
import { hostGet, requireLive } from './support';

/** A16: the label for the CE in every Host answer. The wording is a requirement (prd.md A16). */
const WORDING = 'CF-compiled, run on the desktop CLR, never run on CE';

test('[A16.host.ce-label-wording] GET /api/ce carries the required wording', async () => {
  requireLive();
  const r = await hostGet('/api/ce');
  expect(r.status, 'GET /api/ce').toBe(200);
  expect(r.body?.label, 'label field of GET /api/ce').toBe(WORDING);
});
