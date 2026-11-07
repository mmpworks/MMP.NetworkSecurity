// Checks that each AddRoundKey button names the round key its step uses.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  for (const k of ['128', '192', '256']) {
    await page.click('#size-' + k);
    const rounds = await page.locator('#rounds button').count();
    let ok = 0;
    for (let n = 0; n < rounds; n++) {
      await page.click('#rounds button:nth-child(' + (n + 1) + ')');
      const labels = await page.locator('#ribbon button').allTextContents();
      const last = labels[labels.length - 1];
      await page.click('#ribbon button:last-child');
      const slot = await page.textContent('#slotlabel');
      if (last === 'AddRoundKey ' + n && slot === 'Round key ' + n) ok++;
    }
    console.log('AES-' + k, 'button matches the key used:', ok, 'of', rounds);
  }
  console.log('page errors:', errors.length);
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
