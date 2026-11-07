// Measures where the bits start on each line of every binary display.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
const starts = text => text.split('\n').map(l => { const m = l.search(/[01]{4} [01]{4}/); return m; });
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.evaluate(() => { cur = 1; render(); });
  const ark = await page.textContent('#detail .bits');
  console.log(ark);
  console.log('AddRoundKey bit columns:', starts(ark).join(','));
  await page.screenshot({ path: dir + '/look-ark.png', clip: { x: 700, y: 180, width: 520, height: 320 } });
  await page.click('#tab-keys');
  for (let i = 0; i < 8; i++) await page.click('#knext');   // reaches w11, then builds w12
  await page.click('#knext');
  await page.waitForFunction(() => !document.querySelector('#keq').hidden && document.querySelector('#keqresult'), null, { timeout: 15000 });
  const keq = await page.evaluate(() => document.querySelector('#keq').innerText.split('\n').slice(1).join('\n'));
  console.log(keq);
  console.log('Key equation bit columns at w' + (await page.evaluate(() => chosen)) + ':', starts(keq).join(','));
  await page.evaluate(() => kstop());
  await page.click('#tab-field');
  const field = await page.textContent('#fieldbits');
  console.log(field);
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
