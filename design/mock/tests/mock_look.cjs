// One look at the mock: drives each step type and reads end frames against the page's own data.
const path = require('path');
const root = process.argv[2];
const { chromium } = require(path.join(root, 'node_modules', 'playwright'));
const dir = process.argv[3];

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir.replace(/\\/g, '/') + '/aes-walk-mock.page.html');
  const frame = () => page.evaluate(() => ({
    cur, shown: cells.map(c => c.querySelector('.hex').textContent).join(''),
    want: steps()[cur].state.map(hex).join(''), kind: steps()[cur].kind, sel,
    overflow: document.documentElement.scrollWidth > innerWidth,
  }));
  let ok = 0, total = 0;
  await page.evaluate(() => { speed = 0.2; });
  for (let i = 0; i < 40; i++) {
    await page.click('#next');
    await page.waitForFunction(n => cur === n && window.settled === true, i + 1, { timeout: 20000 });
    const f = await frame();
    total++;
    if (f.shown === f.want) ok++; else console.log('MISMATCH', f);
  }
  console.log('end frames match data:', ok, 'of', total);
  await page.click('#rounds button:nth-child(2)');
  await page.click('#ribbon button:nth-child(3)');
  await page.click('#grid .cell:nth-child(6)');
  console.log('trace head:', await page.textContent('#tracehead'));
  await page.screenshot({ path: dir + '/look-block.png', fullPage: true });
  await page.click('#tab-keys');
  await page.waitForTimeout(1200);
  await page.screenshot({ path: dir + '/look-keys.png', fullPage: true });
  await page.click('#tab-field');
  await page.screenshot({ path: dir + '/look-field.png', fullPage: true });
  await page.setViewportSize({ width: 400, height: 900 });
  await page.click('#tab-block');
  console.log('phone overflow:', (await frame()).overflow);
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
