// Watches a key word build byte by byte, then checks interrupts and the finished table.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-keys');
  await page.click('#knext');
  const seen = [];
  for (let j = 0; j < 4; j++) {
    await page.waitForFunction(n => filling && filling.count === n && !document.querySelector('#keq').hidden && document.querySelector('#keqresult'), j, { timeout: 15000 });
    const top = await page.textContent('.keqtop');
    const keyPicks = await page.evaluate(() => [...document.querySelectorAll('#keystr .kb.pick')].map(x => x.dataset.stage + ':' + x.textContent).join(' '));
    const shown = await page.evaluate(() => kcells.filter(k => k.word === 4).map(k => k.el.querySelector('.hex').textContent || '__').join(' '));
    seen.push(top + ' | key line lit: ' + keyPicks + ' | w4 so far: ' + shown);
    if (j === 1) await page.screenshot({ path: dir + '/look-fill.png', clip: { x: 60, y: 300, width: 1180, height: 640 } });
    await page.waitForFunction(n => !filling || filling.count > n, j, { timeout: 15000 });
  }
  seen.forEach(s => console.log(s));
  await page.waitForFunction(() => filling === null, null, { timeout: 15000 });
  console.log('w4 chips after build:', await page.textContent('#build .last code'));
  await page.click('#knext');                     // w5
  await page.waitForFunction(() => filling && !document.querySelector('#keq').hidden, null, { timeout: 15000 });
  console.log('w5 first byte:', await page.textContent('.keqtop'));
  await page.click('#kback');                     // interrupt
  const left = await page.evaluate(() => ({ filling, picks: document.querySelectorAll('.pick').length, flyers: document.querySelectorAll('.kflyer').length, keq: document.querySelector('#keq').hidden, built }));
  console.log('after Back mid-word:', JSON.stringify(left));
  await page.click('#knext');                     // start w5 again, then skip through the rest fast
  for (let i = 0; i < 40; i++) { if (await page.locator('#knext').isEnabled()) await page.click('#knext'); }
  await page.evaluate(() => kstop());
  await page.evaluate(() => { renderKeys(); });
  const r = await page.evaluate(() => {
    let good = 0;
    kcells.forEach(c => { if (c.el.querySelector('.hex').textContent === hex(S().words[c.word].word[c.b % 4])) good++; });
    return { good, cells: kcells.length, built };
  });
  console.log('full table:', r.good, 'of', r.cells, ' built', r.built);
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
