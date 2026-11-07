// Watches the phantom column through each stage, and checks what it shows against the data.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
const show = page => page.evaluate(() => kph ? kph.cells.map(c => c.textContent).join(' ') : null);
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-keys');
  await page.evaluate(() => { speed = 0.6; });
  await page.click('#knext');                       // w4
  const want = await page.evaluate(() => { const w = S().words[4]; const f = a => a.map(hex).join(' '); return { start: f(w.previous), rot: f(w.rotated), sub: f(w.substituted), rcon: f(w.afterRcon) }; });
  console.log('expected', JSON.stringify(want));
  const seen = new Set();
  for (let i = 0; i < 80; i++) {
    const s = await show(page);
    if (s) seen.add(s);
    if (await page.evaluate(() => filling && filling.count >= 1)) break;
    await page.waitForTimeout(40);
  }
  console.log('phantom passed through:', [...seen].join(' -> '));
  for (const k of ['start', 'rot', 'sub', 'rcon']) console.log(' saw', k + ':', seen.has(want[k]));
  await page.evaluate(() => { document.querySelector('#kplay').click(); });        // freeze for the picture
  await page.waitForTimeout(150);
  await page.screenshot({ path: dir + '/look-phantom.png', clip: { x: 0, y: 300, width: 1280, height: 620 } });
  console.log('paused: phantom holds', await show(page), '| picked row', await page.evaluate(() => kph.cells.findIndex(c => c.classList.contains('pick'))), '| filled', await page.evaluate(() => filling.count));
  console.log('base column w3 still:', await page.evaluate(() => kcells.filter(k => k.word === 3).map(k => k.el.querySelector('.hex').textContent).join(' ')));
  await page.click('#kplay');                       // resume
  await page.waitForFunction(() => filling === null, null, { timeout: 30000 });
  console.log('after build: phantom', await page.evaluate(() => !!kph), '| w4:', await page.evaluate(() => kcells.filter(k => k.word === 4).map(k => k.el.querySelector('.hex').textContent).join(' ')));
  await page.click('#knext');                       // w5 has no phantom
  await page.waitForTimeout(600);
  console.log('w5 phantom:', await page.evaluate(() => !!kph));
  await page.click('#kback');
  console.log('Back clears:', await page.evaluate(() => ({ phantom: !!kph, boxes: document.querySelectorAll('.kphantom').length })));

  // Every row every phantom word pairs: the phantom's row j must be the value the equation uses.
  const r = await page.evaluate(() => {
    let ok = 0, total = 0;
    ['128', '192', '256'].forEach(k => {
      document.querySelector('#size-' + k).click();
      S().words.forEach(w => {
        if (w.key || !(w.rotated || w.substituted)) return;
        const temp = combineWord(w);
        temp.forEach((b, j) => { total++; if ((b ^ w.keyBack[j]) === w.word[j]) ok++; });
      });
    });
    return { ok, total };
  });
  console.log('phantom rows combine to the new word:', r.ok, 'of', r.total);

  await page.click('#size-256');
  await page.evaluate(() => { kstop(); built = 12; chosen = null; renderKeys(); renderBuild(false); speed = 0.3; });
  await page.click('#knext');
  await page.waitForTimeout(250);
  console.log('AES-256 w12 note:', await page.textContent('#kwhy'));
  console.log('w12 phantom exists:', await page.evaluate(() => !!kph));
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
