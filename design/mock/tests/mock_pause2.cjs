// Samples the matrix overflow flyer across a pause, so a one-frame settle can be told from a real drift.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1300 } });
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#run-fips');
  for (let run = 0; run < 5; run++) {
    await page.evaluate(() => { stop(); mstop(); speed = 1; cur = firstOfRound(1) + 2; render(); mv.pos = 5; mv.all = false; renderMix(false); });
    await page.click('#mplay');
    await page.waitForSelector('.ovfly', { timeout: 15000 });
    await page.waitForTimeout(100 + run * 120);
    await page.click('#mplay');
    const sample = () => page.evaluate(() => {
      const f = document.querySelector('.ovfly');
      return { pos: mv.pos, x: f ? Math.round(f.getBoundingClientRect().left * 10) / 10 : null, label: document.querySelector('#mplay').textContent, states: f ? f.getAnimations().map(a => a.playState).join(',') : '' };
    });
    const out = [await sample()];
    for (const gap of [50, 200, 1000, 2000]) { await page.waitForTimeout(gap); out.push(await sample()); }
    console.log('run', run, out.map(o => o.pos + ':' + o.x + ':' + o.states).join('  '), '| label', out[0].label);
    await page.click('#mplay');
    await page.waitForTimeout(100);
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
