// Drives the round constant animation: order, the overflow step, pause, and the value lit per word.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
const row = page => page.evaluate(() => [...document.querySelectorAll('#rconrow .kb')].map(x => x.textContent).join(' '));
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1400 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-keys');
  console.log('at rest:', await row(page), '|', await page.textContent('#rnote'));
  await page.evaluate(() => { speed = 0.25; });
  await page.click('#rplay');
  console.log('play starts:', await row(page), '| label', await page.textContent('#rplay'));
  await page.waitForFunction(() => rpos === 7, null, { timeout: 30000 });
  console.log('reached 80:', await row(page));
  // Pause on the overflow step, with the bit in the air.
  await page.evaluate(() => { speed = 1; });
  await page.waitForSelector('.ovfly', { timeout: 15000 });
  await page.click('#rplay');
  await page.waitForTimeout(120);
  const a = await page.evaluate(() => ({ x: document.querySelector('.ovfly').getBoundingClientRect().left, pos: rpos, label: document.querySelector('#rplay').textContent }));
  await page.waitForTimeout(1500);
  const b = await page.evaluate(() => ({ x: document.querySelector('.ovfly').getBoundingClientRect().left, pos: rpos, label: document.querySelector('#rplay').textContent }));
  console.log('paused on the overflow:', JSON.stringify(a), '| held:', JSON.stringify(a) === JSON.stringify(b));
  console.log('bit rows:', (await page.locator('#rbits .brow').allTextContents()).join(' | '));
  await page.screenshot({ path: dir + '/look-rcon.png', fullPage: true });
  await page.click('#rplay');
  await page.evaluate(() => { speed = 0.25; });
  await page.waitForFunction(() => rplaying === false, null, { timeout: 30000 });
  console.log('finished:', await row(page), '| label', await page.textContent('#rplay'));
  const want = await page.evaluate(() => D.rcon.map(hex).join(' '));
  console.log('matches the list:', (await row(page)) === want);
  await page.click('#rreset');
  for (const [k, used] of [['192', 8], ['256', 7], ['128', 10]]) {
    await page.click('#size-' + k);
    const r = await page.evaluate(() => ({ used: rconUsed(), dim: document.querySelectorAll('#rconrow .unused').length, note: document.querySelector('#rnote').textContent }));
    console.log('AES-' + k, JSON.stringify(r), r.used === used ? 'OK' : 'WRONG');
  }
  // The value lit in the side panel follows the rotating word.
  const lit = await page.evaluate(() => {
    const out = [];
    S().words.forEach(w => {
      if (!w.rotated) return;
      built = w.i + 1; chosen = w.i; renderKeys(); renderBuild(false);
      const chip = document.querySelector('#rconmini .pick');
      out.push((chip ? chip.textContent : 'none') === hex(w.rcon));
    });
    built = S().nk; chosen = null; renderKeys(); renderBuild(false);
    return { ok: out.filter(Boolean).length, total: out.length };
  });
  console.log('lit value equals the word\'s constant:', lit.ok, 'of', lit.total);
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
