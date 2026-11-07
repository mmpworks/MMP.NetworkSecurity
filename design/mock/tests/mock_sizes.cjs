// Drives all three key sizes: round chips, every block frame, and every key table cell.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  for (const k of ['128', '192', '256']) {
    await page.click('#size-' + k);
    const chips = await page.locator('#rounds button').count();
    const stepCount = await page.evaluate(() => steps().length);
    let ok = 0;
    for (let i = 0; i < stepCount - 1; i++) {
      await page.click('#next');
      const same = await page.evaluate(() => cells.map(c => c.querySelector('.hex').textContent).join('') === steps()[cur].state.map(hex).join(''));
      if (same) ok++;
    }
    await page.click('#tab-keys');
    const start = await page.evaluate(() => ({ built, grids: document.querySelectorAll('.rkb').length, head: document.querySelector('#keyhead').textContent, key: document.querySelector('#keystr').children.length }));
    const words = await page.evaluate(() => S().words.length);
    for (let i = start.built; i < words; i++) await page.click('#knext');
    const r = await page.evaluate(() => {
      let good = 0, labels = 0;
      kcells.forEach(c => {
        if (c.el.querySelector('.hex').textContent === hex(S().words[c.word].word[c.b % 4])) good++;
        if (c.el.querySelector('.w').textContent === 'w' + c.word) labels++;
      });
      return { cells: kcells.length, good, labels, heads: [...document.querySelectorAll('.rkb h3')].slice(0, 3).map(x => x.textContent), rows: document.querySelector('#build').children.length };
    });
    console.log('AES-' + k, 'round chips', chips, '| frames', ok, 'of', stepCount - 1, '| key words shown', start.key, '| grids', start.grids, '| cells', r.good, 'of', r.cells, '| labels', r.labels, '|', r.heads.join(' / '));
    if (k === '256') {
      await page.evaluate(() => { kstop(); chosen = 12; renderKeys(); renderBuild(); });
      console.log('w12 stages:', await page.evaluate(() => [...document.querySelectorAll('#build b')].map(b => b.textContent).join(' > ')));
      await page.screenshot({ path: dir + '/look-256.png', fullPage: true });
    }
    await page.click('#tab-block');
  }
  await page.setViewportSize({ width: 400, height: 900 });
  for (const t of ['block', 'keys', 'field', 'long']) {
    await page.click('#tab-' + t);
    console.log('phone', t, await page.evaluate(() => document.documentElement.scrollWidth));
  }
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
