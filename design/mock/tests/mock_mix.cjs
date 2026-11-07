// Walks the MixColumns matrix view on the FIPS 197 example and checks each term, sum, and the filled result.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1250 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#run-fips');
  await page.evaluate(() => { cur = firstOfRound(1) + 2; render(); });
  console.log('card shown on mix:', await page.isVisible('#mixcard'), '| strip:', await page.textContent('#mstrip'));
  const caps = [];
  for (let i = 0; i < 5; i++) {
    caps.push((await page.textContent('#mcap b')) + ' || ' + (await page.textContent('#mcap span')) + ' || ' + (await page.textContent('#mrun')));
    if (i < 4) await page.click('#mnext');
  }
  caps.forEach(c => console.log(c));
  await page.evaluate(() => { mv.pos = 1; renderMix(false); });
  await page.waitForTimeout(400);
  await page.screenshot({ path: dir + '/look-mix.png', fullPage: true });
  const box = await page.evaluate(() => {
    const b = document.querySelector('#mbox').getBoundingClientRect(), chip = mixCells.strip[1].getBoundingClientRect(), cell = mixCells.mat[1 * 4 + 0].getBoundingClientRect();
    return { aligned: Math.abs(b.left + 3 - chip.left) < 2, reaches: b.bottom >= mixCells.mat[0 + 4 * 1].getBoundingClientRect().bottom };
  });
  console.log('pair box:', JSON.stringify(box));
  // Walk every position of every column on every size, comparing the view with the data.
  for (const k of ['128', '192', '256']) {
    await page.click('#size-' + k);
    await page.click('#run-fips');
    const r = await page.evaluate(() => {
      let ok = 0, total = 0;
      steps().forEach((st, i) => {
        if (st.kind !== 'mix') return;
        cur = i; render();
        for (let c = 0; c < 4; c++) for (let row = 0; row < 4; row++) {
          mv.col = c; mv.pos = row * 5 + 4; mv.all = false; mv.done = {}; renderMix(false);
          total++;
          if (mixCells.res[row + 4 * c].querySelector('.hex').textContent === hex(st.state[row + 4 * c])) ok++;
        }
        document.querySelector('#mfill').click();
        total++;
        if (mixCells.res.map(x => x.querySelector('.hex').textContent).join('') === st.state.map(hex).join('')) ok++;
      });
      return { ok, total };
    });
    console.log('AES-' + k, 'result bytes and full grids:', r.ok, 'of', r.total);
  }
  await page.evaluate(() => { cur = 0; render(); });
  console.log('card hidden off mix:', !(await page.isVisible('#mixcard')));
  await page.evaluate(() => { cur = firstOfRound(1) + 2; render(); });
  await page.click('#grid .cell:nth-child(9)');
  console.log('tap a byte in column 2 picks column:', await page.evaluate(() => mv.col));
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
