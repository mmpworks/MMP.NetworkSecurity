// Watches the overflow bit break away, and checks every bit row against the data.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1350 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#run-fips');
  await page.evaluate(() => { cur = firstOfRound(1) + 2; render(); mv.pos = 3; renderMix(false); });
  await page.click('#mnext');                      // pos 4, the sum
  await page.click('#mnext');                      // row 1, 1 x d4
  await page.click('#mnext');                      // row 1, 2 x bf: overflows
  console.log('caption:', await page.textContent('#mcap b'));
  await page.waitForSelector('.ovfly', { timeout: 5000 });
  await page.waitForTimeout(350);
  const mid = await page.evaluate(() => { const f = document.querySelector('.ovfly').getBoundingClientRect(); return { x: Math.round(f.left), onScreen: f.left < innerWidth, hidden: document.querySelector('#ovfbit').style.visibility }; });
  console.log('breakaway mid-flight:', JSON.stringify(mid));
  await page.screenshot({ path: dir + '/look-overflow.png', clip: { x: 60, y: 860, width: 1160, height: 490 } });
  await page.waitForFunction(() => !document.querySelector('.ovfly'), null, { timeout: 8000 });
  console.log('flyer gone after leaving: true');
  console.log('bit rows:', (await page.locator('#mbits .brow').allTextContents()).join(' | '));
  console.log('page scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  await page.click('#mnext');                      // interrupt or move on
  await page.click('#mback');
  await page.click('#mback');
  console.log('flyers left after Back:', await page.locator('.ovfly').count());
  // Every term on every mix step: the bit rows must agree with the data.
  const r = await page.evaluate(() => {
    let ok = 0, total = 0, over = 0;
    ['128', '192', '256'].forEach(k => {
      document.querySelector('#size-' + k).click();
      steps().forEach((st, i) => {
        if (st.kind !== 'mix') return;
        st.terms.forEach(col => col.forEach(row => row.parts.forEach(p => {
          if (p.factor === 1) return;
          renderBits(p);
          total++;
          const d = p.doublings[0], answers = [...document.querySelectorAll('#mbits .ans')].map(x => x.textContent.replace(' ', ''));
          if (d.reduced) over++;
          const wantLast = bin(p.result), wantDouble = bin(d.to);
          const lowXor = ((d.shifted & 255) ^ (d.reduced ? 27 : 0)) === d.to;
          if (answers[0] === wantDouble && answers[answers.length - 1] === wantLast && lowXor) ok++;
        })));
      });
    });
    return { ok, total, over };
  });
  console.log('bit rows agree:', r.ok, 'of', r.total, '| of those, with overflow:', r.over);
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
