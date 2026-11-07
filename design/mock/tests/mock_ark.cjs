// Watches AddRoundKey in a later round: the key is set first, the block holds, then bytes change one at a time.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  for (const round of [1, 5, 10]) {
    await page.evaluate(n => { stop(); speed = 0.6; const i = steps().findIndex(s => s.kind === 'ark' && s.round === n); cur = i - 1; window.settled = true; render(); }, round);
    const before = await page.evaluate(() => steps()[cur].state.map(hex).join(''));
    await page.click('#next');
    await page.waitForTimeout(150);
    const early = await page.evaluate(() => ({ label: document.querySelector('#slotlabel').textContent, key: slots.map(c => c.querySelector('.hex').textContent).join(''), want: steps()[cur].key.map(hex).join(''), block: cells.map(c => c.querySelector('.hex').textContent).join('') }));
    console.log('round', round, '| label:', early.label, '| key is set:', early.key === early.want, '| block unchanged:', early.block === before);
    if (round === 1) { await page.waitForTimeout(500); await page.screenshot({ path: dir + '/look-ark-set.png', clip: { x: 60, y: 200, width: 640, height: 560 } }); }
    // Count the distinct partial states while bytes change.
    const seen = new Set();
    for (let i = 0; i < 400; i++) {
      const s = await page.evaluate(() => ({ settled: window.settled, block: cells.map(c => c.querySelector('.hex').textContent).join('') }));
      seen.add(s.block);
      if (s.settled === true) break;
      await page.waitForTimeout(15);
    }
    const end = await page.evaluate(() => cells.map(c => c.querySelector('.hex').textContent).join('') === steps()[cur].state.map(hex).join(''));
    console.log('  in-between block states seen:', seen.size, '| end matches:', end);
  }
  // Pause while the key grid holds, then resume.
  await page.evaluate(() => { stop(); speed = 1; const i = steps().findIndex(s => s.kind === 'ark' && s.round === 2); cur = i - 1; window.settled = true; render(); });
  await page.click('#next');
  await page.waitForTimeout(700);
  await page.click('#play');
  const a = await page.evaluate(() => ({ label: document.querySelector('#play').textContent, block: cells.map(c => c.querySelector('.hex').textContent).join('') }));
  await page.waitForTimeout(2500);
  const b = await page.evaluate(() => ({ label: document.querySelector('#play').textContent, block: cells.map(c => c.querySelector('.hex').textContent).join('') }));
  console.log('pause during the hold:', a.label, '| held:', a.block === b.block);
  await page.click('#play');
  await page.waitForFunction(() => window.settled === true, null, { timeout: 20000 });
  console.log('resume ends right:', await page.evaluate(() => cells.map(c => c.querySelector('.hex').textContent).join('') === steps()[cur].state.map(hex).join('')));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
