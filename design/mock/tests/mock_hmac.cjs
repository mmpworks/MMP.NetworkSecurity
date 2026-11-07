// Drives the HMAC and chain tab: the attack, the steps, each chain case, pause, and phone width.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1500 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-hmac');
  await page.click('#hattack');
  console.log('plain:', await page.textContent('#hplain'));
  console.log('keyed:', await page.textContent('#hkeyed'));
  await page.click('#hattack');
  await page.evaluate(() => { speed = 0.2; });
  await page.click('#hplay');
  await page.waitForFunction(() => hv.step >= 2, null, { timeout: 15000 });
  await page.click('#hplay');
  const s1 = await page.evaluate(() => hv.step);
  await page.waitForTimeout(1500);
  const s2 = await page.evaluate(() => hv.step);
  console.log('steps paused at', s1, '| held:', s1 === s2, '| label', await page.textContent('#hplay'));
  await page.click('#hplay');
  await page.waitForFunction(() => hv.playing === false, null, { timeout: 15000 });
  const parts = await page.evaluate(() => { const b = D.hmac.build; let ok = 0; const p = b.padded, i = b.inner, o = b.outer; for (let x = 0; x < 64; x++) { const k = parseInt(p.substr(x * 2, 2), 16); if ((k ^ 0x36) === parseInt(i.substr(x * 2, 2), 16) && (k ^ 0x5c) === parseInt(o.substr(x * 2, 2), 16)) ok++; } return ok; });
  console.log('pad bytes hold:', parts, 'of 64 | last step label:', await page.evaluate(() => hv.step));
  for (const k of ['change', 'remove', 'cut', 'rewrite', 'none']) {
    await page.click(`#ccases button[data-case="${k}"]`);
    const r = await page.evaluate(() => ({
      cards: [...document.querySelectorAll('.cevent')].map(c => c.classList.contains('ok') ? 'ok' : c.classList.contains('bad') ? 'BAD' : c.classList.contains('skip') ? 'skip' : '?').join(' '),
      verdict: document.querySelector('#cverdict').textContent,
      rootSame: document.querySelector('#croot').textContent === document.querySelector('#csealed').textContent,
    }));
    console.log(k, '|', r.cards, '| root same:', r.rootSame, '|', r.verdict);
    if (k === 'rewrite') await page.screenshot({ path: dir + '/look-chain.png', fullPage: true });
  }
  await page.evaluate(() => { speed = 0.5; });
  await page.click('#cplay');
  await page.waitForFunction(() => hv.chainShown >= 2, null, { timeout: 10000 });
  await page.click('#cplay');
  const c1 = await page.evaluate(() => hv.chainShown);
  await page.waitForTimeout(1500);
  console.log('chain paused at', c1, '| held:', c1 === await page.evaluate(() => hv.chainShown));
  await page.click('#cplay');
  await page.waitForFunction(() => hv.chainPlaying === false, null, { timeout: 15000 });
  console.log('chain built:', await page.textContent('#cverdict'));
  await page.hover('#view-hmac .spec[data-spec="rfc2104"]');
  console.log('spec card:', await page.textContent('#speccard a'), await page.getAttribute('#speccard a', 'href'));
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
