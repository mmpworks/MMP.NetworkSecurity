// Drives the Feistel tab: each function both ways, the swap rule, pause, and phone width.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-feistel');
  const rule = await page.evaluate(() => {
    let links = 0, total = 0, xor = 0, xt = 0;
    const x = (a, b) => a.match(/../g).map((h, i) => (parseInt(h, 16) ^ parseInt(b.substr(i * 2, 2), 16)).toString(16).padStart(2, '0')).join('');
    Object.values(D.feistel.functions).forEach(F => ['enc', 'dec'].forEach(d => {
      const R = F[d].rounds;
      R.forEach((r, i) => {
        xt++; if (x(r.left, r.f) === r.out) xor++;
        if (i) { total += 2; if (r.left === R[i - 1].right) links++; if (r.right === R[i - 1].out) links++; }
      });
    }));
    return { xor, xt, links, total };
  });
  console.log('XOR holds:', rule.xor, 'of', rule.xt, '| swap links hold:', rule.links, 'of', rule.total);
  for (const f of ['hash', 'and', 'zero']) {
    await page.click(`#ffn button[data-f="${f}"]`);
    const enc = await page.evaluate(() => ({ in: feistelRun().input, out: feistelRun().output }));
    await page.click('#fdir button[data-d="dec"]');
    const dec = await page.evaluate(() => ({ in: feistelRun().input, out: feistelRun().output }));
    console.log(f, '| decrypt in = encrypt out:', dec.in === enc.out, '| back to the text:', dec.out === enc.in, '| text out of encrypt:', Buffer.from(enc.out, 'hex').toString('latin1'));
    await page.click('#fdir button[data-d="enc"]');
  }
  await page.click('#ffn button[data-f="hash"]');
  await page.evaluate(() => { speed = 0.25; });
  await page.click('#fplay');
  await page.waitForFunction(() => fv.p >= 4, null, { timeout: 15000 });
  await page.click('#fplay');
  await page.waitForTimeout(100);
  const a = await page.evaluate(() => fv.p);
  await page.waitForTimeout(1500);
  const b = await page.evaluate(() => fv.p);
  console.log('paused at', a, '| held:', a === b, '| label', await page.textContent('#fplay'), '|', await page.textContent('#fcap b'));
  await page.evaluate(() => { speed = 1; renderFeistel(); });
  await page.screenshot({ path: dir + '/look-feistel.png', fullPage: true });
  await page.click('#fplay');
  await page.evaluate(() => { speed = 0.1; });
  await page.waitForFunction(() => fv.playing === false, null, { timeout: 15000 });
  console.log('finished:', await page.textContent('#fcap b'), '| out:', await page.textContent('#fout'));
  await page.hover('#view-feistel .spec');
  console.log('spec:', await page.getAttribute('#speccard a', 'href'));
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
