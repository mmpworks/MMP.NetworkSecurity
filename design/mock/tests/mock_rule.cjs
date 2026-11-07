// Checks the rule line on every word of every key size against what the data says that word did.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 }, reducedMotion: 'reduce' });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-keys');
  const r = await page.evaluate(() => {
    const out = {};
    ['128', '192', '256'].forEach(k => {
      document.querySelector('#size-' + k).click();
      let good = 0, n = 0;
      const samples = [];
      S().words.forEach(w => {
        n++;
        built = w.i + 1; chosen = w.i; renderKeys(); renderBuild(false);
        const t = document.querySelector('#ktest').textContent;
        const says = t.includes('part of the key') ? 'key' : t.includes('rotates') ? 'rot' : t.includes('S-box step only') ? 'sub' : t.includes('is plain') ? 'plain' : '?';
        const did = w.key ? 'key' : w.rotated ? 'rot' : w.substituted ? 'sub' : 'plain';
        if (says === did && (did !== 'rot' || t.includes(': ' + hex(w.rcon) + '.'))) good++;
        if ([18, 19, 12].includes(w.i)) samples.push(t);
      });
      out[k] = { good, n, samples };
    });
    return out;
  });
  Object.entries(r).forEach(([k, v]) => { console.log('AES-' + k, v.good, 'of', v.n); v.samples.forEach(s => console.log('   ', s)); });
  console.log('phone scrollWidth:', await page.evaluate(() => { document.documentElement.style.width = ''; return document.documentElement.scrollWidth; }));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
