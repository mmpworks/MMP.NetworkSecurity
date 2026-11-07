// Reads the RotWord note on every rotating word of every key size: it may only name a word that exists.
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
      const n = S().words.length;
      let good = 0, total = 0, last = '';
      S().words.forEach(w => {
        if (!w.rotated) return;
        total++;
        built = w.i + 1; chosen = w.i; renderKeys(); renderBuild(false);
        const text = document.querySelector('#kwhy').textContent;
        const m = text.match(/next word that does this is w(?<next>\d+)/);
        if (m ? (+m.groups.next < n && S().words[+m.groups.next].rotated) : text.includes('last word')) good++;
        last = text.split('. ').pop();
      });
      out[k] = { good, total, last };
    });
    return out;
  });
  console.log(JSON.stringify(r));
  console.log('page errors:', errors.length);
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
