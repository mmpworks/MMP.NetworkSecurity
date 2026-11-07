// Drives the key schedule view: every built cell against the page's data, and the word labels.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.click('#tab-keys');
  await page.waitForTimeout(800);
  await page.screenshot({ path: dir + '/look-keys-start.png', fullPage: true });
  for (let i = 0; i < 40; i++) await page.click('#knext');
  await page.waitForTimeout(2000);
  const r = await page.evaluate(() => {
    let ok = 0, labels = 0;
    kcells.forEach(k => {
      if (k.el.querySelector('.hex').textContent === hex(D.words[k.word].word[k.b % 4])) ok++;
      if (k.el.querySelector('.w').textContent === 'w' + k.word) labels++;
    });
    return { cells: kcells.length, ok, labels, letters: document.querySelectorAll('.kcell .ch').length };
  });
  console.log('cells match data:', r.ok, 'of', r.cells, ' word labels:', r.labels, 'of', r.cells, ' letters:', r.letters);
  await page.click('#kreset');
  for (let i = 0; i < 5; i++) await page.click('#knext');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: dir + '/look-keys-w8.png', fullPage: true });
  await page.setViewportSize({ width: 400, height: 900 });
  console.log('phone scrollWidth:', await page.evaluate(() => document.documentElement.scrollWidth));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
