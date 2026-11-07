// Checks the colored pattern during and after the ShiftRows roll.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.evaluate(() => { cur = firstOfRound(1); render(); speed = 1.5; });
  await page.click('#next');
  await page.waitForSelector('.rollstrip');
  for (const r of [1, 2, 3]) {
    await page.waitForFunction(n => {
      const note = document.querySelector('#detail').textContent;
      return note.startsWith('Row ' + n) && document.querySelector('.rollstrip');
    }, r, { timeout: 15000 });
    const during = await page.evaluate(() => [...document.querySelectorAll('.rollstrip .cell')].map(c => c.classList.contains('hot') ? 'X' : '.').join(''));
    console.log('row', r, 'strip colors:', during);
    if (r === 2) { await page.waitForTimeout(800); await page.screenshot({ path: dir + '/look-shift-mid.png', clip: { x: 60, y: 300, width: 400, height: 400 } }); }
  }
  await page.waitForFunction(() => window.settled === true, null, { timeout: 15000 });
  const end = await page.evaluate(() => {
    const out = [];
    for (let r = 0; r < 4; r++) { let line = ''; for (let c = 0; c < 4; c++) line += cells[r + 4 * c].classList.contains('hot') ? 'X' : '.'; out.push(line); }
    return { out, match: cells.map(c => c.querySelector('.hex').textContent).join('') === steps()[cur].state.map(hex).join('') };
  });
  console.log('end pattern:', end.out.join(' / '), ' bytes match:', end.match);
  await page.screenshot({ path: dir + '/look-shift-end.png', clip: { x: 60, y: 300, width: 400, height: 400 } });
  await page.click('#next');
  await page.waitForFunction(() => steps()[cur].kind === 'mix');
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
