// Captures the ShiftRows roll mid-motion, then interrupts one to prove no strip or hidden cell is left behind.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.evaluate(() => { cur = firstOfRound(1); render(); speed = 2.2; });
  await page.click('#next');                       // from SubBytes to ShiftRows
  await page.waitForSelector('.rollstrip');
  await page.waitForTimeout(3200);                 // row 2 is rolling by now
  await page.screenshot({ path: dir + '/look-roll.png', clip: { x: 60, y: 300, width: 640, height: 400 } });
  console.log('strips during motion:', await page.locator('.rollstrip').count());
  await page.click('#back');                       // interrupt
  const left = await page.evaluate(() => ({
    strips: document.querySelectorAll('.rollstrip').length,
    hidden: cells.filter(c => c.style.visibility === 'hidden').length,
    shown: cells.map(c => c.querySelector('.hex').textContent).join(''),
    want: steps()[cur].state.map(hex).join(''),
  }));
  console.log('after interrupt:', JSON.stringify({ strips: left.strips, hidden: left.hidden, match: left.shown === left.want }));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
