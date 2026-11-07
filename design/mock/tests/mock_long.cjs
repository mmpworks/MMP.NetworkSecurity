// Drives the Long text tab and the binary tooltip in a headless browser.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1100 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');
  await page.hover('#grid .cell:nth-child(1)');
  console.log('tip, start:', JSON.stringify(await page.textContent('#bintip')));
  await page.evaluate(() => { speed = 0.2; });
  await page.click('#next');
  await page.waitForFunction(() => window.settled === true);
  await page.mouse.move(5, 5);
  await page.hover('#grid .cell:nth-child(1)');
  console.log('tip, after ARK:', JSON.stringify(await page.textContent('#bintip')));
  await page.screenshot({ path: dir + '/look-tip.png', clip: { x: 0, y: 200, width: 760, height: 520 } });
  await page.click('#tab-long');
  console.log('says:', await page.textContent('#longnote'));
  await page.screenshot({ path: dir + '/look-long.png', fullPage: true });
  await page.click('#flipbit');
  console.log('flip:', await page.textContent('#flipsays'), '|', await page.textContent('#longnote'));
  await page.hover('#modes tr:nth-child(2) td:nth-child(4) code');
  console.log('tip lines on a cipher block:', (await page.textContent('#bintip')).split('\n').length);
  await page.screenshot({ path: dir + '/look-long-flip.png', clip: { x: 0, y: 120, width: 1280, height: 420 } });
  console.log('captions:', await page.textContent('#cap-plain'), '|', await page.textContent('#cap-ecb'), '|', await page.textContent('#cap-cbc'));
  await page.setViewportSize({ width: 400, height: 900 });
  for (const t of ['block', 'keys', 'field', 'long']) {
    await page.click('#tab-' + t);
    console.log('phone', t, await page.evaluate(() => document.documentElement.scrollWidth));
  }
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
