// Proves that Pause freezes mid-motion, holds, and that Resume carries on, in all three views.
const path = require('path');
const { chromium } = require(path.join(process.argv[2], 'node_modules', 'playwright'));
const dir = process.argv[3];
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 1300 } });
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto('file:///' + dir + '/aes-walk-mock.page.html');

  // Key schedule, mid-word.
  await page.click('#tab-keys');
  await page.click('#kplay');
  await page.waitForFunction(() => filling && !document.querySelector('#keq').hidden && filling.count === 1, null, { timeout: 20000 });
  await page.click('#kplay');
  const keySnap = () => page.evaluate(() => ({ word: filling && filling.word, count: filling && filling.count, eq: document.querySelector('.keqtop').textContent, label: document.querySelector('#kplay').textContent }));
  const k1 = await keySnap();
  await page.waitForTimeout(4000);
  const k2 = await keySnap();
  console.log('key paused:', JSON.stringify(k1), '| held for 4 s:', JSON.stringify(k1) === JSON.stringify(k2));
  const shownEq = await page.textContent('.keqtop');
  await page.hover('#build .kb.pick');
  console.log('hover works while paused:', !(await page.evaluate(() => document.querySelector('#bintip').hidden)), '| equation still', shownEq);
  await page.click('#kplay');
  console.log('key label after Resume:', await page.textContent('#kplay'));
  await page.waitForFunction(() => filling && filling.word > 4 || (filling && filling.count > 1), null, { timeout: 15000 });
  console.log('key carried on from byte', await page.evaluate(() => filling.count));
  await page.click('#kplay');                       // pause again
  await page.click('#knext');                       // Next while paused
  const n = await page.evaluate(() => ({ paused: clock.paused, chosen, label: document.querySelector('#kplay').textContent }));
  console.log('Next while paused:', JSON.stringify(n));
  await page.click('#kback');
  console.log('Back clears:', JSON.stringify(await page.evaluate(() => ({ paused: clock.paused, flyers: document.querySelectorAll('.kflyer').length, picks: document.querySelectorAll('.pick').length }))));

  // Single-word Next can pause too, with a flyer in the air.
  await page.click('#knext');
  await page.waitForSelector('.kflyer', { timeout: 15000 });
  await page.click('#kplay');
  const fly1 = await page.evaluate(() => document.querySelector('.kflyer').getBoundingClientRect().left);
  await page.waitForTimeout(1500);
  const fly2 = await page.evaluate(() => document.querySelector('.kflyer') && document.querySelector('.kflyer').getBoundingClientRect().left);
  console.log('flying byte frozen:', fly1 === fly2, Math.round(fly1));
  await page.click('#kplay');
  await page.waitForFunction(() => !document.querySelector('.kflyer') || filling === null, null, { timeout: 8000 });
  await page.click('#kreset');

  // MixColumns, during the overflow bit flight.
  await page.click('#tab-block');
  await page.click('#run-fips');
  await page.evaluate(() => { speed = 1; cur = firstOfRound(1) + 2; render(); mv.pos = 5; renderMix(false); });
  await page.click('#mplay');
  await page.waitForSelector('.ovfly', { timeout: 15000 });
  await page.click('#mplay');
  const m1 = await page.evaluate(() => ({ pos: mv.pos, x: document.querySelector('.ovfly').getBoundingClientRect().left, label: document.querySelector('#mplay').textContent }));
  await page.waitForTimeout(3000);
  const m2 = await page.evaluate(() => ({ pos: mv.pos, x: document.querySelector('.ovfly').getBoundingClientRect().left, label: document.querySelector('#mplay').textContent }));
  console.log('matrix paused mid-flight:', JSON.stringify(m1), '| held:', JSON.stringify(m1) === JSON.stringify(m2));
  await page.click('#mplay');
  await page.waitForFunction(p => mv.pos > p, m1.pos, { timeout: 15000 });
  console.log('matrix carried on to pos', await page.evaluate(() => mv.pos));
  await page.click('#mnext');
  console.log('matrix Next stops Play:', await page.evaluate(() => ({ playing: mplaying, paused: clock.paused })));

  // Block view, during the ShiftRows roll.
  await page.evaluate(() => { stop(); cur = firstOfRound(1); render(); speed = 1.5; });
  await page.click('#next');
  await page.waitForSelector('.rollstrip');
  await page.waitForTimeout(300);
  await page.click('#play');
  const pos = () => page.evaluate(() => { const s = document.querySelector('.rollstrip > div'); return s ? s.getBoundingClientRect().left : null; });
  const b1 = await pos();
  await page.waitForTimeout(1500);
  const b2 = await pos();
  console.log('roll frozen:', b1 === b2, '| label:', await page.textContent('#play'));
  await page.click('#play');
  await page.waitForFunction(() => window.settled === true, null, { timeout: 20000 });
  const end = await page.evaluate(() => ({ match: cells.map(c => c.querySelector('.hex').textContent).join('') === steps()[cur].state.map(hex).join(''), strips: document.querySelectorAll('.rollstrip').length, label: document.querySelector('#play').textContent }));
  console.log('roll finished:', JSON.stringify(end));
  console.log('page errors:', errors.length, errors.slice(0, 3));
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
