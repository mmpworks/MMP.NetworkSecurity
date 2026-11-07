"""Adds the lifted phantom copy of the word before, for key schedule words that transform it."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<div class="keq" id="keq" aria-live="polite" hidden></div>''',
     '''<p class="note kwhy" id="kwhy" hidden></p>
        <div class="keq" id="keq" aria-live="polite" hidden></div>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.kgrid { position: relative; }
.kphantom { position: absolute; z-index: 6; overflow: hidden; border-radius: 8px; box-shadow: 0 12px 26px rgba(0,0,0,.42); outline: 2px solid var(--accent); background: var(--panel); pointer-events: none; }
.kphantom .pstrip { display: flex; flex-direction: column; gap: 3px; }
.kphantom .pcell { height: 50px; flex: 0 0 50px; border-radius: 6px; background: var(--accent-soft); display: grid; place-items: center; font: 600 15px var(--mono); }
.kphantom .pcell.pick { background: var(--fg); color: var(--bg); }
.kwhy { color: var(--fg); }
.build .s1 { background: var(--accent-soft); }""")
swap('''h += row("RotWord: rotate left one byte", chips(w.rotated, "rot"));''',
     '''h += row("RotWord: rotate one byte, up this column", chips(w.rotated, "rot"));''')
swap('''    var gap = fill ? ms(420) : ms(120);''', '''    var gap = fill ? stageGap(S().words[chosen]) : ms(120);''')
swap('''  return b.children.length;
}
function clearPicks() {''', '''  var why = $("kwhy"), wc = chosen === null ? null : S().words[chosen];
  if (wc && !wc.key && (wc.rotated || wc.substituted)) {
    why.hidden = false;
    why.textContent = wc.rotated
      ? "RotWord works on a copy of w" + (chosen - 1) + ", so w" + (chosen - 1) + " itself does not change. The copy moves up one byte, and the top byte wraps to the bottom. All 4 bytes of w" + chosen + " then use this one finished copy. The next word that does this is w" + (chosen + nk) + "."
      : "AES-256 only: a copy of w" + (chosen - 1) + " goes through the S-box, with no rotation. w" + (chosen - 1) + " itself does not change.";
  } else why.hidden = true;
  return b.children.length;
}
/* The phantom: a lifted copy of the word before. It rotates and changes in view, then lines up row by row with the new word. */
var kph = null;
function stageGap(w) { return w && !w.key && (w.rotated || w.substituted) && !reduced.matches ? ms(950) : ms(420); }
function removePhantom() { if (kph) { kph.box.remove(); kph = null; } }
function makePhantom(word) {
  removePhantom();
  var col = kcells.filter(function (k) { return k.word === word; }).sort(function (a, b) { return a.b - b.b; });
  var first = col[0].el, grid = first.parentElement;
  var box = document.createElement("div");
  box.className = "kphantom";
  box.style.left = first.offsetLeft + "px";
  box.style.top = first.offsetTop + "px";
  box.style.width = first.offsetWidth + "px";
  box.style.height = (col[3].el.offsetTop + col[3].el.offsetHeight - first.offsetTop) + "px";
  var strip = document.createElement("div");
  strip.className = "pstrip";
  var values = S().words[word].word;
  values.forEach(function (b) {
    var c = document.createElement("div");
    c.className = "pcell"; c.textContent = hex(b);
    strip.appendChild(c);
  });
  box.appendChild(strip);
  grid.appendChild(box);
  kph = { box: box, strip: strip, cells: Array.prototype.slice.call(strip.children), pitch: col[1].el.offsetTop - first.offsetTop };
  box.animate([{ transform: "none", opacity: 0.4 }, { transform: "translate(12px,-20px) scale(1.04)", opacity: 1 }], { duration: ms(380), easing: "ease-out", fill: "forwards" });
}
function phantomShow(values) { kph.cells.forEach(function (c, j) { c.textContent = hex(values[j]); }); }
function phantomRotate(w, t) {
  var extra = document.createElement("div");
  extra.className = "pcell"; extra.textContent = kph.cells[0].textContent;
  kph.strip.appendChild(extra);
  var move = kph.strip.animate([{ transform: "none" }, { transform: "translateY(" + (-kph.pitch) + "px)" }], { duration: ms(720), easing: "ease-in-out", fill: "forwards" });
  move.finished.catch(function () {}).then(function () {
    if (t !== ktoken || !kph) return;
    move.cancel(); extra.remove(); phantomShow(w.rotated);
  });
}
function phantomFlip(values, only) {
  kph.cells.forEach(function (c, j) {
    if (only !== undefined && only !== j) return;
    var half = c.animate([{ transform: "rotateX(0)" }, { transform: "rotateX(90deg)" }], { duration: ms(170), delay: j * ms(70), fill: "forwards" });
    half.finished.catch(function () {}).then(function () {
      if (!kph || kph.cells[j] !== c) return;
      c.textContent = hex(values[j]);
      half.cancel();
      c.animate([{ transform: "rotateX(90deg)" }, { transform: "rotateX(0)" }], { duration: ms(170) });
    });
  });
}
function runPhantom(w, t) {
  makePhantom(w.i - 1);
  var gap = stageGap(w), guard = function (fn) { return function () { if (t === ktoken && kph) fn(); }; };
  if (w.rotated) {
    later(guard(function () { phantomRotate(w, t); }), gap);
    later(guard(function () { phantomFlip(w.substituted); }), gap * 2);
    later(guard(function () { phantomFlip(w.afterRcon, 0); }), gap * 3);
  } else {
    later(guard(function () { phantomFlip(w.substituted); }), gap);
  }
}
function flattenPhantom(t) {
  if (!kph) return Promise.resolve();
  var box = kph.box;
  box.getAnimations().forEach(function (a) { a.cancel(); });
  var down = box.animate([{ transform: "translate(12px,-20px) scale(1.04)", opacity: 1 }, { transform: "none", opacity: 0 }], { duration: ms(480), easing: "ease-in", fill: "forwards" });
  return down.finished.catch(function () {}).then(function () { if (t === ktoken) removePhantom(); });
}
function pickKeyLine(word, j) {
  var inKey = document.querySelector('#keystr .kb[data-stage="key' + word + '"][data-j="' + j + '"]');
  if (inKey) inKey.classList.add("pick");
}
function clearPicks() {''')
swap('''  pickWordByte(word - 1, sourceByteOfPrevious(w, j));''',
     '''  if (kph) { kph.cells[j].classList.add("pick"); pickKeyLine(word - 1, sourceByteOfPrevious(w, j)); }
  else pickWordByte(word - 1, sourceByteOfPrevious(w, j));''')
swap('''  var t = ++ktoken;
  filling = null; clearPicks();
  chosen = built; built++;''', '''  var t = ++ktoken;
  filling = null; clearPicks(); removePhantom();
  chosen = built; built++;''')
swap('''  var w = S().words[chosen], rows = renderBuild(true);
  return wait((rows - 1) * ms(420) + ms(280)).then(function () { return fillByte(w, 0, t); }).then(function (done) {
    if (t !== ktoken) return false;
    filling = null; clearPicks(); $("keq").hidden = true;''', '''  var w = S().words[chosen], rows = renderBuild(true);
  if (w.rotated || w.substituted) runPhantom(w, t);
  return wait((rows - 1) * stageGap(w) + ms(280)).then(function () { return fillByte(w, 0, t); }).then(function (done) {
    if (t !== ktoken) return false;
    clearPicks();
    return flattenPhantom(t).then(function () { return done; });
  }).then(function (done) {
    if (t !== ktoken) return false;
    filling = null; $("keq").hidden = true;''')
swap('''function kstop() { clockResume(); kplaying = false; ktoken++; filling = null; clearPicks(); $("keq").hidden = true; }''',
     '''function kstop() { clockResume(); kplaying = false; ktoken++; filling = null; clearPicks(); removePhantom(); $("keq").hidden = true; }''')
path.write_text(text, encoding="utf-8")
print("patched")
