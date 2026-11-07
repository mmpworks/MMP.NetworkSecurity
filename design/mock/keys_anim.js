/* filling holds the word being built and how many of its bytes are on screen. */
var filling = null;
function cellShown(k) {
  if (k.word >= built) return false;
  return !(filling && k.word === filling.word && k.b % 4 >= filling.count);
}
function renderKeys() {
  kcells.forEach(function (k) {
    var shown = cellShown(k), cl = k.el.classList, nk = S().nk, value = S().words[k.word].word[k.b % 4];
    k.el.querySelector(".hex").textContent = shown ? hex(value) : "";
    k.el.setAttribute("aria-label", "Word " + k.word + (shown ? ", byte " + hex(value) : ", not built yet"));
    cl.toggle("unbuilt", !shown && !(chosen === k.word));
    cl.toggle("new", k.word === chosen);
    cl.toggle("src1", chosen !== null && chosen >= nk && k.word === chosen - 1);
    cl.toggle("src2", chosen !== null && chosen >= nk && k.word === chosen - nk);
  });
  $("kback").disabled = built <= S().nk;
  $("knext").disabled = built >= S().words.length;
  $("kplay").textContent = kplaying ? "Pause" : "Play";
}
function chips(word, stage) {
  return word.map(function (b, j) { return '<span class="kb" data-stage="' + stage + '" data-j="' + j + '">' + hex(b) + "</span>"; }).join("");
}
function blankChips(stage) {
  return [0, 1, 2, 3].map(function (j) { return '<span class="kb empty" data-stage="' + stage + '" data-j="' + j + '">--</span>'; }).join("");
}
function row(label, val, cls) { return '<div class="' + (cls || "") + '"><b>' + label + "</b><code>" + val + "</code></div>"; }
function combineWord(w) { return w.afterRcon || w.substituted || w.previous; }
function renderBuild(fill) {
  var h = "", title, nk = S().nk;
  $("keq").hidden = true;
  if (chosen === null) {
    title = "The key fills w0 to w" + (nk - 1);
    for (var i = 0; i < nk; i++) h += row("w" + i, chips(S().words[i].word, "key"));
    h += row("Next to build", "w" + nk);
  } else {
    var w = S().words[chosen], plain = !w.afterRcon && !w.substituted;
    title = "How w" + chosen + " is made";
    if (w.key) h = row("w" + chosen + " is the key itself", chips(w.word, "new"), "last");
    else {
      h += row("The word before, w" + (chosen - 1), chips(w.previous, plain ? "temp" : "prev"), "s1");
      if (w.rotated) {
        h += row("RotWord: rotate left one byte", chips(w.rotated, "rot"));
        h += row("SubWord: the same S-box", chips(w.substituted, "sub"));
        h += row("XOR round constant " + hex(w.rcon), chips(w.afterRcon, "temp"));
      } else if (w.substituted) {
        h += row("AES-256 only: SubWord", chips(w.substituted, "temp"));
      }
      h += row("XOR the word " + nk + " back, w" + (chosen - nk), chips(w.keyBack, "back"), "s2");
      h += row("New word, w" + chosen, fill ? blankChips("new") : chips(w.word, "new"), "last");
    }
  }
  $("ktitle").textContent = title;
  var b = $("build"); b.innerHTML = h;
  if (!reduced.matches) Array.prototype.forEach.call(b.children, function (el, i) {
    var gap = fill ? ms(420) : ms(120);
    el.animate([{ opacity: 0, transform: "translateY(6px)" }, { opacity: 1, transform: "none" }], { duration: ms(280), delay: i * gap, easing: "ease-out", fill: "backwards" });
  });
  return b.children.length;
}
function clearPicks() {
  Array.prototype.forEach.call(document.querySelectorAll(".pick"), function (x) { x.classList.remove("pick"); });
  Array.prototype.forEach.call(document.querySelectorAll(".kflyer"), function (x) { x.remove(); });
}
/* Lights one byte of a word, in the table and in the key line if that word is part of the key. */
function pickWordByte(word, j) {
  kcells.forEach(function (k) { if (k.word === word && k.b % 4 === j) k.el.classList.add("pick"); });
  var inKey = document.querySelector('#keystr .kb[data-stage="key' + word + '"][data-j="' + j + '"]');
  if (inKey) inKey.classList.add("pick");
}
function pickChip(stage, j) {
  var el = document.querySelector('#build .kb[data-stage="' + stage + '"][data-j="' + j + '"]');
  if (el) el.classList.add("pick");
  return el;
}
/* RotWord moves each byte left, so byte j of the rotated word starts as byte j + 1 of the word before. */
function sourceByteOfPrevious(w, j) { return w.rotated ? (j + 1) % 4 : j; }
function flyTo(from, to, text, t) {
  var a = from.getBoundingClientRect(), b = to.getBoundingClientRect();
  var fly = document.createElement("div");
  fly.className = "kflyer"; fly.textContent = text;
  fly.style.left = a.left + "px"; fly.style.top = a.top + "px";
  document.body.appendChild(fly);
  var move = fly.animate([{ transform: "none" }, { transform: "translate(" + (b.left + b.width / 2 - a.left - 14) + "px," + (b.top + b.height / 2 - a.top - 12) + "px)" }], { duration: ms(520), easing: "ease-in-out", fill: "both" });
  return move.finished.catch(function () {}).then(function () { fly.remove(); });
}
function fillByte(w, j, t) {
  if (t !== ktoken) return Promise.resolve(false);
  if (j > 3) return Promise.resolve(true);
  var nk = S().nk, word = w.i, temp = combineWord(w), back = w.keyBack[j];
  clearPicks();
  pickWordByte(word - nk, j);
  pickWordByte(word - 1, sourceByteOfPrevious(w, j));
  pickChip("back", j); pickChip("temp", j);
  var eq = $("keq");
  eq.hidden = false;
  eq.innerHTML = '<div class="keqtop"><span class="k">' + hex(back) + "</span> XOR <span>" + hex(temp[j]) + '</span> = <span class="r" id="keqresult">' + hex(w.word[j]) + "</span></div>" +
    "w" + (word - nk) + " byte " + j + "   " + nibbles(back) + "\nXOR         " + nibbles(temp[j]) + "\nw" + word + " byte " + j + "   " + nibbles(w.word[j]);
  return wait(ms(800)).then(function () {
    if (t !== ktoken) return false;
    var target = null;
    kcells.forEach(function (k) { if (k.word === word && k.b % 4 === j) target = k.el; });
    return flyTo($("keqresult"), target, hex(w.word[j]), t).then(function () {
      if (t !== ktoken) return false;
      filling.count = j + 1;
      renderKeys();
      var chip = pickChip("new", j);
      if (chip) { chip.textContent = hex(w.word[j]); chip.classList.remove("empty"); }
      target.animate([{ transform: "scale(1.16)" }, { transform: "none" }], { duration: ms(260), easing: "ease-out" });
      return wait(ms(320)).then(function () { return fillByte(w, j + 1, t); });
    });
  });
}
function knext() {
  if (built >= S().words.length) return Promise.resolve(false);
  var t = ++ktoken;
  filling = null; clearPicks();
  chosen = built; built++;
  if (reduced.matches) { renderKeys(); renderBuild(false); return Promise.resolve(true); }
  filling = { word: chosen, count: 0 };
  renderKeys();
  var w = S().words[chosen], rows = renderBuild(true);
  return wait((rows - 1) * ms(420) + ms(280)).then(function () { return fillByte(w, 0, t); }).then(function (done) {
    if (t !== ktoken) return false;
    filling = null; clearPicks(); $("keq").hidden = true;
    renderKeys();
    return done;
  });
}
/* Stopping shows the current word whole. */
function kstop() { kplaying = false; ktoken++; filling = null; clearPicks(); $("keq").hidden = true; }
function kplay() {
  if (kplaying) { kstop(); renderKeys(); renderBuild(false); return; }
  kplaying = true;
  if (built >= S().words.length) { built = S().nk; chosen = null; }
  (function loop() {
    if (!kplaying) return;
    if (built >= S().words.length) { kplaying = false; renderKeys(); return; }
    renderKeys();
    knext().then(function () { if (kplaying) setTimeout(loop, ms(260)); });
  })();
  renderKeys();
}
$("kplay").onclick = kplay;
$("knext").onclick = function () { kstop(); knext(); };
$("kback").onclick = function () { kstop(); var nk = S().nk; if (built > nk) built--; chosen = built > nk ? built - 1 : null; renderKeys(); renderBuild(false); };
$("kreset").onclick = function () { kstop(); built = S().nk; chosen = null; renderKeys(); renderBuild(false); };
