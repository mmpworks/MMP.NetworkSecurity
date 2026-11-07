/* MixColumns matrix view. It walks one output byte at a time: 4 term positions, then the sum, for each of 4 rows. */
var mv = { key: null, col: 0, pos: 0, done: {}, all: false, lastCol: null };
var mplaying = false, mtimer = null;
var mixCells = { mat: [], state: [], res: [], strip: [] };
function mixBuildGrid(host, list, cls) {
  host.innerHTML = "";
  for (var i = 0; i < 16; i++) {
    var c = document.createElement("div");
    c.className = "mcell " + cls;
    c.style.gridRow = (i % 4) + 1;
    c.style.gridColumn = Math.floor(i / 4) + 1;
    c.innerHTML = '<span class="hex"></span>';
    host.appendChild(c);
    list.push(c);
  }
}
function mixBuild() {
  if (mixCells.mat.length) return;
  mixBuildGrid($("mmat"), mixCells.mat, "mfactor");
  mixBuildGrid($("mstate"), mixCells.state, "mhex");
  mixBuildGrid($("mres"), mixCells.res, "mhex");
  for (var k = 0; k < 4; k++) {
    var c = document.createElement("div");
    c.className = "mcell mhex mchip";
    c.style.gridColumn = k + 1;
    c.innerHTML = '<span class="hex"></span>';
    $("mstrip").appendChild(c);
    mixCells.strip.push(c);
  }
  [0, 1, 2, 3].forEach(function (c) {
    var b = document.createElement("button");
    b.textContent = "Column " + c;
    b.dataset.mcol = c;
    b.onclick = function () { mstop(); mv.col = c; mv.pos = 0; mv.all = false; renderMix(true); };
    $("mcols").appendChild(b);
  });
  $("mplay").onclick = mplay;
  $("mnext").onclick = function () { mstop(); mixStep(1); };
  $("mback").onclick = function () { mstop(); mixStep(-1); };
  $("mfill").onclick = function () { mstop(); [0, 1, 2, 3].forEach(function (c) { mv.done[c] = true; }); mv.all = true; renderMix(false); };
}
function mstop() { mplaying = false; clearTimeout(mtimer); if ($("mplay")) $("mplay").textContent = "Play this column"; }
/* A real position moves one term. Crossing the end of a column moves to the next column. */
function mixStep(d) {
  if (mv.all) { mv.all = false; }
  var next = mv.pos + d, moved = false;
  if (next > 19) {
    mv.done[mv.col] = true;
    if (mv.col < 3) { mv.col++; next = 0; moved = true; } else { next = 19; mv.all = true; }
  }
  if (next < 0) {
    if (mv.col > 0) { mv.col--; delete mv.done[mv.col]; next = 19; moved = true; } else next = 0;
  }
  mv.pos = next;
  renderMix(moved);
}
function mplay() {
  if (mplaying) { mstop(); return; }
  if (mv.all) { mv.all = false; mv.done = {}; mv.col = 0; mv.pos = 0; renderMix(true); }
  mplaying = true;
  $("mplay").textContent = "Pause";
  (function loop() {
    if (!mplaying) return;
    if (mv.pos >= 19) { mv.done[mv.col] = true; mstop(); renderMix(false); return; }
    var wait = mv.pos % 5 === 4 ? ms(1100) : ms(1500);
    mtimer = setTimeout(function () { if (!mplaying) return; mixStep(1); loop(); }, reduced.matches ? 500 : wait);
  })();
}
function mixTermWords(p) {
  var name = p.factor + " × " + hex(p.byte);
  if (p.factor === 1) return { top: name + " = " + hex(p.result), how: "Times 1 leaves the byte as it is." };
  var d = p.doublings[0];
  var dbl = "Field multiply by 2: shift left to get " + d.shifted.toString(16) + ". " +
    (d.reduced ? "That is too big for a byte, so XOR 11b. It gives " + hex(d.to) + "." : "It fits in a byte, so it stays " + hex(d.to) + ".");
  if (p.factor === 2) return { top: name + " = " + hex(p.result), how: dbl };
  return { top: name + " = " + hex(p.result), how: dbl + " Times 3 is times 2, XOR the byte: " + hex(d.to) + " XOR " + hex(p.byte) + " = " + hex(p.result) + "." };
}
function renderMix(flyColumn) {
  var s = steps()[cur];
  if (s.kind !== "mix") return;
  var before = steps()[cur - 1].state, col = mv.col, r = Math.floor(mv.pos / 5), k = mv.pos % 5;
  var terms = s.terms[col], row = terms[r];
  mixCells.mat.forEach(function (el, i) {
    var rr = i % 4, cc = Math.floor(i / 4);
    el.querySelector(".hex").textContent = s.terms[0][rr].parts[cc].factor;
    el.classList.toggle("mrow", !mv.all && rr === r);
    el.classList.toggle("mpair", !mv.all && rr === r && cc === k);
  });
  mixCells.state.forEach(function (el, i) {
    el.querySelector(".hex").textContent = hex(before[i]);
    el.classList.toggle("mcolhot", !mv.all && Math.floor(i / 4) === col);
    el.classList.toggle("mpairsrc", !mv.all && Math.floor(i / 4) === col && i % 4 === k);
  });
  mixCells.strip.forEach(function (el, j) {
    el.querySelector(".hex").textContent = hex(before[col * 4 + j]);
    el.classList.toggle("mpair", !mv.all && j === k);
    el.style.visibility = mv.all ? "hidden" : "";
  });
  mixCells.res.forEach(function (el, i) {
    var rr = i % 4, cc = Math.floor(i / 4);
    var filled = mv.done[cc] || (cc === col && (rr < r || (rr === r && k === 4)));
    el.querySelector(".hex").textContent = filled ? hex(s.state[i]) : "";
    el.classList.toggle("mempty", !filled);
    el.classList.toggle("mnew", !mv.all && cc === col && rr === r && k === 4);
  });
  Array.prototype.forEach.call($("mcols").children, function (b) { b.setAttribute("aria-pressed", +b.dataset.mcol === col && !mv.all ? "true" : "false"); });
  var box = $("mbox");
  if (mv.all || k > 3) box.hidden = true;
  else {
    box.hidden = false;
    var wrap = $("mmatwrap").getBoundingClientRect(), chip = mixCells.strip[k].getBoundingClientRect(), cell = mixCells.mat[r + 4 * k].getBoundingClientRect();
    box.style.left = (chip.left - wrap.left - 3) + "px";
    box.style.top = (chip.top - wrap.top - 3) + "px";
    box.style.width = (chip.width + 6) + "px";
    box.style.height = (cell.bottom - chip.top + 6) + "px";
  }
  var cap = $("mcap"), run = $("mrun");
  if (mv.all) {
    cap.innerHTML = "<b>All 4 columns are done.</b><span>The result is the state after MixColumns.</span>";
    run.innerHTML = "";
  } else if (k < 4) {
    var w = mixTermWords(row.parts[k]);
    cap.innerHTML = "<b>" + w.top + "</b><span>Row " + r + " of the matrix, byte " + k + " of column " + col + ". " + w.how + "</span>";
  } else {
    cap.innerHTML = "<b>Output byte " + r + " = " + hex(row.total) + "</b><span>Add the 4 results with XOR. The answer goes in row " + r + ", column " + col + ".</span>";
  }
  if (!mv.all) {
    var shown = row.parts.map(function (p, j) { return j <= k ? '<span class="kb' + (j === k ? " pick" : "") + '">' + hex(p.result) + "</span>" : '<span class="kb empty">--</span>'; });
    run.innerHTML = shown.join(" xor ") + " = " + (k === 4 ? '<span class="kb pick">' + hex(row.total) + "</span>" : '<span class="kb empty">--</span>');
  }
  $("mback").disabled = col === 0 && mv.pos === 0 && !mv.all;
  $("mnext").disabled = !!mv.all;
  if (!reduced.matches && !mv.all) {
    if (flyColumn) mixCells.strip.forEach(function (el, j) {
      var from = mixCells.state[col * 4 + j].getBoundingClientRect(), to = el.getBoundingClientRect();
      el.animate([{ transform: "translate(" + (from.left - to.left) + "px," + (from.top - to.top) + "px)" }, { transform: "none" }], { duration: ms(560), delay: j * ms(90), easing: "ease-in-out", fill: "backwards" });
    });
    if (k === 4) {
      var target = mixCells.res[r + 4 * col];
      target.animate([{ transform: "scale(1.25)" }, { transform: "none" }], { duration: ms(320), easing: "ease-out" });
    }
  }
}
function mixSync() {
  var s = steps()[cur], card = $("mixcard");
  if (s.kind !== "mix") { card.hidden = true; mstop(); mv.key = null; return; }
  mixBuild();
  card.hidden = false;
  var key = size + "/" + run + "/" + cur, wanted = sel === null ? null : Math.floor(sel / 4);
  if (mv.key !== key) {
    mstop();
    mv.key = key; mv.col = wanted === null ? 0 : wanted; mv.pos = 0; mv.done = {}; mv.all = false; mv.lastCol = wanted;
    renderMix(false);
    return;
  }
  if (wanted !== null && wanted !== mv.lastCol) {
    mstop(); mv.lastCol = wanted; mv.col = wanted; mv.pos = 0; mv.all = false;
    renderMix(true);
    return;
  }
  renderMix(false);
}

