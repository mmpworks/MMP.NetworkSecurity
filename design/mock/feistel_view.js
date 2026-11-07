/* Feistel view. A step moves through each round: F, then XOR, then swap. All values come from the script. */
var fv = { f: "hash", dir: "enc", p: null, playing: false, tok: 0 };
function feistelRun() { return D.feistel.functions[fv.f][fv.dir]; }
function feistelLast() { return feistelRun().rounds.length * 3 - 1; }
function fchips(h, cls) {
  var out = "";
  for (var i = 0; i < h.length; i += 2) out += '<span class="kb ' + (cls || "") + '">' + h.substr(i, 2) + "</span>";
  return '<span class="fchips">' + out + "</span>";
}
function fText(h) {
  var s = "";
  for (var i = 0; i < h.length; i += 2) { var b = parseInt(h.substr(i, 2), 16); s += b >= 32 && b < 127 ? String.fromCharCode(b) : "."; }
  return s;
}
function renderFeistel() {
  var run = feistelRun(), rows = run.rounds, showAll = fv.p === null, h = "";
  h += "<tr><th>Round</th><th>Key</th><th>Left</th><th>Right</th><th>F(right, key)</th><th>Left XOR F</th><th>Next left, next right</th></tr>";
  rows.forEach(function (r, i) {
    var at = showAll ? 3 : (fv.p === -1 ? -1 : Math.min(3, fv.p - i * 3 + 1));
    var live = !showAll && fv.p >= i * 3 && fv.p < (i + 1) * 3;
    var seenRow = showAll || fv.p >= i * 3;
    h += '<tr class="' + (live ? "fnow" : "") + (seenRow ? "" : " flater") + '"><td>' + (i + 1) + "</td><td>" + fchips(r.key, "fkey") + "</td><td>" + fchips(r.left) + "</td><td>" + fchips(r.right, at === 1 && live ? "pick" : "") + "</td>" +
      "<td>" + (at >= 1 ? fchips(r.f, at === 1 && live ? "pick" : "") : "") + "</td>" +
      "<td>" + (at >= 2 ? fchips(r.out, at === 2 && live ? "pick" : "") : "") + "</td>" +
      "<td>" + (at >= 3 ? fchips(r.right) + " " + fchips(r.out) : "") + "</td></tr>";
  });
  $("ftable").innerHTML = h;
  var cap = $("fcap"), done = showAll || fv.p >= feistelLast();
  if (showAll) cap.innerHTML = "<b>All " + rows.length + " rounds shown.</b><span>Press Play to step through them.</span>";
  else if (fv.p === -1) cap.innerHTML = "<b>Split the block in half.</b><span>Left and right. Each round changes only one half.</span>";
  else if (!done) {
    var n = Math.floor(fv.p / 3), part = fv.p % 3, r = rows[n], words = [
      ["F(" + r.right + ", key) = " + r.f, "Run the right half and the round key through F. The right half itself does not change."],
      [r.left + " XOR " + r.f + " = " + r.out, "XOR that with the left half. This is the only part that changes the bytes."],
      ["Swap", "The old right half becomes the new left, and the XOR answer becomes the new right."]
    ][part];
    cap.innerHTML = "<b>Round " + (n + 1) + ": " + words[0] + "</b><span>" + words[1] + "</span>";
  } else cap.innerHTML = "<b>Round " + rows.length + " done.</b><span>A last swap undoes the swap at the end of this round. DES does this too. It is why the same steps decrypt.</span>";
  var finished = showAll || done, outHex = run.output;
  $("fin").innerHTML = fchips(run.input) + ' <span class="mono ftext">' + fText(run.input) + "</span>";
  $("fout").innerHTML = finished ? fchips(outHex, "tagbyte") + ' <span class="mono ftext">' + fText(outHex) + "</span>" : '<span class="note">Not finished yet</span>';
  var F = D.feistel.functions[fv.f];
  $("fsays").textContent = F.says;
  $("fback").textContent = fv.dir === "dec"
    ? (finished ? "The same steps, with the keys in reverse order, gave back the text. F was never run backward." : "These are the same steps as encrypt. Only the key order changes.")
    : (finished ? "Switch to Decrypt to run the same steps with the keys reversed." : "");
  $("fplay").textContent = isPaused("feistel") ? "Resume" : fv.playing ? "Pause" : "Play the rounds";
  Array.prototype.forEach.call($("ffn").children, function (b) { b.setAttribute("aria-pressed", b.dataset.f === fv.f ? "true" : "false"); });
  Array.prototype.forEach.call($("fdir").children, function (b) { b.setAttribute("aria-pressed", b.dataset.d === fv.dir ? "true" : "false"); });
  var now = $("ftable").querySelector(".kb.pick");
  if (now && !reduced.matches && !showAll) Array.prototype.forEach.call($("ftable").querySelectorAll(".fchips .pick"), function (el) { el.animate([{ transform: "scale(1.25)" }, { transform: "none" }], { duration: ms(280), easing: "ease-out" }); });
}
function fStop() { clockResume(); fv.playing = false; fv.tok++; }
function fLoop(t) {
  if (!fv.playing || t !== fv.tok) return;
  if (fv.p >= feistelLast()) { fv.playing = false; renderFeistel(); return; }
  fv.p++;
  renderFeistel();
  later(function () { fLoop(t); }, reduced.matches ? 60 : ms(1500));
}
function setupFeistel() {
  Object.keys(D.feistel.functions).forEach(function (k) {
    var b = document.createElement("button");
    b.textContent = D.feistel.functions[k].label; b.dataset.f = k;
    b.onclick = function () { fStop(); fv.f = k; fv.p = null; renderFeistel(); };
    $("ffn").appendChild(b);
  });
  ["enc", "dec"].forEach(function (d) {
    var b = document.createElement("button");
    b.textContent = d === "enc" ? "Encrypt" : "Decrypt"; b.dataset.d = d;
    b.onclick = function () { fStop(); fv.dir = d; fv.p = null; renderFeistel(); };
    $("fdir").appendChild(b);
  });
  $("fplay").onclick = function () {
    if (isPaused("feistel")) { clockResume(); renderFeistel(); return; }
    if (fv.playing) { clockPause("feistel"); renderFeistel(); return; }
    clockResume();
    if (fv.p === null || fv.p >= feistelLast()) fv.p = -1;
    fv.playing = true;
    var t = ++fv.tok;
    renderFeistel();
    later(function () { fLoop(t); }, reduced.matches ? 60 : ms(1100));
  };
  $("fnext").onclick = function () { fStop(); if (fv.p === null || fv.p >= feistelLast()) fv.p = -1; else fv.p++; renderFeistel(); };
  $("fall").onclick = function () { fStop(); fv.p = null; renderFeistel(); };
  renderFeistel();
}

