/* GCM view. AES locks counters, not text. The text XORs with the key stream one byte at a time. */
var gp = { pos: null, playing: false, tok: 0, flipped: false };
function gcmTotal() { return D.gcm.textBytes.length; }
function gcmBlockOf(i) { return Math.floor(i / 16); }
function gcmChar(b) { return b === 32 ? "sp" : (b >= 33 && b < 127 ? String.fromCharCode(b) : hex(b)); }
function renderGcmTape() {
  var G = D.gcm, h = "", shown = gp.pos === null ? gcmTotal() : gp.pos;
  G.blocks.forEach(function (bk, n) {
    var start = n * 16, active = gp.pos !== null && gcmBlockOf(Math.min(gp.pos, gcmTotal() - 1)) === n && gp.pos < gcmTotal();
    h += '<div class="gblock' + (active ? " on" : "") + '"><div class="ghead">Counter ' + bk.count + ': <code>' + bk.counter + "</code></div>";
    h += '<div class="grow"><b>Text</b><div class="gcells">';
    bk.plain.forEach(function (b, j) { h += '<span class="gc' + (start + j === shown ? " now" : "") + '">' + gcmChar(b) + "</span>"; });
    h += '</div></div><div class="grow"><b>Key stream</b><div class="gcells">';
    bk.stream.forEach(function (b, j) {
      var used = j < bk.plain.length, cls = "gc kb" + (used ? "" : " unusedbyte") + (start + j === shown ? " now" : "");
      var seen = gp.pos === null || (start + j) <= gp.pos || gcmBlockOf(gp.pos) >= n;
      h += '<span class="' + cls + '">' + (seen ? hex(b) : "--") + "</span>";
    });
    h += '</div></div><div class="grow"><b>Sent</b><div class="gcells">';
    bk.cipher.forEach(function (b, j) {
      var done = start + j < shown;
      h += '<span class="gc kb' + (done ? " gdone" : " empty") + '">' + (done ? hex(b) : "--") + "</span>";
    });
    h += "</div></div></div>";
  });
  $("gtape").innerHTML = h;
}
function renderGcmCaption() {
  var G = D.gcm, cap = $("gcap");
  if (gp.pos === null) {
    cap.innerHTML = "<b>" + gcmTotal() + " bytes in, " + gcmTotal() + " bytes out.</b><span>Press Play to send the text one byte at a time.</span>";
    return;
  }
  if (gp.pos >= gcmTotal()) {
    var last = G.blocks[G.blocks.length - 1], left = 16 - last.plain.length;
    cap.innerHTML = "<b>" + gcmTotal() + " bytes in, " + gcmTotal() + " bytes out.</b><span>No padding. The last block used " + last.plain.length + " key stream bytes and dropped the other " + left + ". The receiver makes the same key stream with forward AES and XORs again to get the text back.</span>";
    return;
  }
  var n = gcmBlockOf(gp.pos), j = gp.pos % 16, bk = G.blocks[n], p = bk.plain[j], s = bk.stream[j], c = bk.cipher[j];
  cap.innerHTML = "<b>" + gcmChar(p) + " (" + hex(p) + ") XOR " + hex(s) + " = " + hex(c) + "</b><span>Byte " + gp.pos + " of the text. AES never sees this byte. " + (j === 0 ? "This is the first byte of a new block, so AES just locked counter " + bk.count + " to make 16 more key stream bytes." : "It uses byte " + j + " of the key stream from counter " + bk.count + ".") + "</span>" +
    '<div class="bits gbits">  ' + nibbles(p) + "  " + hex(p) + '\nXOR <span class="k">' + nibbles(s) + "  " + hex(s) + '</span>\n  = <span class="r">' + nibbles(c) + "  " + hex(c) + "</span></div>";
}
function renderGcm() {
  renderGcmTape();
  renderGcmCaption();
  $("gplay").textContent = isPaused("gcm") ? "Resume" : gp.playing ? "Pause" : "Play the stream";
  $("gnext").disabled = gp.pos !== null && gp.pos >= gcmTotal();
}
function gstop() { clockResume(); gp.playing = false; gp.tok++; }
function gcmStep() {
  gp.pos = gp.pos === null ? 0 : Math.min(gp.pos + 1, gcmTotal());
  renderGcm();
  var row = $("gtape").querySelector(".gc.now");
  if (row && !reduced.matches) row.animate([{ transform: "scale(1.3)" }, { transform: "none" }], { duration: ms(240), easing: "ease-out" });
}
function gcmLoop(t) {
  if (!gp.playing || t !== gp.tok) return;
  if (gp.pos !== null && gp.pos >= gcmTotal()) { gp.playing = false; renderGcm(); return; }
  gcmStep();
  var starting = gp.pos < gcmTotal() && gp.pos % 16 === 0;
  later(function () { gcmLoop(t); }, reduced.matches ? 60 : (starting ? ms(1300) : ms(520)));
}
function renderGcmTag() {
  var G = D.gcm, t = G.tag, h = "";
  $("gh").textContent = G.h; $("gmask").textContent = G.mask;
  h += "<tr><th>Step</th><th>This block</th><th>XOR with the running value</th><th>Multiply by H</th></tr>";
  G.ghash.forEach(function (s) { h += "<tr><td>" + s.label + "</td><td><code>" + s.block + "</code></td><td><code>" + s.xored + "</code></td><td><code>" + s.mulled + "</code></td></tr>"; });
  $("gtable").innerHTML = h;
  var f = gp.flipped;
  $("gflip").textContent = f ? "Put the bit back" : "Flip one bit on the wire";
  $("gsent").textContent = t;
  $("gcalc").textContent = f ? G.flip.tag : t;
  $("gverdict").textContent = f
    ? "The tags differ, so the receiver rejects the message and returns no text. Without the tag, it would read: " + G.flip.text
    : "The tags match, so the receiver accepts the text.";
  $("gverdict").className = "gverdict " + (f ? "bad" : "good");
}
function setupGcm() {
  var G = D.gcm;
  $("gkey").textContent = "AES-128 test key. Nonce: " + G.nonce + ". Made-up values, for the walk only. Other data the tag protects: " + G.aad + ".";
  $("gplay").onclick = function () {
    if (isPaused("gcm")) { clockResume(); renderGcm(); return; }
    if (gp.playing) { clockPause("gcm"); renderGcm(); return; }
    clockResume();
    if (gp.pos !== null && gp.pos >= gcmTotal()) gp.pos = null;
    gp.playing = true;
    var t = ++gp.tok;
    renderGcm();
    gcmLoop(t);
  };
  $("gnext").onclick = function () { gstop(); gcmStep(); };
  $("gall").onclick = function () { gstop(); gp.pos = null; renderGcm(); };
  $("gflip").onclick = function () { gp.flipped = !gp.flipped; renderGcmTag(); };
  renderGcm(); renderGcmTag();
}

