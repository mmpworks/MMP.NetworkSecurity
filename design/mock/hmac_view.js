/* HMAC and chain view. Every value comes from the script, which reproduces the spec's case 002. */
var hv = { step: -1, playing: false, tok: 0, attacked: false, chainShown: 5, chainPlaying: false, ctok: 0, attack: "none" };
function chipsHex(h, cls, perRow) {
  var out = "";
  for (var i = 0; i < h.length; i += 2) out += '<span class="kb ' + (cls || "") + '">' + h.substr(i, 2) + "</span>";
  return '<span class="hexchips" style="--per:' + (perRow || 16) + '">' + out + "</span>";
}
function shortHash(h) { return h.slice(0, 8) + "…" + h.slice(-8); }
function renderAttackDemo() {
  var A = D.hmac.attack, on = hv.attacked, msg = on ? A.changed : A.message;
  $("hmsg").textContent = msg;
  $("hattack").textContent = on ? "Put it back" : "Change 100 to 900";
  $("hplain").textContent = on
    ? "The attacker changes the message and works out a new hash: " + shortHash(A.changedHash) + ". The hash has no key, so anyone can do this. The receiver's check passes, and the change goes unseen."
    : "Hash: " + shortHash(A.messageHash) + ". The receiver hashes the message and compares.";
  $("hplain").className = "gverdict " + (on ? "bad" : "good");
  $("hkeyed").textContent = on
    ? "The attacker changes the message but has no key, so the tag stays " + shortHash(A.messageTag) + ". The receiver works out " + shortHash(A.changedTag) + ". They differ, so the receiver rejects the message."
    : "HMAC: " + shortHash(A.messageTag) + ". Only someone holding the key can make this tag.";
  $("hkeyed").className = "gverdict " + (on ? "good" : "good");
}
var HSTEPS = [
  ["The key, padded with zeros to 64 bytes", "padded", "SHA-256 works on 64-byte blocks, so a short key is filled out with zeros."],
  ["XOR every byte with 36, the inner pad", "inner", "This makes the first key block. Hover a byte to see its bits."],
  ["SHA-256 of that block plus the message", "innerHash", "This is the inner hash. It covers the key and the message."],
  ["XOR every key byte with 5c, the outer pad", "outer", "This makes a second key block, different from the first one."],
  ["SHA-256 of that block plus the inner hash", "tag", "This is the HMAC tag. Hashing a second time under the key stops an attacker from adding to the end of the message."]
];
function renderHmacSteps() {
  var B = D.hmac.build, h = "";
  HSTEPS.forEach(function (st, i) {
    var seen = hv.step === -1 || i <= hv.step, now = hv.step === i;
    h += '<div class="hstep' + (now ? " on" : "") + (seen ? "" : " later") + '"><b>' + (i + 1) + ". " + st[0] + "</b>" +
      (seen ? chipsHex(B[st[1]], i === 4 ? "tagbyte" : "", 16) : '<span class="note">Not worked out yet</span>') +
      (seen ? '<span class="note">' + st[2] + "</span>" : "") + "</div>";
  });
  $("hsteps").innerHTML = h;
  $("hplay").textContent = isPaused("hmac") ? "Resume" : hv.playing ? "Pause" : "Play the steps";
  var now = $("hsteps").querySelector(".hstep.on");
  if (now && !reduced.matches && hv.playing) now.animate([{ opacity: 0, transform: "translateY(8px)" }, { opacity: 1, transform: "none" }], { duration: ms(420), easing: "ease-out" });
}
function hLoop(t) {
  if (!hv.playing || t !== hv.tok) return;
  if (hv.step >= HSTEPS.length - 1) { hv.playing = false; renderHmacSteps(); return; }
  hv.step++;
  renderHmacSteps();
  later(function () { hLoop(t); }, reduced.matches ? 60 : ms(2400));
}
function hStop() { clockResume(); hv.playing = false; hv.tok++; }

/* The chain. Each case is what the spec's verifier does, and the reason text is the verifier's. */
var CASES = {
  none: { label: "No change" },
  change: { label: "Change event 3" },
  remove: { label: "Remove event 3" },
  rewrite: { label: "Rewrite with the key" }
};
function caseData() { return D.hmac.chain.cases[hv.attack] || null; }
function renderChain() {
  var C = D.hmac.chain, cs = caseData(), list = cs ? cs.entries : C.entries, h = "";
  list.forEach(function (e, i) {
    var hidden = !cs && i >= hv.chainShown;
    var st = e.status || (hidden ? "later" : "ok");
    var word = { ok: "Seal checks out", later: "Not built yet", bad: "Stops here", skip: "Not reached" }[st] || "";
    h += '<div class="cevent ' + st + (e.changed ? " changed" : "") + '"><div class="chead"><b>Event ' + e.seq + "</b><span>" + word + "</span></div>" +
      '<code class="ctext">' + e.text + "</code>" +
      (hidden ? "" : '<div class="clinks"><span>Previous seal <code class="seal" title="' + e.prev + '">' + shortHash(e.prev) + '</code></span><span>Seal <code class="seal sealout" title="' + e.seal + '">' + shortHash(e.seal) + "</code>" + (e.oldSeal ? ' <span class="note">was ' + shortHash(e.oldSeal) + "</span>" : "") + "</span></div>") + "</div>";
    if (i < list.length - 1) h += '<div class="clink" aria-hidden="true"></div>';
  });
  $("clist").innerHTML = h;
  var root = cs && cs.root ? cs.root : C.root;
  $("croot").textContent = root;
  $("csealed").textContent = C.root;
  $("crootrow").className = "mono longtext " + (root === C.root ? "" : "rootbad");
  var v = $("cverdict");
  if (cs) { v.hidden = false; v.innerHTML = cs.verdict; v.className = "gverdict " + (cs.caught === "chain" ? "good" : "good"); }
  else if (hv.chainShown >= list.length) { v.hidden = false; v.className = "gverdict good"; v.textContent = "All 5 seals check out, and the 5 seals make the sealed Merkle root."; }
  else v.hidden = true;
  Array.prototype.forEach.call($("ccases").children, function (b) { b.setAttribute("aria-pressed", b.dataset.case === hv.attack ? "true" : "false"); });
  $("cplay").textContent = isPaused("chain") ? "Resume" : hv.chainPlaying ? "Pause" : "Build the chain";
}
function cStop() { clockResume(); hv.chainPlaying = false; hv.ctok++; }
function cLoop(t) {
  if (!hv.chainPlaying || t !== hv.ctok) return;
  if (hv.chainShown >= 5) { hv.chainPlaying = false; renderChain(); return; }
  hv.chainShown++;
  renderChain();
  var cards = $("clist").querySelectorAll(".cevent"), card = cards[hv.chainShown - 1];
  if (card && !reduced.matches) card.animate([{ transform: "scale(1.03)", outlineColor: "transparent" }, { transform: "none" }], { duration: ms(380), easing: "ease-out" });
  later(function () { cLoop(t); }, reduced.matches ? 60 : ms(1500));
}
function setupHmac() {
  var C = D.hmac.chain;
  $("hattack").onclick = function () { hv.attacked = !hv.attacked; renderAttackDemo(); };
  $("hkeyline").textContent = "Key: " + D.hmac.build.keyText + ". Message: " + D.hmac.attack.message + ". Made-up values, for the walk only.";
  $("hplay").onclick = function () {
    if (isPaused("hmac")) { clockResume(); renderHmacSteps(); return; }
    if (hv.playing) { clockPause("hmac"); renderHmacSteps(); return; }
    clockResume();
    if (hv.step >= HSTEPS.length - 1 || hv.step === -1) hv.step = -2;
    hv.step = hv.step === -2 ? -1 : hv.step;
    hv.playing = true;
    var t = ++hv.tok;
    if (hv.step === -1) { hv.step = 0; renderHmacSteps(); later(function () { hLoop(t); }, reduced.matches ? 60 : ms(2400)); }
    else hLoop(t);
  };
  $("hnext").onclick = function () { hStop(); hv.step = hv.step >= HSTEPS.length - 1 || hv.step === -1 ? 0 : hv.step + 1; renderHmacSteps(); };
  $("hall").onclick = function () { hStop(); hv.step = -1; renderHmacSteps(); };
  $("ctenant").textContent = C.tenant;
  $("ckey").textContent = C.sessionKey;
  $("cplay").onclick = function () {
    if (isPaused("chain")) { clockResume(); renderChain(); return; }
    if (hv.chainPlaying) { clockPause("chain"); renderChain(); return; }
    clockResume();
    hv.attack = "none"; hv.chainShown = 0; hv.chainPlaying = true;
    var t = ++hv.ctok;
    renderChain();
    cLoop(t);
  };
  Object.keys(CASES).forEach(function (k) {
    var b = document.createElement("button");
    b.textContent = CASES[k].label; b.dataset.case = k;
    b.onclick = function () { cStop(); hv.attack = k; hv.chainShown = 5; renderChain(); };
    $("ccases").appendChild(b);
  });
  renderAttackDemo(); renderHmacSteps(); renderChain();
}

