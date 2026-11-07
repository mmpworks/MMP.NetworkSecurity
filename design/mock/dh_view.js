/* Diffie-Hellman view. Every number is looked up from the script's tables. The page does no math. */
var dv = { a: 6, b: 15, p: null, playing: false, tok: 0, tryTok: 0 };
var DH_LAST = 8;
function dhPow(base, e) { return D.dh.pow[base][e]; }
function dhVals() {
  var g = D.dh.g, A = dhPow(g, dv.a), B = dhPow(g, dv.b);
  return { g: g, n: D.dh.n, A: A, B: B, s1: dhPow(B, dv.a), s2: dhPow(A, dv.b) };
}
function dhNum(label, v, cls) {
  return '<div class="dhrow"><span class="dhlabel">' + label + '</span><span class="dhnum ' + (cls || "") + '">' + v + "</span></div>";
}
function dhChain(base, e, n) {
  var out = "";
  for (var k = 1; k <= e; k++) out += '<span class="kb ' + (k === e ? "pick" : "") + '" title="' + base + " to the power " + k + " mod " + n + '">' + dhPow(base, k) + "</span>";
  return '<span class="dhpow">' + base + "<sup>" + e + "</sup> mod " + n + ":</span> " + '<span class="fchips dhchain">' + out + "</span>";
}
function dhPaint(p) {
  var v = p === null ? DH_LAST : p;
  function dot(c, t, on) { return on ? '<span class="pdot" style="background:' + c + '" title="' + t + '"></span>' : '<span class="pdot pempty"></span>'; }
  var Y = "#f2c500", R = "#d9363e", U = "#2f6fde", O = "#e8792a", G = "#4aa35a", K = "#7a5a3a";
  return '<div><b>Client</b> ' + dot(Y, "public paint", v >= 0) + " + " + dot(R, "private paint", v >= 1) + " = " + dot(O, "public mix", v >= 3) + "</div>" +
    '<div><b>Server</b> ' + dot(Y, "public paint", v >= 0) + " + " + dot(U, "private paint", v >= 2) + " = " + dot(G, "public mix", v >= 4) + "</div>" +
    '<div><b>Client</b> ' + dot(G, "server's mix", v >= 6) + " + " + dot(R, "private paint", v >= 7) + " = " + dot(K, "shared color", v >= 7) + "</div>" +
    '<div><b>Server</b> ' + dot(O, "client's mix", v >= 5) + " + " + dot(U, "private paint", v >= 8) + " = " + dot(K, "shared color", v >= 8) + "</div>";
}
function renderDh() {
  var v = dhVals(), p = dv.p, at = function (n) { return p === null || p >= n; }, c = "", w = "", s = "";
  c += dhNum("Private number", at(1) ? dv.a : "?", "dhkey");
  if (at(3)) c += dhNum("Public number", v.A);
  if (at(6)) c += dhNum("From the server", v.B);
  if (at(7)) c += dhNum("Secret", v.s1, "dhsecret");
  if (at(0)) w += dhNum("n, the prime", v.n) + dhNum("g, the base", v.g);
  if (at(5)) w += dhNum("Client sends", v.A);
  if (at(6)) w += dhNum("Server sends", v.B);
  s += dhNum("Private number", at(2) ? dv.b : "?", "dhkey");
  if (at(4)) s += dhNum("Public number", v.B);
  if (at(5)) s += dhNum("From the client", v.A);
  if (at(8)) s += dhNum("Secret", v.s2, "dhsecret");
  $("dclient").innerHTML = c; $("dwire").innerHTML = w; $("dserver").innerHTML = s;
  $("dpaint").innerHTML = dhPaint(p);
  var words = [
    ["Both sides agree on n and g", "These two numbers are public. Anyone may read them. Often a standard fixes them in advance."],
    ["The client picks a private number", "It never leaves the client. Not even the server sees it."],
    ["The server picks a private number", "It never leaves the server."],
    ["Client: " + v.g + " to the power " + dv.a + ", mod " + v.n + " = " + v.A, "Mod " + v.n + " means: keep the remainder after dividing by " + v.n + ", like a clock with " + v.n + " hours. Going forward is easy."],
    ["Server: " + v.g + " to the power " + dv.b + ", mod " + v.n + " = " + v.B, "The server does the same with its own private number."],
    ["The client sends " + v.A, "This number crosses the wire. The listener reads it."],
    ["The server sends " + v.B, "This one crosses too. The listener now has all four public numbers."],
    ["Client: " + v.B + " to the power " + dv.a + ", mod " + v.n + " = " + v.s1, "The client uses the server's public number and its own private number."],
    ["Server: " + v.A + " to the power " + dv.b + ", mod " + v.n + " = " + v.s2, "The answers match, because both are " + v.g + " to the power " + dv.a + " times " + dv.b + ". The secret never crossed the wire."]
  ];
  var chains = [null, null, null, [v.g, dv.a], [v.g, dv.b], null, null, [v.B, dv.a], [v.A, dv.b]];
  if (p === null) {
    $("dcap").innerHTML = "<b>Both sides hold " + v.s1 + ", and it never crossed the wire.</b><span>Press Play to step through it.</span>";
    $("dchain").innerHTML = "";
  } else {
    $("dcap").innerHTML = "<b>" + words[p][0] + "</b><span>" + words[p][1] + "</span>";
    $("dchain").innerHTML = chains[p] ? dhChain(chains[p][0], chains[p][1], v.n) : "";
  }
  $("dplay").textContent = isPaused("dh") ? "Resume" : dv.playing ? "Pause" : "Play the exchange";
}
function dStop() { clockResume(); dv.playing = false; dv.tok++; }
function dLoop(t) {
  if (!dv.playing || t !== dv.tok) return;
  if (dv.p >= DH_LAST) { dv.playing = false; renderDh(); return; }
  dv.p++;
  renderDh();
  later(function () { dLoop(t); }, reduced.matches ? 60 : ms(2200));
}
function dhListenerMix() {
  dv.tryTok++;
  var v = dhVals(), x = D.dh.mul[v.A][v.B], el = $("dlisten");
  el.className = "gverdict good";
  el.textContent = x === v.s1
    ? "The listener multiplies " + v.A + " by " + v.B + ", mod " + v.n + ", and gets " + x + ". This pair of private numbers happens to match the secret, because here a + b equals a times b, mod " + (v.n - 1) + ". Almost every other pair misses."
    : "The listener multiplies " + v.A + " by " + v.B + ", mod " + v.n + ", and gets " + x + ". The secret is " + v.s1 + ". Multiplying adds the two private numbers, and the secret needs them multiplied.";
}
function dhListenerTry() {
  var t = ++dv.tryTok, v = dhVals(), el = $("dlisten"), k = 0;
  el.className = "gverdict";
  function step() {
    if (t !== dv.tryTok) return;
    k++;
    var got = dhPow(v.g, k);
    if (got === v.A) {
      el.className = "gverdict bad";
      el.textContent = "Found it on try " + k + ": " + v.g + " to the power " + k + " gives " + v.A + ". So the private number is " + k + ", and " + v.B + " to the power " + k + ", mod " + v.n + ", gives the secret, " + dhPow(v.B, k) + ". With a small n, trying each number works.";
      return;
    }
    el.textContent = "Try " + k + ": " + v.g + " to the power " + k + " gives " + got + ". The client's public number is " + v.A + ".";
    later(step, reduced.matches ? 30 : ms(320));
  }
  step();
}
function renderMiddle() {
  var v = dhVals(), M = D.dh.mitm, mp = dhPow(v.g, M);
  $("dmid").innerHTML =
    '<div class="dhgrid"><div class="dhside"><h3>Client</h3>' + dhNum("Thinks this is the server", mp) + dhNum("Secret", dhPow(mp, dv.a), "dhsecret") + "</div>" +
    '<div class="dhside dhattack"><h3>In the middle</h3>' + dhNum("Private number", M, "dhkey") + dhNum("Secret with the client", dhPow(v.A, M), "dhsecret") + dhNum("Secret with the server", dhPow(v.B, M), "dhsecret") + "</div>" +
    '<div class="dhside"><h3>Server</h3>' + dhNum("Thinks this is the client", mp) + dhNum("Secret", dhPow(mp, dv.b), "dhsecret") + "</div></div>" +
    '<p class="gverdict bad">Each side holds a working secret, and each one is shared with the attacker. Diffie-Hellman gives you a secret. It does not tell you who holds the other copy. So in a TLS 1.3 certificate handshake, the server signs a hash of the handshake so far, which holds both public numbers, and the client checks that key&#39;s certificate (<button class="spec" data-spec="rfc8446">RFC 8446</button>, section 4.4.3). Lessons 4 and 5 cover that.</p>';
  $("dmid").hidden = false;
  if (typeof wireSpecs === "function") wireSpecs($("dmid"));
}
function setupDh() {
  ["da", "db"].forEach(function (id) {
    var sel = $(id), html = "";
    for (var i = 2; i < D.dh.n - 1; i++) html += '<option value="' + i + '">' + i + "</option>";
    sel.innerHTML = html;
    sel.value = id === "da" ? dv.a : dv.b;
    sel.onchange = function () {
      dStop(); dv.tryTok++;
      dv.a = parseInt($("da").value, 10); dv.b = parseInt($("db").value, 10); dv.p = null;
      $("dlisten").textContent = ""; $("dlisten").className = "gverdict"; $("dmid").hidden = true;
      renderDh();
    };
  });
  $("dplay").onclick = function () {
    if (isPaused("dh")) { clockResume(); renderDh(); return; }
    if (dv.playing) { clockPause("dh"); renderDh(); return; }
    clockResume();
    if (dv.p === null || dv.p >= DH_LAST) dv.p = 0;
    dv.playing = true;
    var t = ++dv.tok;
    renderDh();
    later(function () { dLoop(t); }, reduced.matches ? 60 : ms(1800));
  };
  $("dnext").onclick = function () { dStop(); if (dv.p === null || dv.p >= DH_LAST) dv.p = 0; else dv.p++; renderDh(); };
  $("dall").onclick = function () { dStop(); dv.p = null; renderDh(); };
  $("dmix").onclick = dhListenerMix;
  $("dtry").onclick = dhListenerTry;
  $("dmidbtn").onclick = renderMiddle;
  var X = D.dh.x25519;
  $("dreal").innerHTML =
    '<div class="seal-row"><span>Client private</span> ' + fchips(X.a, "fkey") + "</div>" +
    '<div class="seal-row"><span>Client public</span> ' + fchips(X.A) + "</div>" +
    '<div class="seal-row"><span>Server private</span> ' + fchips(X.b, "fkey") + "</div>" +
    '<div class="seal-row"><span>Server public</span> ' + fchips(X.B) + "</div>" +
    '<div class="seal-row"><span>Secret, both sides</span> ' + fchips(X.s, "tagbyte") + "</div>" +
    '<div class="seal-row"><span>AES-128 key, by HKDF</span> ' + fchips(X.key, "pick") + "</div>";
  renderDh();
}

