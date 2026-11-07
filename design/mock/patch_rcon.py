"""Animates the round constant doubling and lights the value in use."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''<p class="mono" id="rconrow"></p>''',
     '''<div class="rconrow" id="rconrow"></div>
      <div class="controls">
        <button class="btn primary" id="rplay">Play the doubling</button>
        <button class="btn" id="rnext">Next</button>
        <button class="btn" id="rreset">Show all</button>
      </div>
      <p class="note" id="rnote"></p>
      <div class="mbits scroll" id="rbits"></div>''')
swap('''<p class="note kwhy" id="kwhy" hidden></p>''',
     '''<div class="rconmini"><h3>Round constants</h3><div class="rconrow" id="rconmini"></div></div>
        <p class="note kwhy" id="kwhy" hidden></p>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.rconrow { display: flex; flex-wrap: wrap; gap: 6px; font: 600 15px var(--mono); }
.rconrow .kb { padding: 3px 7px; background: var(--sunk); border-radius: 5px; }
.rconrow .kb.unused { opacity: .35; text-decoration: line-through; }
.rconrow .kb.pick { background: var(--fg); color: var(--bg); }
.rconmini { display: grid; gap: 4px; }
.build .s1 { background: var(--accent-soft); }""")
swap('''$("rconrow").textContent = D.rcon.map(hex).join("  ");''', '''/* Round constants: each value is the one before it, doubled in the field. */
var rpos = null, rplaying = false, rtok = 0;
function rconUsed() { return S().words.filter(function (w) { return w.rotated; }).length; }
function rconLit() {
  if (rpos !== null) return rpos;
  var w = chosen === null ? null : S().words[chosen];
  return w && w.rotated ? chosen / S().nk - 1 : -1;
}
function renderRcon() {
  var used = rconUsed(), lit = rconLit();
  ["rconrow", "rconmini"].forEach(function (id) {
    $(id).innerHTML = D.rcon.map(function (b, i) {
      var hidden = rpos !== null && i > rpos;
      var cls = "kb" + (i >= used ? " unused" : "") + (i === lit ? " pick" : "") + (hidden ? " empty" : "");
      return '<span class="' + cls + '">' + (hidden ? "--" : hex(b)) + "</span>";
    }).join("");
  });
  $("rplay").textContent = isPaused("rcon") ? "Resume" : rplaying ? "Pause" : "Play the doubling";
  var note = "AES-" + size + " uses " + used + " of these 10.";
  if (rpos === null) $("rnote").textContent = note + " Press Play to build the list from 01.";
  else if (rpos === 0) $("rnote").textContent = note + " The list starts at 01. No key goes in, so every AES key uses this same list.";
  else $("rnote").textContent = note + " Value " + (rpos + 1) + " is " + hex(D.rcon[rpos]) + ".";
}
function rstop() { clockResume(); rplaying = false; rtok++; }
function rreset() { rstop(); rpos = null; renderBits(null, $("rbits")); renderRcon(); }
/* One doubling: show the bit rows at once, and reveal the new value when they finish. */
function rstep() {
  var used = rconUsed(), t = ++rtok;
  if (rpos === null) { rpos = 0; renderBits(null, $("rbits")); renderRcon(); return ms(1200); }
  if (rpos >= used - 1) { rplaying = false; renderRcon(); return 0; }
  var d = D.rconSteps[rpos];
  var p = { factor: 2, byte: d.from, result: d.to, doublings: [d] };
  mvForward = true;
  renderBits(p, $("rbits"));
  mvForward = false;
  var hold = reduced.matches ? 0 : termWait(p) - ms(500);
  var finish = function () { if (t !== rtok && !rplaying) return; rpos++; renderRcon(); };
  if (hold > 0) later(finish, hold); else finish();
  return reduced.matches ? 400 : termWait(p);
}
function rloop() {
  if (!rplaying) return;
  var wait = rstep();
  if (!rplaying) return;
  later(rloop, wait + ms(120));
}
$("rplay").onclick = function () {
  if (isPaused("rcon")) { clockResume(); renderRcon(); return; }
  if (rplaying) { clockPause("rcon"); renderRcon(); return; }
  clockResume();
  if (rpos !== null && rpos >= rconUsed() - 1) rpos = null;
  rplaying = true;
  renderRcon();
  rloop();
};
$("rnext").onclick = function () { rstop(); renderRcon(); rstep(); };
$("rreset").onclick = rreset;''')
swap('''function renderBits(p) {
  var host = $("mbits"), t = ++bitToken;''', '''function renderBits(p, where) {
  var host = where || $("mbits"), t = ++bitToken;''')
swap('''    var bit = $("ovfbit");
    if (!bit) return;''', '''    var bit = host.querySelector(".ovf");
    if (!bit) return;''')
swap('''  $("ktitle").textContent = title;
  var b = $("build"); b.innerHTML = h;''', '''  $("ktitle").textContent = title;
  renderRcon();
  var b = $("build"); b.innerHTML = h;''')
swap('''  $("keystr").innerHTML = parts.join("");
}''', '''  $("keystr").innerHTML = parts.join("");
  rreset();
}''')
path.write_text(text, encoding="utf-8")

build = HERE / "build_mock.py"
source = build.read_text(encoding="utf-8")
old = '''data = {
    "long": LONG,'''
assert source.count(old) == 1
source = source.replace(old, '''RCON_STEPS = []
for value in RCON[:-1]:
    shifted = value << 1
    reduced_bit = bool(shifted & 0x100)
    RCON_STEPS.append({"from": value, "shifted": shifted, "reduced": reduced_bit, "to": xtime(value)})
assert [s["to"] for s in RCON_STEPS] == RCON[1:]

data = {
    "long": LONG,
    "rconSteps": RCON_STEPS,''')
build.write_text(source, encoding="utf-8")
print("patched")
