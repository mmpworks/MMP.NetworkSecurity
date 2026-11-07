"""Adds the overflow breakaway to the MixColumns matrix view."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''      <div class="mrun scroll" id="mrun"></div>''',
     '''      <div class="mbits scroll" id="mbits"></div>
      <div class="mrun scroll" id="mrun"></div>''')
swap(""".mrun { font: 15px/1.6 var(--mono); white-space: nowrap; }""",
     """.mrun { font: 15px/1.6 var(--mono); white-space: nowrap; }
.mbits { display: grid; gap: 2px; font: 15px/1.5 var(--mono); min-height: 0; }
.mbits .brow { display: grid; grid-template-columns: minmax(170px, 230px) auto; gap: 12px; white-space: pre; }
.mbits .brow b { font-weight: 400; color: var(--muted); }
.mbits .ovf { color: var(--key); font-weight: 700; }
.mbits .ans { color: var(--flash); font-weight: 600; }
.ovfly { position: fixed; z-index: 35; pointer-events: none; font: 700 22px var(--mono); color: var(--key); }""")
swap('''  var dbl = "Field multiply by 2: shift left to get " + d.shifted.toString(16) + ". " +
    (d.reduced ? "That is too big for a byte, so XOR 11b. It gives " + hex(d.to) + "." : "It fits in a byte, so it stays " + hex(d.to) + ".");''',
     '''  var dbl = "Field multiply by 2: shift left to get " + d.shifted.toString(16) + ". " +
    (d.reduced ? "The top bit does not fit in a byte, so it breaks away. Reducing by 11b removes that bit and XORs 1b into the rest. It gives " + hex(d.to) + "." : "It fits in a byte, so it stays " + hex(d.to) + ".");''')
swap('''  $("mback").disabled = col === 0 && mv.pos === 0 && !mv.all;''',
     '''  renderBits(mv.all || k > 3 ? null : row.parts[k]);
  $("mback").disabled = col === 0 && mv.pos === 0 && !mv.all;''')
swap('''  mv.pos = next;
  renderMix(moved);''', '''  mv.pos = next;
  mvForward = d > 0;
  renderMix(moved);
  mvForward = false;''')
swap('''    var wait = mv.pos % 5 === 4 ? ms(1100) : ms(1500);''',
     '''    var wait = mv.pos % 5 === 4 ? ms(1100) : termWait(steps()[cur].terms[mv.col][Math.floor(mv.pos / 5)].parts[mv.pos % 5]);''')
swap('''function renderMix(flyColumn) {''', '''/* The bit work behind one multiply. A set bit 8 breaks away and leaves the screen, then 1b goes in. */
var mvForward = false, bitToken = 0;
function bits8(b) { var s = bin(b); return s.slice(0, 4) + " " + s.slice(4); }
function brow(label, val, cls) { return '<div class="brow ' + (cls || "") + '"><b>' + label + "</b><span>" + val + "</span></div>"; }
function termWait(p) {
  if (p.factor === 1) return ms(1400);
  return ms(p.doublings[0].reduced ? 3400 : 2000) + (p.factor === 3 ? ms(1000) : 0);
}
function renderBits(p) {
  var host = $("mbits"), t = ++bitToken;
  Array.prototype.forEach.call(document.querySelectorAll(".ovfly"), function (x) { x.remove(); });
  if (!p || p.factor === 1) { host.innerHTML = ""; return; }
  var d = p.doublings[0], low = d.shifted & 255;
  var h = brow(hex(d.from), "  " + bits8(d.from));
  if (d.reduced) {
    h += brow("Shift left", '<span class="ovf" id="ovfbit">1</span> ' + bits8(low));
    h += brow("The top bit breaks away", "  " + bits8(low));
    h += brow("XOR 1b, the rest of 11b", "  " + bits8(27));
  } else {
    h += brow("Shift left, no overflow", "  " + bits8(low));
  }
  h += brow("2 × " + hex(d.from) + " = " + hex(d.to), '  <span class="ans">' + bits8(d.to) + "</span>");
  if (p.factor === 3) {
    h += brow("XOR the byte, " + hex(p.byte), "  " + bits8(p.byte));
    h += brow("3 × " + hex(p.byte) + " = " + hex(p.result), '  <span class="ans">' + bits8(p.result) + "</span>");
  }
  host.innerHTML = h;
  if (reduced.matches || !mvForward) return;
  var rows = host.children, at = [0, ms(500)], next = ms(500);
  if (d.reduced) { at.push(ms(1800)); at.push(ms(2300)); next = ms(2300); }
  for (var i = at.length; i < rows.length; i++) { next += ms(520); at.push(next); }
  Array.prototype.forEach.call(rows, function (el, i) {
    el.animate([{ opacity: 0, transform: "translateX(-10px)" }, { opacity: 1, transform: "none" }], { duration: ms(300), delay: at[i], easing: "ease-out", fill: "backwards" });
  });
  if (!d.reduced) return;
  setTimeout(function () {
    if (t !== bitToken) return;
    var bit = $("ovfbit");
    if (!bit) return;
    var r = bit.getBoundingClientRect(), fly = document.createElement("div");
    fly.className = "ovfly"; fly.textContent = "1";
    fly.style.left = r.left + "px"; fly.style.top = (r.top - 6) + "px";
    document.body.appendChild(fly);
    bit.style.visibility = "hidden";
    var out = fly.animate([
      { transform: "none", offset: 0 },
      { transform: "translate(40px,-34px) scale(1.5)", offset: 0.25 },
      { transform: "translate(" + (innerWidth - r.left + 60) + "px,-120px) scale(1.2)", offset: 1 }
    ], { duration: ms(900), easing: "ease-in", fill: "both" });
    out.finished.catch(function () {}).then(function () { fly.remove(); });
  }, ms(850));
}
function renderMix(flyColumn) {''')
path.write_text(text, encoding="utf-8")
print("patched")
