"""Makes every AddRoundKey set its grid first, hold, slide, and change bytes one at a time."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")
start = text.index("function animArk(s, t) {")
end = text.index("function advance() {")
new = '''function animArk(s, t) {
  var slot = $("slotgrid");
  /* Round 0 already shows its key on the Start view. Later rounds fill the key grid in first, column by column. */
  var entering = s.round === 0 ? Promise.resolve() : Promise.all(slots.map(function (el, i) {
    return anim(el, [{ opacity: 0, transform: "scale(.7)" }, { opacity: 1, transform: "none" }], ms(240), Math.floor(i / 4) * ms(150) + (i % 4) * ms(35));
  }));
  return entering.then(function () {
    if (t !== token) return;
    return wait(s.round === 0 ? ms(250) : ms(800));
  }).then(function () {
    if (t !== token) return;
    var a = $("grid").getBoundingClientRect(), b = slot.getBoundingClientRect();
    var move = "translate(" + (a.left - b.left) + "px," + (a.top - b.top) + "px) scale(" + (a.width / b.width) + ")";
    slot.style.position = "relative"; slot.style.zIndex = 2; slot.style.transformOrigin = "top left";
    return anim(slot, [{ transform: "none", opacity: 1 }, { transform: move, opacity: .55 }], ms(650)).then(function () {
      if (t !== token) return;
      return Promise.all(cells.map(function (el, i) {
        return wait(i * ms(70)).then(function () {
          if (t !== token) return;
          setCell(el, s.state[i], i);
          el.classList.add("hot");
          return anim(el, [{ transform: "scale(1.12)" }, { transform: "none" }], ms(200));
        });
      }));
    }).then(function () {
      if (t !== token) return;
      return wait(ms(350));
    }).then(function () {
      if (t !== token) return;
      return anim(slot, [{ transform: move, opacity: .55 }, { transform: "none", opacity: 1 }], ms(500));
    }).then(function () { slot.style.zIndex = ""; });
  });
}
'''
text = text[:start] + new + text[end:]
path.write_text(text, encoding="utf-8")
print("patched")
