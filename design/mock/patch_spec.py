"""Adds the spec hover card to the mock template."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('checked against FIPS 197, using its test keys.',
     'checked against <button class="spec" data-spec="fips197">FIPS 197</button>, using its test keys.')
swap('<button id="run-fips" aria-pressed="false">FIPS 197 example</button>',
     '<button id="run-fips" aria-pressed="false"><span class="specmark" data-spec="fips197">FIPS 197</span> example</button>')
swap('$("says").textContent = SAYS[s.kind][1];',
     '$("says").innerHTML = SAYS[s.kind][1].replace("FIPS 197", \'<button class="spec" data-spec="fips197">FIPS 197</button>\');')
swap(".build .s1 { background: var(--accent-soft); }",
     """.spec { border: 0; background: none; padding: 0; font: inherit; color: var(--accent); text-decoration: underline dotted; text-underline-offset: 3px; }
.specmark { text-decoration: underline dotted; text-underline-offset: 3px; }
#speccard { position: fixed; z-index: 40; width: min(340px, calc(100vw - 32px)); background: var(--panel); color: var(--fg); border: 1px solid var(--line);
  border-radius: 10px; padding: 12px 14px; display: grid; gap: 6px; box-shadow: 0 6px 22px rgba(0,0,0,.28); font: 14px/1.45 var(--body); }
#speccard b { font: 700 15px var(--display); }
#speccard a { color: var(--accent); }
.build .s1 { background: var(--accent-soft); }""")
swap("setupLong(); buildKeyTable();",
     """/* Every named spec gets a hover card: what it is, and a link. The card stays open while the pointer is on it, so the link can be clicked. */
var SPECS = {
  fips197: {
    name: "FIPS 197",
    title: "Advanced Encryption Standard (AES)",
    says: "The US government standard that defines AES. NIST published it in 2001 and updated it in 2023. It sets the block steps, the key schedule for 128, 192 and 256-bit keys, and test values anyone can check against.",
    link: "https://csrc.nist.gov/pubs/fips/197/final",
    linkText: "Read FIPS 197 at NIST"
  }
};
var card = document.createElement("div");
card.id = "speccard"; card.hidden = true; card.setAttribute("role", "tooltip");
document.body.appendChild(card);
var cardTimer = null, cardOwner = null;
function keepCard() { clearTimeout(cardTimer); }
function hideCardSoon() { clearTimeout(cardTimer); cardTimer = setTimeout(function () { card.hidden = true; cardOwner = null; }, 260); }
function showCard(el) {
  var s = SPECS[el.dataset.spec];
  if (!s) return;
  keepCard();
  tip.hidden = true;
  cardOwner = el;
  card.innerHTML = "<b></b><span></span><span></span><a target=\\"_blank\\" rel=\\"noopener\\"></a>";
  card.children[0].textContent = s.name;
  card.children[1].textContent = s.title;
  card.children[2].textContent = s.says;
  card.children[3].textContent = s.linkText;
  card.children[3].href = s.link;
  card.hidden = false;
  var r = el.getBoundingClientRect(), w = card.offsetWidth, h = card.offsetHeight;
  card.style.left = Math.max(8, Math.min(innerWidth - w - 8, r.left)) + "px";
  card.style.top = (r.bottom + h + 8 < innerHeight ? r.bottom + 6 : Math.max(8, r.top - h - 6)) + "px";
}
document.addEventListener("mouseover", function (e) {
  if (!e.target.closest) return;
  var el = e.target.closest("[data-spec]");
  if (el) showCard(el);
  else if (e.target.closest("#speccard")) keepCard();
  else if (cardOwner) hideCardSoon();
});
document.addEventListener("focusin", function (e) {
  if (!e.target.closest) return;
  var el = e.target.closest("[data-spec]");
  if (el) showCard(el);
  else if (e.target.closest("#speccard")) keepCard();
});
document.addEventListener("click", function (e) {
  if (!e.target.closest) return;
  var el = e.target.closest(".spec");
  if (el) { showCard(el); return; }
  if (!e.target.closest("#speccard")) { card.hidden = true; cardOwner = null; }
});
document.addEventListener("keydown", function (e) { if (e.key === "Escape") { card.hidden = true; cardOwner = null; } });

setupLong(); buildKeyTable();""")
path.write_text(text, encoding="utf-8")
print("patched")
