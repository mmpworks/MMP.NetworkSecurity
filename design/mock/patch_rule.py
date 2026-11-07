"""Shows the key schedule's rule test on every word."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('<h2 id="ktitle"></h2>', '<h2 id="ktitle"></h2>\n        <p class="ktest" id="ktest"></p>')
swap(".build .s1 { background: var(--accent-soft); }",
     """.ktest { font: 600 15px/1.45 var(--mono); max-width: none; padding: 8px 10px; border-radius: 7px; background: var(--sunk); }
.build .s1 { background: var(--accent-soft); }""")
swap('''  $("ktitle").textContent = title;
  renderRcon();''', '''  $("ktitle").textContent = title;
  $("ktest").textContent = ruleLine(chosen === null ? built : chosen);
  renderRcon();''')
swap('''function renderBuild(fill) {''', '''/* The test that decides what a word does. It reads the word number and Nk, and never the round. */
function ruleLine(i) {
  var nk = S().nk, words = S().words;
  if (i >= words.length) return "All " + words.length + " words are built.";
  if (i < nk) return "w" + i + " is part of the key, so nothing is calculated.";
  var left = i % nk, times = Math.floor(i / nk);
  if (left === 0) return i + " ÷ " + nk + " = " + times + ", no remainder, so w" + i + " rotates. It is rotation " + times + ", so it takes round constant " + times + ": " + hex(words[i].rcon) + ".";
  if (nk > 6 && left === 4) return i + " ÷ " + nk + " leaves 4, so w" + i + " gets the S-box step only. AES-256 adds this rule.";
  return i + " ÷ " + nk + " leaves " + left + ", so w" + i + " is plain: no rotation.";
}
function renderBuild(fill) {''')
path.write_text(text, encoding="utf-8")
print("patched")
