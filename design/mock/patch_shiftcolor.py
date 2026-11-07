"""Colors only the wrapping bytes in the ShiftRows roll, and keeps the pattern on the end frame."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap("""  row.concat(row).forEach(function (el) {
    var copy = el.cloneNode(true);
    copy.classList.add("hot");
""", """  row.concat(row).forEach(function (el, n) {
    var copy = el.cloneNode(true);
    copy.classList.toggle("hot", n % 4 < r);
""")
swap("""      el.querySelector(".mark").textContent = r + 4 * ((c + r) % 4);
      el.classList.add("hot");
""", """      el.querySelector(".mark").textContent = r + 4 * ((c + r) % 4);
      el.classList.toggle("hot", c + r >= 4);
""")
swap("""el.querySelector(".mark").textContent = r + 4 * ((c + r) % 4); });
  }""", """el.querySelector(".mark").textContent = r + 4 * ((c + r) % 4); el.classList.toggle("hot", c + r >= 4); });
  }""")
swap("""SAYS = {""", """SAYS = {""") if False else None
path.write_text(text, encoding="utf-8")
print("patched")
