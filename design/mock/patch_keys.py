"""Splices the byte-by-byte key animation into the mock template."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")

start = text.index("function renderKeys() {")
end_marker = '$("kreset").onclick = function () { kstop(); built = S().nk; chosen = null; renderKeys(); renderBuild(); };\n'
end = text.index(end_marker) + len(end_marker)
text = text[:start] + (HERE / "keys_anim.js").read_text(encoding="utf-8") + text[end:]


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''parts.push("<span><small>w" + i + "</small>" + wordHex(s.words[i].word) + "</span>");''',
     '''parts.push("<span><small>w" + i + "</small>" + s.words[i].word.map(function (b, j) { return '<span class="kb" data-stage="key' + i + '" data-j="' + j + '">' + hex(b) + "</span>"; }).join("") + "</span>");''')
swap('<div class="build" id="build" aria-live="polite"></div>',
     '<div class="build" id="build"></div>\n        <div class="keq" id="keq" aria-live="polite" hidden></div>')
swap('var TIP_TARGETS = ".cell, .kcell, code, .sbox td, .keystr span";',
     'var TIP_TARGETS = ".kb, .cell, .kcell, code, .sbox td";')
swap(".build .s1 { background: var(--accent-soft); }",
     """.kb { padding: 0 2px; border-radius: 3px; display: inline-block; }
.kb.empty { color: var(--muted); }
.kb.pick { background: var(--fg); color: var(--bg); }
.kcell.pick { outline: 3px solid var(--fg); outline-offset: 1px; z-index: 2; }
.keq { background: var(--sunk); border-radius: 8px; padding: 10px 12px; font: 13px/1.6 var(--mono); white-space: pre; overflow-x: auto; }
.keq .keqtop { font: 600 22px/1.4 var(--mono); }
.keq .k { color: var(--key); }
.keq .r { color: var(--flash); }
.kflyer { position: fixed; z-index: 30; pointer-events: none; font: 600 22px var(--mono); color: var(--flash); }
.build .s1 { background: var(--accent-soft); }""")
path.write_text(text, encoding="utf-8")
print("patched")
