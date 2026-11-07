"""Adds the MixColumns matrix view to the mock template."""
import pathlib

HERE = pathlib.Path(__file__).parent
path = HERE / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


swap('''    <div class="card" style="grid-column: 1 / -1">
      <h2>Where did this byte come from?</h2>''', '''    <div class="card" id="mixcard" style="grid-column: 1 / -1" hidden>
      <h2>How MixColumns multiplies</h2>
      <p class="sub">Each output byte comes from one row of the fixed matrix and one column of the state. Pair them up, multiply each pair in the field, and add the results with XOR.</p>
      <div class="controls">
        <span class="seg" id="mcols" aria-label="Column"></span>
        <button class="btn" id="mback">Back</button>
        <button class="btn primary" id="mplay">Play this column</button>
        <button class="btn" id="mnext">Next</button>
        <button class="btn" id="mfill">Fill all</button>
      </div>
      <div class="mbench">
        <div class="mblock">
          <h3>The fixed matrix</h3>
          <div class="mmatwrap" id="mmatwrap">
            <div class="mstrip" id="mstrip"></div>
            <div class="mbracket"><div class="mgrid" id="mmat"></div></div>
            <div class="mboxline" id="mbox" hidden></div>
          </div>
        </div>
        <div class="mop">×</div>
        <div class="mblock">
          <h3>State before</h3>
          <div class="mspacer"></div>
          <div class="mbracket"><div class="mgrid" id="mstate"></div></div>
        </div>
        <div class="mop">=</div>
        <div class="mblock">
          <h3>State after</h3>
          <div class="mspacer"></div>
          <div class="mbracket"><div class="mgrid" id="mres"></div></div>
        </div>
      </div>
      <div class="mcap" id="mcap" aria-live="polite"></div>
      <div class="mrun scroll" id="mrun"></div>
    </div>
    <div class="card" style="grid-column: 1 / -1">
      <h2>Where did this byte come from?</h2>''')
swap(".build .s1 { background: var(--accent-soft); }",
     """.mbench { display: flex; flex-wrap: wrap; gap: 14px 18px; align-items: flex-end; }
.mblock { display: grid; gap: 6px; min-width: 0; }
.mop { font: 600 26px var(--mono); padding-bottom: 72px; color: var(--muted); }
.mmatwrap { position: relative; display: grid; gap: 8px; }
.mstrip, .mspacer { min-height: 46px; }
.mstrip { display: grid; grid-template-columns: repeat(4, 46px); gap: 4px; padding: 0 10px; }
.mbracket { position: relative; padding: 4px 10px; border-left: 2px solid var(--fg); border-right: 2px solid var(--fg); border-radius: 8px; }
.mgrid { display: grid; grid-template-columns: repeat(4, 46px); gap: 4px; }
.mcell { height: 46px; display: grid; place-items: center; border-radius: 6px; border: 1px solid transparent; font: 600 16px var(--mono); }
.mcell.mfactor { background: var(--sunk); }
.mcell.mhex { background: var(--sunk); }
.mcell.mchip { background: var(--accent-soft); border-color: var(--accent); }
.mcell.mrow { background: var(--accent-soft); }
.mcell.mcolhot { background: var(--accent-soft); }
.mcell.mpairsrc { border-color: var(--key); }
.mcell.mpair { background: var(--key-soft); border-color: var(--key); }
.mcell.mempty { background: transparent; border: 1px dashed var(--line); }
.mcell.mnew { background: var(--flash-soft); border-color: var(--flash); }
.mboxline { position: absolute; border: 2px solid var(--key); border-radius: 8px; pointer-events: none; transition: left .3s ease, top .3s ease, height .3s ease; }
.mcap { display: grid; gap: 4px; min-height: 76px; }
.mcap b { font: 600 22px var(--mono); }
.mcap span { max-width: 70ch; color: var(--muted); }
.mrun { font: 15px/1.6 var(--mono); white-space: nowrap; }
@media (prefers-reduced-motion: reduce) { .mboxline { transition: none; } }
@media (max-width: 480px) { .mop { padding: 0; width: 100%; } .mgrid, .mstrip { grid-template-columns: repeat(4, 38px); } .mcell { height: 38px; font-size: 14px; } .mstrip, .mspacer { min-height: 38px; } }
.build .s1 { background: var(--accent-soft); }""")
swap('''  $("play").textContent = playing ? "Pause" : "Play this round";
}''', '''  $("play").textContent = playing ? "Pause" : "Play this round";
  mixSync();
}''')
swap("/* Every named spec gets a hover card", (HERE / "mix_view.js").read_text(encoding="utf-8") + "/* Every named spec gets a hover card")
swap('var TIP_TARGETS = ".kb, .cell, .kcell, code, .sbox td";', 'var TIP_TARGETS = ".kb, .cell, .kcell, .mhex, code, .sbox td";')
path.write_text(text, encoding="utf-8")
print("patched")
