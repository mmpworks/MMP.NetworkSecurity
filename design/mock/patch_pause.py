"""Adds a real pause and resume to every animation in the mock."""
import pathlib

path = pathlib.Path(__file__).parent / "template.html"
text = path.read_text(encoding="utf-8")


def swap(old, new):
    global text
    assert text.count(old) == 1, old
    text = text.replace(old, new)


# One clock: timers and running animations freeze together.
swap("""function wait(n) { return new Promise(function (ok) { setTimeout(ok, n); }); }""",
     """/* The clock. Pause freezes every timer and every running animation where they are. Resume carries on from there. */
var clock = { paused: false, owner: null, timers: [], frozen: [] };
function later(fn, delay) {
  var job = { fn: fn, left: delay, since: Date.now(), id: null };
  job.id = setTimeout(function () { clockDrop(job); fn(); }, delay);
  clock.timers.push(job);
  if (clock.paused) freezeJob(job);
  return job;
}
function clockDrop(job) { clock.timers = clock.timers.filter(function (x) { return x !== job; }); }
function freezeJob(job) { clearTimeout(job.id); job.left = Math.max(0, job.left - (Date.now() - job.since)); job.id = null; }
function clockPause(owner) {
  if (clock.paused) return;
  clock.paused = true; clock.owner = owner;
  clock.timers.forEach(freezeJob);
  clock.frozen = document.getAnimations().filter(function (a) { return a.playState === "running"; });
  clock.frozen.forEach(function (a) { a.pause(); });
}
function clockResume() {
  if (!clock.paused) return;
  clock.paused = false; clock.owner = null;
  clock.frozen.forEach(function (a) { if (a.playState === "paused") a.play(); });
  clock.frozen = [];
  clock.timers.forEach(function (job) {
    job.since = Date.now();
    job.id = setTimeout(function () { clockDrop(job); job.fn(); }, job.left);
  });
}
function isPaused(owner) { return clock.paused && clock.owner === owner; }
function wait(n) { return new Promise(function (ok) { later(ok, n); }); }""")

# Block view.
swap("""function stop() { playing = false; token++; clearRunning(); }""",
     """function stop() { clockResume(); playing = false; token++; clearRunning(); }""")
swap("""  if (playing) { playing = false; $("play").textContent = "Play this round"; return; }
  playing = true;""",
     """  if (isPaused("block")) { clockResume(); blockLabel(); return; }
  if (playing || window.settled === false) { clockResume(); clockPause("block"); blockLabel(); return; }
  clockResume();
  playing = true;""")
swap("""advance().then(function (ok) { if (ok) setTimeout(loop, ms(260)); else { playing = false; } });""",
     """advance().then(function (ok) { if (ok) later(loop, ms(260)); else { playing = false; blockLabel(); } });""")
swap("""$("next").onclick = function () { playing = false; advance(); };""",
     """$("next").onclick = function () { clockResume(); playing = false; advance(); };""")
swap("""  $("play").textContent = playing ? "Pause" : "Play this round";
  mixSync();""", """  blockLabel();
  mixSync();""")
swap("""function firstOfRound(n) {""",
     """function blockLabel() {
  $("play").textContent = isPaused("block") ? "Resume" : (playing || window.settled === false) ? "Pause" : "Play this round";
}
function firstOfRound(n) {""")
swap("""    clearRunning(); render(); window.settled = true;""",
     """    window.settled = true; clearRunning(); render();""")
swap("""  if (reduced.matches) { cur++; render(); return Promise.resolve(true); }""",
     """  if (reduced.matches) { cur++; window.settled = true; render(); return Promise.resolve(true); }""")

# Key schedule.
start = text.index("function kstop() {")
end_marker = "$(\"kplay\").onclick = kplay;"
end = text.index(end_marker)
text = text[:start] + """function kstop() { clockResume(); kplaying = false; ktoken++; filling = null; clearPicks(); $("keq").hidden = true; }
function keyLabel() {
  $("kplay").textContent = isPaused("key") ? "Resume" : (kplaying || filling) ? "Pause" : "Play";
}
function kplay() {
  if (isPaused("key")) { clockResume(); keyLabel(); return; }
  if (kplaying || filling) { clockResume(); clockPause("key"); keyLabel(); return; }
  clockResume();
  kplaying = true;
  if (built >= S().words.length) { built = S().nk; chosen = null; }
  (function loop() {
    if (!kplaying) return;
    if (built >= S().words.length) { kplaying = false; renderKeys(); return; }
    renderKeys();
    knext().then(function () { if (kplaying) later(loop, ms(260)); else renderKeys(); });
  })();
  renderKeys();
}
""" + text[end:]
swap("""  $("kplay").textContent = kplaying ? "Pause" : "Play";
}
function chips(""", """  keyLabel();
}
function chips(""")

# MixColumns view.
swap("""function mstop() { mplaying = false; clearTimeout(mtimer); if ($("mplay")) $("mplay").textContent = "Play this column"; }""",
     """function mixLabel() { $("mplay").textContent = isPaused("mix") ? "Resume" : mplaying ? "Pause" : "Play this column"; }
function mstop() { clockResume(); mplaying = false; mixToken++; if ($("mplay")) mixLabel(); }""")
swap("""var mplaying = false, mtimer = null;""", """var mplaying = false, mixToken = 0;""")
swap("""  if (mplaying) { mstop(); return; }
  if (mv.all) {""", """  if (isPaused("mix")) { clockResume(); mixLabel(); return; }
  if (mplaying) { clockPause("mix"); mixLabel(); return; }
  clockResume();
  if (mv.all) {""")
swap("""  mplaying = true;
  $("mplay").textContent = "Pause";
  (function loop() {""", """  mplaying = true;
  var t = ++mixToken;
  mixLabel();
  (function loop() {""")
swap("""    mtimer = setTimeout(function () { if (!mplaying) return; mixStep(1); loop(); }, reduced.matches ? 500 : wait);""",
     """    later(function () { if (!mplaying || t !== mixToken) return; mixStep(1); loop(); }, reduced.matches ? 500 : wait);""")
swap("""  setTimeout(function () {
    if (t !== bitToken) return;
    var bit = $("ovfbit");""", """  later(function () {
    if (t !== bitToken) return;
    var bit = $("ovfbit");""")
path.write_text(text, encoding="utf-8")
print("patched")
