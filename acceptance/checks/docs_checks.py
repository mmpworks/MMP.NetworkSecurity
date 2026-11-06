"""Text clauses of the acceptance suite: A3 tour statement, A12 tour statement, A14 static, A15, A15a, A16 wording, A17 wording and copy.

Reads app/src/tours/lesson-NN.json (ux-design.md section 3.1), app/src/glossary.json and the app source from a product repo root.
Prints one "@@CLAUSE {json}" line per clause, the same protocol the C# groups use. Uses the standard library only.
The reading grade is the Flesch-Kincaid grade level computed here. The suite does not use the builders' tools/tour_lint.py.

Run: python -I docs_checks.py --root <repo root> [--ids a,b] [--tic-gate <path>] [--max-grade 8.9] [--max-concept 0.30]
"""
import argparse
import glob
import hashlib
import json
import os
import re
import subprocess
import sys

TOUR_GLOB = os.path.join("app", "src", "tours", "lesson-*.json")


def tour_files(root):
    # Lesson 0 is the toy lesson. It sits outside the suite and has its own spec under app/e2e/ (lead decision, 2026-11-05).
    out = []
    for f in sorted(glob.glob(os.path.join(root, TOUR_GLOB))):
        m = re.search(r"lesson-(\d+)\.json$", f)
        if m and int(m.group(1)) >= 1:
            out.append(f)
    return out
TERM = re.compile(r"\{\{term:([a-z0-9-]+)\}\}")
LESSONS = range(1, 12)

# Accuracy rules the tours must state (prd.md "Teaching accuracy rules"). Rule 7 and 8 are checked over every tour.
RULES = {
    1: (9, "the gateway sees everything except the PIN block", [r"gateway", r"pin block", r"(?:cannot|can't|can not) (?:open|read)|stays? (?:closed|locked)|never sees|does not see"]),
    2: (7, "the downgrade sentinel helps only a client that speaks TLS 1.3", [r"downgrade|DOWNGRD", r"(?:only|just) (?:a |the )?client", r"1\.3"]),
    3: (7, "TLS 1.1 CBC: explicit IV, MAC then encrypt, padding oracles, RC4, record now decrypt later", [r"explicit iv|BEAST", r"mac.then.encrypt|padding oracle|lucky ?13", r"RC4", r"record now|decrypt (?:it )?later"]),
    4: (5, "the hybrid protects key exchange only; certificates stay classical", [r"hybrid", r"key exchange", r"certificates? (?:stay|are|remain)s? (?:classical|not post.quantum)|classical certificates?"]),
    5: (11, "managed code has no constant-time guarantee", [r"managed code", r"no constant.time guarantee|constant.time guarantee"]),
    6: (10, "a passkey-shaped challenge is not WebAuthn", [r"passkey", r"not webauthn|is not a webauthn|not the real webauthn"]),
}
LABEL = "Built to show the parts. Do not copy."
FORBIDDEN_CLAIMS = [r"\bPCI[- ]DSS compliant\b", r"\bFIPS[- ]validated\b", r"\bcertified secure\b", r"\bguarantees? compliance\b", r"\bcompliant with (?:PCI|FIPS|SOC|HIPAA)\b"]
CE_WORDING = "CF-compiled, run on the desktop CLR, never run on CE"
FORBIDDEN_CE = [r"(?i)\btested on (?:a )?(?:real )?(?:windows )?CE\b", r"(?i)\bverified on (?:a )?(?:real )?(?:windows )?CE\b", r"(?i)\bruns? on (?:a )?real (?:windows )?CE (?:device|board)\b"]


def emit(cid, status, reason="", detail=""):
    print("@@CLAUSE " + json.dumps({"id": cid, "status": status, "reason": reason, "detail": detail[:1500], "ms": 0}), flush=True)


class NotRun(Exception):
    def __init__(self, reason, detail):
        Exception.__init__(self, detail)
        self.reason = reason


class Fail(Exception):
    pass


# ---------------------------------------------------------------- reading level

def syllables(word):
    w = re.sub(r"[^a-z]", "", word.lower())
    if not w:
        return 0
    if len(w) <= 3:
        return 1
    w = re.sub(r"(?:[^laeiouy]es|ed|[^laeiouy]e)$", "", w)
    w = re.sub(r"^y", "", w)
    return max(1, len(re.findall(r"[aeiouy]{1,2}", w)))


def grade(text):
    """Flesch-Kincaid grade level. Returns (grade, words, sentences)."""
    sentences = [s for s in re.split(r"(?<=[.!?])\s+|\n+", text.strip()) if re.search(r"[A-Za-z]", s)]
    words = re.findall(r"[A-Za-z]+(?:'[a-z]+)?", text)
    if not sentences or not words:
        return 0.0, len(words), len(sentences)
    syl = sum(syllables(w) for w in words)
    g = 0.39 * (len(words) / len(sentences)) + 11.8 * (syl / len(words)) - 15.59
    return g, len(words), len(sentences)


def plain(s):
    return TERM.sub(lambda m: m.group(1).replace("-", " "), s)


# ---------------------------------------------------------------- loading

def load_tours(root):
    files = tour_files(root)
    if not files:
        raise NotRun("PRODUCT_MISSING", "no tour files at app/src/tours/lesson-*.json yet")
    tours = {}
    for f in files:
        m = re.search(r"lesson-(\d+)\.json$", f)
        data = json.load(open(f, encoding="utf-8"))
        steps = data if isinstance(data, list) else data.get("steps", [])
        # Design section 11: a tour carries claims [{text, source}] at the top of the file. A step may also carry its own claims.
        top = data.get("claims", []) if isinstance(data, dict) else []
        tours[int(m.group(1))] = {"file": f, "steps": steps, "claims": top}
    return tours


def load_glossary(root):
    p = os.path.join(root, "app", "src", "glossary.json")
    if not os.path.exists(p):
        raise NotRun("PRODUCT_MISSING", "app/src/glossary.json does not exist yet")
    data = json.load(open(p, encoding="utf-8"))
    entries = data if isinstance(data, list) else data.get("terms", data.get("entries", []))
    return {e["id"]: e for e in entries}


def step_texts(step):
    parts = [step.get("title", "")] + list(step.get("text", [])) + list(step.get("textMine", []))     # textMine: the variant shown on a learner's own key
    t = step.get("tryIt")
    if isinstance(t, dict):
        parts.append(t.get("label", ""))
    return [plain(p) for p in parts if p]


def lesson_text(tour):
    return "\n".join("\n".join(step_texts(s)) for s in tour["steps"])


# ---------------------------------------------------------------- clauses

def a14_static(root, max_concept):
    tours = load_tours(root)
    glossary = load_glossary(root)
    problems = []
    seen_ids = set()
    summary = []
    for n, tour in sorted(tours.items()):
        steps = tour["steps"]
        if not steps:
            problems.append("lesson %d: tour file has no steps" % n)
            continue
        concept = 0
        for s in steps:
            sid = s.get("id", "")
            if not re.fullmatch(r"L%d-S\d\d" % n, sid):
                problems.append("lesson %d: step id '%s' is not L%d-Snn" % (n, sid, n))
            if sid in seen_ids:
                problems.append("lesson %d: step id %s used twice" % (n, sid))
            seen_ids.add(sid)
            text = s.get("text", [])
            if not (1 <= len(text) <= 4):
                problems.append("%s: text has %d strings; allowed 1 to 4" % (sid, len(text)))
            bind = s.get("bind") or {}
            kind = bind.get("kind")
            if kind == "event":
                if not bind.get("eventType"):
                    problems.append("%s: bind.kind is event and bind.eventType is empty" % sid)
            elif kind == "concept":
                concept += 1
            else:
                problems.append("%s: bind.kind must be event or concept, got %r" % (sid, kind))
            for term in TERM.findall(" ".join(text)):
                if term not in glossary:
                    problems.append("%s: {{term:%s}} is not in glossary.json" % (sid, term))
            for term in s.get("glossary", []):
                if term not in glossary:
                    problems.append("%s: glossary entry '%s' is not in glossary.json" % (sid, term))
        share = concept / float(len(steps))
        summary.append("L%d %d/%d concept" % (n, concept, len(steps)))
        if share > max_concept + 1e-9:
            problems.append("lesson %d: %d of %d steps are concept steps (%.0f%%); the cap is %.0f%%" % (n, concept, len(steps), share * 100, max_concept * 100))
    if problems:
        raise Fail("; ".join(problems[:6]) + (" ... %d problems" % len(problems) if len(problems) > 6 else ""))
    return "%d lessons: %s" % (len(tours), ", ".join(summary))


def a15_grade(root, max_grade):
    tours = load_tours(root)
    bad, report = [], []
    total_text = []
    for n, tour in sorted(tours.items()):
        text = lesson_text(tour)
        total_text.append(text)
        g, w, s = grade(text)
        report.append("L%d %.1f" % (n, g))
        if g > max_grade:
            worst = sorted(((grade(" ".join(step_texts(st)))[0], st.get("id", "?")) for st in tour["steps"]), reverse=True)[:3]
            bad.append("lesson %d reads at grade %.1f (limit %.1f); hardest steps: %s" % (n, g, max_grade, ", ".join("%s %.1f" % (i, v) for v, i in worst)))
    g_all = grade("\n".join(total_text))[0]
    try:
        glossary = load_glossary(root)
        for tid, e in glossary.items():
            gs = grade(e.get("short", ""))[0]
            words = len(re.findall(r"[A-Za-z]+", e.get("short", "")))
            if gs > max_grade or words > 20:
                bad.append("glossary '%s' short is grade %.1f with %d words (limit %.1f and 20)" % (tid, gs, words, max_grade))
    except NotRun:
        pass
    if g_all > max_grade:
        bad.append("all tour text together reads at grade %.1f" % g_all)
    if bad:
        raise Fail("; ".join(bad[:5]))
    return "grade by lesson: %s; all text %.1f; limit %.1f" % (", ".join(report), g_all, max_grade)


def a15_tic_gate(root, tic_gate):
    if not os.path.exists(tic_gate):
        raise NotRun("TOOL_MISSING", "tic-gate.py not found at " + tic_gate)
    files = tour_files(root)
    gp = os.path.join(root, "app", "src", "glossary.json")
    if os.path.exists(gp):
        files.append(gp)
    if not files:
        raise NotRun("PRODUCT_MISSING", "no tour files yet")
    hits = []
    for f in files:
        r = subprocess.run([sys.executable, tic_gate, f], capture_output=True, text=True)
        if r.returncode != 0:
            hits.append(os.path.basename(f) + ": " + (r.stdout or r.stderr).strip().replace("\n", " | ")[:200])
    if hits:
        raise Fail("tic-gate.py found tics: " + "; ".join(hits[:4]))
    return "tic-gate.py clean on %d files" % len(files)


def a15a_rules(root):
    tours = load_tours(root)
    problems, missing_lessons, ok = [], [], []
    for rule, (lesson, desc, patterns) in RULES.items():
        if lesson not in tours:
            missing_lessons.append("rule %d (lesson %d)" % (rule, lesson))
            continue
        text = lesson_text(tours[lesson])
        absent = [p for p in patterns if not re.search(p, text, re.I)]
        if absent:
            problems.append("rule %d, lesson %d must state '%s'; the tour lacks text matching %s" % (rule, lesson, desc, ", ".join(absent)))
        else:
            ok.append(str(rule))
    for n, tour in tours.items():
        if LABEL.lower() not in lesson_text(tour).lower():
            problems.append("rule 7: lesson %d carries no step with '%s'" % (n, LABEL))
        for pat in FORBIDDEN_CLAIMS:
            m = re.search(pat, lesson_text(tour), re.I)
            if m:
                problems.append("rule 8: lesson %d makes a compliance claim: '%s'" % (n, m.group(0)))
    if problems:
        raise Fail("; ".join(problems[:5]))
    if missing_lessons:
        raise NotRun("LESSON_NOT_BUILT", "rules checked: %s. Not checked because the lesson has no tour yet: %s" % (",".join(ok) or "none", "; ".join(missing_lessons)))
    return "accuracy rules 1 to 8 stated across %d lessons" % len(tours)


def a15a_claims_cite(root):
    tours = load_tours(root)
    problems, claims = [], 0
    for n, tour in sorted(tours.items()):
        found = [("lesson %d" % n, cl) for cl in tour.get("claims", [])]
        for s in tour["steps"]:
            found.extend((s.get("id", "?"), cl) for cl in s.get("claims", []))
        for where, cl in found:
            claims += 1
            if not (isinstance(cl, dict) and cl.get("text") and cl.get("source") and re.search(r"\w", str(cl.get("source")))):
                problems.append("%s: claim '%s' has no text or no source" % (where, str(cl)[:40]))
    if claims == 0:
        raise NotRun("NO_CLAIMS_DECLARED", "no tour declares a 'claims' array [{text, source}]; a security claim with no declared source cannot be checked (CONTRACT.md, tour claims)")
    if problems:
        raise Fail("; ".join(problems[:5]))
    return "%d security claims, each cites a source" % claims


def norm(text):
    return " ".join(str(text).split())


def text_hash(text):
    return hashlib.sha256(norm(text).encode("utf-8")).hexdigest()


def current_claims(tour, n):
    """(id, text) of every claim a tour declares now. A claim without an id gets L<lesson>-C<nn> by order, top claims first."""
    found = list(tour.get("claims", []))
    for st in tour["steps"]:
        found.extend(st.get("claims", []))
    out = []
    for i, cl in enumerate(found, 1):
        if isinstance(cl, dict) and cl.get("text"):
            out.append((cl.get("id") or "L%d-C%02d" % (n, i), cl["text"]))
    return out


def tour_text_hash(tour):
    """One hash over every step's text and textMine, in order. A change to any sentence changes it."""
    parts = []
    for st in tour["steps"]:
        parts.append(st.get("id", ""))
        parts.extend(st.get("text", []))
        parts.extend(st.get("textMine", []))
    return text_hash("\n".join(parts))


def a15a_reader(root):
    """
    A verdict counts only for the text it judged. Each claim verdict carries the claim id and textHash (sha256 of the claim text with spaces
    collapsed). The step-text result (textRead) carries stepsRead, problemsOpen and textHash over every step text and textMine. A verdict that
    does not match the tour now is NOT RUN (unbound or stale), because it says nothing about the new words. An inaccurate claim, an open
    text problem, or a reader who wrote the tour is a FAIL.
    """
    tours = load_tours(root)
    missing, bad, unbound, stale, ok = [], [], [], [], 0
    for n in sorted(tours):
        p = os.path.join(root, "docs", "_verdicts", "a15a-lesson-%02d.json" % n)
        if not os.path.exists(p):
            missing.append(str(n))
            continue
        v = json.load(open(p, encoding="utf-8"))
        reader, authors = str(v.get("reader", "")).strip().lower(), [str(a).strip().lower() for a in v.get("authors", [])]
        if not reader or not authors or reader in authors:
            bad.append("lesson %d: reader '%s' wrote the tour or is empty (authors %s)" % (n, reader, authors))
        for cl in v.get("claims", []):
            if cl.get("verdict") not in ("accurate", "inaccurate", "unclear"):
                bad.append("lesson %d: claim %s has verdict %r" % (n, cl.get("id"), cl.get("verdict")))
            elif cl.get("verdict") != "accurate":
                bad.append("lesson %d: claim %s was judged %s" % (n, cl.get("id"), cl.get("verdict")))
        # The step-text result.
        tr = v.get("textRead")
        if not isinstance(tr, dict):
            unbound.append("lesson %d has no textRead (the step-text result)" % n)
        else:
            problems = tr.get("problems", [])
            open_problems = [x for x in problems if not str(x.get("status", "")).lower().startswith("fixed")]
            if int(tr.get("problemsOpen", 0) or 0) > 0 or open_problems:
                bad.append("lesson %d: the step-text read left %d problems open" % (n, max(int(tr.get("problemsOpen", 0) or 0), len(open_problems))))
            if not tr.get("textHash"):
                unbound.append("lesson %d: textRead has no textHash" % n)
            elif tr["textHash"] != tour_text_hash(tours[n]):
                stale.append("lesson %d: the step text changed after it was read" % n)
            if int(tr.get("stepsRead", -1)) != len(tours[n]["steps"]):
                stale.append("lesson %d: the reader read %s steps and the tour has %d" % (n, tr.get("stepsRead"), len(tours[n]["steps"])))
        # Each claim verdict is bound to its claim id and text, and every claim now declared has a verdict.
        now = dict(current_claims(tours[n], n))
        judged = {}
        for cl in v.get("claims", []):
            cid = cl.get("id")
            judged[cid] = cl
            if cid not in now:
                stale.append("lesson %d: verdict for claim %s, which the tour no longer declares" % (n, cid))
            elif not cl.get("textHash"):
                unbound.append("lesson %d: claim %s has no textHash" % (n, cid))
            elif cl["textHash"] != text_hash(now[cid]):
                stale.append("lesson %d: claim %s changed after it was judged" % (n, cid))
        for cid in now:
            if cid not in judged:
                stale.append("lesson %d: claim %s has no verdict" % (n, cid))
        ok += 1
    if bad:
        raise Fail("; ".join(bad[:5]))
    if unbound:
        raise NotRun("ACCURACY_VERDICT_UNBOUND", "%d verdict parts carry no hash of the text they judged, so they cannot bind to the tour: %s. Run docs_checks.py --hashes and have the reader confirm and stamp them" % (len(unbound), "; ".join(unbound[:4])))
    if stale:
        raise NotRun("ACCURACY_VERDICT_STALE", "the tour changed after the reader judged it: %s" % "; ".join(stale[:4]))
    if missing:
        raise NotRun("ACCURACY_READER_PENDING", "no verdict file docs/_verdicts/a15a-lesson-NN.json for lessons %s; an agent that did not write the tour must read it" % ", ".join(missing))
    return "%d lessons read by an agent that did not write them; every claim accurate and bound to its text hash; step text read in full, no problem open" % ok


def print_hashes(root):
    """Prints what a reader stamps into a verdict: claim id with textHash, and the textRead textHash, per lesson."""
    out = {}
    for n, tour in sorted(load_tours(root).items()):
        out[n] = {"claims": [{"id": cid, "textHash": text_hash(t)} for cid, t in current_claims(tour, n)], "textRead": {"stepsRead": len(tour["steps"]), "textHash": tour_text_hash(tour)}}
    print(json.dumps(out, indent=2))


def statement(root, lesson, patterns, label):
    tours = load_tours(root)
    if lesson not in tours:
        raise NotRun("LESSON_NOT_BUILT", "lesson %d has no tour yet" % lesson)
    text = lesson_text(tours[lesson])
    for s in tours[lesson]["steps"]:
        st = " ".join(step_texts(s))
        if all(re.search(p, st, re.I) for p in patterns):
            return "%s stated in step %s" % (label, s.get("id", "?"))
    raise Fail("lesson %d has no single step that states %s (needs text matching %s)" % (lesson, label, " and ".join(patterns)))


def fips_table(name):
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors", "aes-fips197-rounds.nsv")
    lines = open(path, encoding="utf-8").read().splitlines()
    for i, line in enumerate(lines):
        if line == "table = " + name:
            return bytes.fromhex(lines[i + 1].split(" = ")[1])
    raise NotRun("VECTORS_MISSING", "no table %s in aes-fips197-rounds.nsv" % name)


def table_patterns(table):
    """8 bytes from each row of a table, as hex or decimal, with any separators. So a copy of any part of a table shows, whatever its format."""
    out = []
    for start in range(0, 256, 16):
        chunk = table[start:start + 8]
        out.append(r"[\s,'\"]*(?:0x)?".join("%02x" % b for b in chunk))
        out.append(r"\b" + r"\s*,\s*".join(str(b) for b in chunk) + r"\b")
    return [re.compile(p, re.I) for p in out]


def a19_no_table_in_app(root):
    """Design section 3.1: every state and table on screen comes from the engine at query time, so app/src holds neither S-box."""
    if not os.path.exists(os.path.join(root, "app", "src", "walk.ts")):
        raise NotRun("PRODUCT_MISSING", "app/src/walk.ts does not exist yet")
    patterns = table_patterns(fips_table("sbox")) + table_patterns(fips_table("inverse"))
    hits = []
    for folder, _, files in os.walk(os.path.join(root, "app", "src")):
        for name in files:
            path = os.path.join(folder, name)
            text = open(path, encoding="utf-8", errors="replace").read()
            if any(p.search(text) for p in patterns):
                hits.append(os.path.relpath(path, root))
    if hits:
        raise Fail("app/src holds S-box bytes in: %s" % ", ".join(hits))
    return "no part of either S-box is under app/src"


WALK_NEVER = [
    (r"SubBytes replaces each byte of the plaintext", None),
    (r"10 main rounds", None),
    (r"decryption reverses the steps", r"\b(?:one block|ECB|CBC)\b"),
    (r"matrix multiplication", r"special multiply"),
    (r"4-bit chunk", None),
    (r"AES makes the tag", None),
    (r"adds the round key", r"\bXOR"),
    (r"the inverse round key", None),
    (r"unique IV", None),
    (r"corrupted block affects", None),
    (r"GCM must check the tag first", None),
    (r"vulnerable to cryptanalysis", None),
]


def a19_words(root):
    """Design section 2.6. A banned phrase with an 'unless' pattern is allowed on a line that also matches it."""
    panel = os.path.join(root, "app", "src", "components", "AesBlockWalk.vue")
    if not os.path.exists(panel):
        raise NotRun("PRODUCT_MISSING", "app/src/components/AesBlockWalk.vue does not exist yet")
    names = [panel, os.path.join(root, "app", "src", "components", "SboxView.vue"), os.path.join(root, "app", "src", "components", "AesFeedView.vue"), os.path.join(root, "app", "src", "walk-gloss.json"), os.path.join(root, "app", "src", "tours", "lesson-01.json")]
    bad = []
    for path in names:
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8").read().splitlines():
            for phrase, unless in WALK_NEVER:
                if re.search(phrase, line, re.I) and not (unless and re.search(unless, line, re.I)):
                    bad.append("%s: '%s'" % (os.path.basename(path), phrase))
    if bad:
        raise Fail("the walk's words break design section 2.6: %s" % "; ".join(bad))
    return "none of the %d phrases of design section 2.6 is in the walk's words" % len(WALK_NEVER)


def a19_routes_listed(root):
    """Design section 3.5: a clause lists each walk route and its behaviour with Show keys OFF, so a new route must join the list (checks/walk_routes.json)."""
    host = os.path.join(root, "src", "NetSec.Host")
    if not os.path.exists(os.path.join(host, "AesWalkRoutes.cs")):
        raise NotRun("PRODUCT_MISSING", "src/NetSec.Host/AesWalkRoutes.cs does not exist yet")
    listed = {r["route"] for r in json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "walk_routes.json"), encoding="utf-8"))["routes"]}
    found = set()
    for path in glob.glob(os.path.join(host, "**", "*.cs"), recursive=True):
        found |= set(re.findall(r"\"(?P<route>/api/[^\"]*walk[^\"]*)\"", open(path, encoding="utf-8").read()))
    if not found:
        raise Fail("no walk route found under src/NetSec.Host")
    unknown = sorted(found - listed)
    if unknown:
        raise Fail("these walk routes are not in checks/walk_routes.json: %s. Each needs its Show keys OFF rule and a clause" % ", ".join(unknown))
    return "%d walk routes in the Host, each listed with its Show keys OFF rule" % len(found)


def walk_lines():
    return json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "walk_lines.json"), encoding="utf-8"))


def text_of_app(root, names):
    """The text of the named app files that exist, with backticks and repeated spaces taken out, so a code span in a line still matches."""
    parts = []
    for name in names:
        path = os.path.join(root, "app", "src", *name.split("/"))
        if os.path.exists(path):
            parts.append(open(path, encoding="utf-8").read())
    return " ".join("\n".join(parts).replace("`", "").split())


def a19_definition(root, max_grade):
    """Design section 2.2c: the 5 lines appear in order, and pass the reading grade."""
    if not os.path.exists(os.path.join(root, "app", "src", "components", "FieldPanel.vue")):
        raise NotRun("PRODUCT_MISSING", "app/src/components/FieldPanel.vue does not exist yet")
    data = walk_lines()
    text = text_of_app(root, data["definitionFiles"])
    at = -1
    for n, line in enumerate(data["definition"]):
        found = text.find(line, at + 1)
        if found < 0:
            raise Fail("definition line %d is missing or out of order: %s" % (n + 1, line))
        at = found
    g = grade(" ".join(data["definition"]))[0]
    if g > max_grade:
        raise Fail("the definition reads at grade %.1f, above %.1f" % (g, max_grade))
    return "the %d definition lines appear in order, at grade %.1f" % (len(data["definition"]), g)


def a19_gcm_line(root):
    """Design section 2.4: the GCM panel names the Galois field. It arrives with chapter 2."""
    if not os.path.exists(os.path.join(root, "app", "src", "components", "AesFeedView.vue")):
        raise NotRun("PRODUCT_MISSING", "app/src/components/AesFeedView.vue does not exist yet")
    data = walk_lines()
    if data["gcmPanel"] not in text_of_app(root, data["gcmFiles"]):
        raise Fail("the GCM panel does not say: %s" % data["gcmPanel"])
    return "the GCM panel names the Galois field"


def engine_limits():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "engine_limits.json")
    return json.load(open(path, encoding="utf-8"))


def a18_line(root, limits, entry):
    """One lesson says on screen what its engine leaves out (docs/conformance-matrix.md). One step holds the whole line, and that step's claim cites the standard."""
    tours = load_tours(root)
    lesson = entry["lesson"]
    if lesson not in tours:
        raise NotRun("LESSON_NOT_BUILT", "lesson %d has no tour yet" % lesson)
    tour = tours[lesson]
    claims = list(tour["claims"])
    for s in tour["steps"]:
        claims += s.get("claims", [])
    whole = lesson_text(tour) + "\n" + "\n".join(plain(c.get("text", "")) for c in claims)
    for p in entry.get("banAnywhere", []):
        m = re.search(p, whole, re.I)
        if m:
            raise Fail("lesson %d still says '%s'" % (lesson, m.group(0)))
    patterns = list(entry["require"])
    if entry.get("needsAbsent", True):
        patterns.append(limits["absent"])
    for s in tour["steps"]:
        text = " ".join(step_texts(s))
        if entry.get("readClaims"):
            text += " " + " ".join(plain(c.get("text", "")) for c in s.get("claims", []))
        if not all(re.search(p, text, re.I) for p in patterns):
            continue
        for p in entry.get("banInLine", []):
            m = re.search(p, text, re.I)
            if m:
                raise Fail("step %s says '%s'. The line names what the engine leaves out, and does not rank the standard's list" % (s.get("id", "?"), m.group(0)))
        if not any(re.search(entry["source"], c.get("source", ""), re.I) for c in s.get("claims", [])):
            raise Fail("step %s holds the line, and carries no claim whose source names %s" % (s.get("id", "?"), entry["source"]))
        return "stated in step %s, matrix row %d" % (s.get("id", "?"), entry["row"])
    raise Fail("lesson %d has no single step with all of: %s" % (lesson, " and ".join(patterns)))


NON_GOAL_HEADING = re.compile(r"(?i)^#{1,6}\s.*\b(non-?goals?|out of scope|not in scope|will not do)\b")


def strip_non_goals(text, filename):
    """
    A plan lists the things it will NOT do, such as 'A run on a real CE device'. That line states a non-goal and claims nothing.
    In a markdown file, lines under a heading that names non-goals are left out of the scan. The scan still reads every other line,
    so a claim in the UI source or in a closing report is found.
    """
    if not filename.endswith(".md"):
        return text
    keep, skipping = [], False
    for line in text.splitlines():
        if re.match(r"^#{1,6}\s", line):
            skipping = bool(NON_GOAL_HEADING.match(line))
        if not skipping:
            keep.append(line)
    return "\n".join(keep)


def a16_wording(root):
    src = os.path.join(root, "app", "src")
    if not os.path.isdir(src):
        raise NotRun("PRODUCT_MISSING", "app/src does not exist yet")
    found = []
    for dp, dn, fn in os.walk(src):
        if "node_modules" in dp:
            continue
        for f in fn:
            if f.endswith((".vue", ".ts", ".json", ".md", ".js")):
                p = os.path.join(dp, f)
                if CE_WORDING in open(p, encoding="utf-8", errors="replace").read():
                    found.append(os.path.relpath(p, root))
    if not found:
        raise Fail("the wording '%s' appears nowhere in app/src" % CE_WORDING)
    bad = []
    for base in (src, os.path.join(root, "docs")):
        for dp, dn, fn in os.walk(base):
            if "node_modules" in dp or os.sep + "wip" in dp or os.sep + "_runs" in dp:   # run reports quote the banned phrase when a clause fails
                continue
            for f in fn:
                if f.endswith((".vue", ".ts", ".md", ".json", ".html")):
                    p = os.path.join(dp, f)
                    text = open(p, encoding="utf-8", errors="replace").read()
                    for pat in FORBIDDEN_CE:
                        m = re.search(pat, strip_non_goals(text, f))
                        if m:
                            bad.append("%s: '%s'" % (os.path.relpath(p, root), m.group(0)))
    if bad:
        raise Fail("claims of a CE run: " + "; ".join(bad[:4]))
    return "wording found in %s; no claim of a run on CE" % ", ".join(found[:3])


# ---------------------------------------------------------------- A17 wording and copy (modes-design.md sections 2 and 8)

WIZARD_COPY = os.path.join("app", "src", "wizard-copy.json")
TEST_KEYS_ID = "wizard.common.test-keys-only"
TEST_KEYS_LINE = "Use test keys only. This course shows your keys on screen and in saved files."
LOCAL_ROOT_SENTENCE = "A local root is trusted only by what was told to trust it"


def copy_texts(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [x for v in value for x in copy_texts(v)]
    if isinstance(value, dict):
        return [x for k, v in value.items() if k in ("text", "title", "label", "body", "lines") for x in copy_texts(v)]
    return []


def load_wizard_copy(root):
    p = os.path.join(root, WIZARD_COPY)
    if not os.path.exists(p):
        raise NotRun("PRODUCT_MISSING", "app/src/wizard-copy.json does not exist yet (the wizard words, keyed by copy id)")
    data = json.load(open(p, encoding="utf-8"))
    return {k: copy_texts(v) for k, v in data.items()}


def ui_files(root):
    src = os.path.join(root, "app", "src")
    if not os.path.isdir(src):
        raise NotRun("PRODUCT_MISSING", "app/src does not exist yet")
    for dp, dn, fn in os.walk(src):
        if "node_modules" in dp:
            continue
        for f in fn:
            if f.endswith((".vue", ".ts", ".json", ".md")):
                yield os.path.join(dp, f)


# Prose may say "a real HSM" or "real keys" when it means production. A mode, a transport or a button label may never be called Real.
FORBIDDEN_REAL = [r"(?i)\breal[- ]mode\b", r"(?i)\breal[- ]transport\b", r">\s*Real\s*<", r"\"Real\"", r"'Real'"]


def a17_no_word_real(root):
    """The UI names a mode 'Built-in key' or 'My test key'. It never says 'Real' for a mode, a key or a transport."""
    files = list(ui_files(root))
    text_by_file = {f: open(f, encoding="utf-8", errors="replace").read() for f in files}
    both = {w: [os.path.relpath(f, root) for f, t in text_by_file.items() if w in t] for w in ("Built-in key", "My test key")}
    if not all(both.values()):
        raise NotRun("PRODUCT_MISSING", "the security page does not exist yet: app/src holds no text '%s'" % "' or '".join(w for w, v in both.items() if not v))
    hits = []
    for f, t in text_by_file.items():
        for pat in FORBIDDEN_REAL:
            m = re.search(pat, t)
            if m:
                hits.append("%s: '%s'" % (os.path.relpath(f, root), m.group(0).strip()))
    if hits:
        raise Fail("the word Real names a mode, key or transport in the UI source: " + "; ".join(hits[:5]))
    return "the UI says Built-in key (%s) and My test key (%s); no 'Real mode', 'real key', 'real transport' or 'Real' label in %d files" % (both["Built-in key"][0], both["My test key"][0], len(files))


def a17_test_keys_line(root):
    copy = load_wizard_copy(root)
    if TEST_KEYS_ID not in copy:
        raise Fail("wizard-copy.json has no entry %s" % TEST_KEYS_ID)
    got = norm(" ".join(copy[TEST_KEYS_ID]))
    if got != TEST_KEYS_LINE:
        raise Fail("%s reads '%s'; it must read '%s'" % (TEST_KEYS_ID, got, TEST_KEYS_LINE))
    users = [os.path.relpath(f, root) for f in ui_files(root) if not f.endswith("wizard-copy.json") and TEST_KEYS_ID in open(f, encoding="utf-8", errors="replace").read()]
    vue = [u for u in users if u.endswith(".vue")]
    if not vue:
        raise Fail("no .vue component uses %s, so the security page does not show the line" % TEST_KEYS_ID)
    return "%s reads the exact line; used by %s" % (TEST_KEYS_ID, ", ".join(vue[:3]))


def a17_no_outside_judge_line(root):
    """Where no outside tool can judge a type, the words say so. Where a tool did judge, they name it. A pass never reads 'trusted'."""
    copy = load_wizard_copy(root)
    allv = {k: " ".join(v) for k, v in copy.items()}
    none_ids = [k for k, v in allv.items() if "No outside tool can judge this" in v]
    problems = []
    if len(none_ids) < 2:
        problems.append("'No outside tool can judge this' appears in %d entries; the payment keys and the passkey-shaped login need one each" % len(none_ids))
    if not any("Our own check passed" in allv[k] for k in none_ids):
        problems.append("no 'No outside tool can judge this' entry says 'Our own check passed' (the passkey-shaped login)")
    if not any("Our code matches the published vectors" in allv[k] for k in none_ids):
        problems.append("no 'No outside tool can judge this' entry says 'Our code matches the published vectors' (the payment keys)")
    if not any("Checked against the root you gave it" in v for v in allv.values()):
        problems.append("no entry says 'Checked against the root you gave it'")
    for k, v in allv.items():
        stripped = v.replace(LOCAL_ROOT_SENTENCE, "")
        if re.search(r"(?i)\btrusted\b", stripped):
            problems.append("%s says 'trusted' outside the sentence '%s'" % (k, LOCAL_ROOT_SENTENCE))
        if re.search(r"(?i)device|dukpt|payment|passkey", k) and re.search(r"(?i)checked with openssl|checked with ssh", v):
            problems.append("%s names an outside tool for a type no outside tool can judge" % k)
    if problems:
        raise Fail("; ".join(problems[:5]))
    return "%d entries say no outside tool can judge it; cert checks read 'Checked against the root you gave it'; no entry says trusted" % len(none_ids)


def a17_copy_grade_and_tics(root, max_grade, tic_gate):
    copy = load_wizard_copy(root)
    bad = []
    for k, v in copy.items():
        text = " ".join(v)
        if len(re.findall(r"[A-Za-z]+", text)) >= 6:
            g = grade(text)[0]
            if g > max_grade:
                bad.append("%s reads at grade %.1f (limit %.1f)" % (k, g, max_grade))
    g_all = grade("\n".join(" ".join(v) for v in copy.values()))[0]
    if g_all > max_grade:
        bad.append("all wizard copy together reads at grade %.1f" % g_all)
    if not os.path.exists(tic_gate):
        raise NotRun("TOOL_MISSING", "tic-gate.py not found at " + tic_gate)
    r = subprocess.run([sys.executable, tic_gate, os.path.join(root, WIZARD_COPY)], capture_output=True, text=True)
    if r.returncode != 0:
        bad.append("tic-gate.py found tics: " + (r.stdout or r.stderr).strip().replace("\n", " | ")[:200])
    if bad:
        raise Fail("; ".join(bad[:5]))
    return "%d wizard copy entries: all text grade %.1f (limit %.1f), tic-gate.py clean" % (len(copy), g_all, max_grade)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True)
    ap.add_argument("--ids", default="")
    ap.add_argument("--tic-gate", default=os.path.expanduser("~/.claude/hooks/tic-gate.py"))
    ap.add_argument("--max-grade", type=float, default=8.9)
    ap.add_argument("--max-concept", type=float, default=0.30)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--hashes", action="store_true", help="print the claim and text hashes a reader stamps into a15a verdicts")
    a = ap.parse_args()
    root = a.root
    if a.hashes:
        print_hashes(root)
        return 0
    clauses = {
        "A3.tour.states-managed-heap-can-keep-copies": lambda: statement(root, 6, [r"managed heap|garbage collector|\bGC\b", r"cop(?:y|ies)"], "that a managed heap can keep copies of erased keys"),
        "A12.tour.states-no-constant-time-guarantee": lambda: statement(root, 11, [r"managed code", r"constant.time"], "that managed code has no constant-time guarantee"),
        "A14.tours.static-schema-and-concept-cap": lambda: a14_static(root, a.max_concept),
        "A15.tours.reading-grade": lambda: a15_grade(root, a.max_grade),
        "A15.tours.tic-gate": lambda: a15_tic_gate(root, a.tic_gate),
        "A15a.tours.accuracy-rules-stated": lambda: a15a_rules(root),
        "A15a.tours.claims-cite-a-source": lambda: a15a_claims_cite(root),
        "A15a.tours.reader-verdicts": lambda: a15a_reader(root),
        "A16.wording.cf-compiled-never-run-on-ce": lambda: a16_wording(root),
        "A17.ui.no-word-real": lambda: a17_no_word_real(root),
        "A17.ui.test-keys-line": lambda: a17_test_keys_line(root),
        "A17.ui.no-outside-judge-line": lambda: a17_no_outside_judge_line(root),
        "A17.copy.grade-and-tics": lambda: a17_copy_grade_and_tics(root, a.max_grade, a.tic_gate),
        "A19.app.no-table-under-src": lambda: a19_no_table_in_app(root),
        "A19.app.words-follow-the-rules": lambda: a19_words(root),
        "A19.repo.walk-routes-listed": lambda: a19_routes_listed(root),
        "A19.app.field-definition-lines": lambda: a19_definition(root, a.max_grade),
        "A19.app.gcm-panel-names-the-field": lambda: a19_gcm_line(root),
    }
    limits = engine_limits()
    for entry in limits["lines"]:
        clauses[entry["id"]] = (lambda e: lambda: a18_line(root, limits, e))(entry)
    if a.list:
        print("\n".join(sorted(clauses)))
        return 0
    wanted = [i for i in a.ids.split(",") if i] or sorted(clauses)
    for cid in wanted:
        fn = clauses.get(cid)
        if fn is None:
            emit(cid, "NOT RUN", "NOT_IN_GROUP", "docs_checks.py has no clause with this id")
            continue
        try:
            emit(cid, "PASS", "", fn())
        except NotRun as e:
            emit(cid, "NOT RUN", e.reason, str(e))
        except Fail as e:
            emit(cid, "FAIL", "ASSERTION", str(e))
        except Exception as e:                      # a crash is a FAIL, never a PASS
            emit(cid, "FAIL", "UNEXPECTED_EXCEPTION", "%s: %s" % (type(e).__name__, e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
