#!/usr/bin/env python
"""Builder-side lint of the tour files: shape, concept share (A14), reading grade (A15), and the term marks.
acceptance/checks/docs_checks.py is the grader. This script gives a builder the answer before the gate.

Usage: python tools/tour_lint.py app/src/tours --max-grade 8.9 --max-concept 0.30
"""
import argparse
import json
import os
import re
import sys

TERM = re.compile(r"\{\{term:(?P<id>[a-z0-9-]+)\}\}")
STEP_ID = re.compile(r"^L(?P<lesson>\d+)-S(?P<step>\d+)$")


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
    sentences = [s for s in re.split(r"(?<=[.!?])\s+|\n+", text.strip()) if re.search(r"[A-Za-z]", s)]
    words = re.findall(r"[A-Za-z]+(?:'[a-z]+)?", text)
    if not sentences or not words:
        return 0.0
    total = sum(syllables(w) for w in words)
    return 0.39 * (len(words) / len(sentences)) + 11.8 * (total / len(words)) - 15.59


def steps_of(doc):
    return doc if isinstance(doc, list) else doc.get("steps", [])


def lint(path, max_grade, max_concept):
    problems = []
    with open(path, encoding="utf-8") as handle:
        steps = steps_of(json.load(handle))
    if not steps:
        return ["%s: no steps" % path], 0.0, 0.0, 0
    seen, concept, texts = set(), 0, []
    for step in steps:
        sid = step.get("id", "")
        if not STEP_ID.match(sid):
            problems.append("%s: step id '%s' is not L<lesson>-S<nn>" % (path, sid))
        if sid in seen:
            problems.append("%s: step id '%s' repeats" % (path, sid))
        seen.add(sid)
        bind = step.get("bind") or {}
        kind = bind.get("kind")
        if kind == "concept":
            concept += 1
        elif kind == "event":
            if not bind.get("eventType"):
                problems.append("%s: %s binds an event with no eventType" % (path, sid))
        else:
            problems.append("%s: %s has bind.kind '%s'" % (path, sid, kind))
        # An action unlock names the try-it of its own step. The app ignores ref today, so a wrong ref passes every walk.
        unlock = step.get("unlock") or {}
        if unlock.get("mode") == "action":
            try_id = (step.get("tryIt") or {}).get("id")
            if unlock.get("ref") != try_id:
                problems.append("%s: %s unlock.ref '%s' does not name its try-it '%s'" % (path, sid, unlock.get("ref"), try_id))
        for text in step.get("text", []):
            texts.append(TERM.sub(lambda m: m.group("id").replace("-", " "), text))
            declared = set(step.get("glossary", []))
            for match in TERM.finditer(text):
                if match.group("id") not in declared:
                    problems.append("%s: %s marks term '%s' and its glossary list omits it" % (path, sid, match.group("id")))
    share = concept / len(steps)
    level = grade(" ".join(texts))
    if share > max_concept:
        problems.append("%s: concept share %.2f is above %.2f" % (path, share, max_concept))
    if level > max_grade:
        problems.append("%s: reading grade %.2f is above %.2f" % (path, level, max_grade))
    return problems, level, share, len(steps)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("tours")
    parser.add_argument("--max-grade", type=float, default=8.9)
    parser.add_argument("--max-concept", type=float, default=0.30)
    args = parser.parse_args()
    if not os.path.isdir(args.tours):
        print("tour_lint: %s does not exist; 0 tours checked" % args.tours)
        return 0
    names = sorted(n for n in os.listdir(args.tours) if re.match(r"^lesson-\d+\.json$", n))
    failed = 0
    for name in names:
        problems, level, share, count = lint(os.path.join(args.tours, name), args.max_grade, args.max_concept)
        print("%s: %d steps, grade %.2f, concept share %.2f" % (name, count, level, share))
        for problem in problems:
            print("TOUR " + problem)
        failed += len(problems)
    print("tour_lint: %d files, %d problems" % (len(names), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
