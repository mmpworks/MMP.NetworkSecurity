# Test garden: plan

Status: DRAFT for Steve's sign-off. Steve picked option A on 2026-11-09 (stability levels plus change-based selection plus a full nightly run).

## The problem

1. Every gate runs every test. The app suite is 270 Playwright tests and took 35.5 min at `d1cce14` on a quiet machine. On a loaded machine the same suite took 1.4 h.
2. Heavy runs go one at a time through `tools/heavy_lock.py`. On 2026-11-09 one wait ended with `LOCK_TIMEOUT` after 120 min, and five agents waited in one queue.
3. A long wait costs tokens. An agent that waits past the prompt-cache lifetime reloads its context on the next turn at full price.
4. Most of the time goes to tests that guard code the branch does not touch.

## The goal

A gate runs the tests the change needs. Tests that stayed green for a long time sink below the surface and run on a schedule. A failure pops the tests near it back to the surface until the fix holds.

## Kill condition

The work ends when both results hold, by 2026-11-30:

1. On 5 consecutive product branches (see "Platform or product"), the median gate wall-clock time is 10 min or less on a quiet machine.
2. Over the first 14 days of nightly runs, the count of escapes is 0, or each escape has a mapping fix merged with a red-first test. An escape is a nightly red on a commit where the selected run passed.

## Prior art

1. Test impact analysis (run the tests whose covered files changed). Used by large monorepo CI systems. We take the idea, not their build graph.
2. Test tiers (smoke, regression, release). We take the tiers. We reject tier by judgment: a program moves tests, never an agent.
3. Theo (t3.gg), "Coding Isn't About Code Anymore", 2026-11-09:
   - @38:05 He deleted about half of the unit tests in T3 Code (about 250,000 lines). Of 11,000 deleted tests he brought back 4, and he reports no regression that a deleted test would have caught. This is his self-report, with no data shown.
   - @39:14 When a bad test appears, the team asks the agent that wrote it why, and fixes the guidance at the root.
   - @40:20 One fast check (under about 45 s) runs on every PR with real data and prints its number in the PR. It guards the one property the team cares about.
   - @36:58 A slow check makes agents miss prompt-cache reads.

Where we differ: Theo deletes. We do both. A test that checks nothing gets deleted (step 1). A test that checks something stable sinks (step 2).

## The design

### Levels

| Level | Runs when | Holds |
|---|---|---|
| Surface | Every gate | Tests for the open feature or bug, every test that popped up, and every new test |
| Deep | Nightly, at release, and on any gate whose change touches a file the test covers | Tests that stayed green past the sink rule |
| Release | Release only | Long soaks and the full acceptance sweep |

### The manifest

One file, `tests/levels.json`. One entry per test unit (a Playwright spec file, a C# test class, a tools test file):

```json
{ "id": "app/e2e/dh-walk.spec.ts", "level": "deep", "kind": "product",
  "covers": ["app/src/walks/dh/**", "src/NetSec.Host/Walks/DhWalkRoutes.cs"],
  "greenStreak": 14, "movedAt": "2026-11-20", "movedWhy": "sink rule" }
```

### The picker

`tools/pick_tests.py --base <ref>` reads the diff and the manifest. It prints the test list and the reason for each pick:

1. All surface tests.
2. Each deep test whose `covers` matches a changed file.
3. All tests, when the change touches a platform path (see below).
4. All tests, when the manifest has no entry for a changed file. An unmapped file never skips a test.

The gate prints one row per skipped test unit as SKIP with its level. A skipped test never reads PASS.

### Move rules (deterministic)

1. Sink: a surface test sinks after 10 green runs in a row across at least 7 days, with no failure in that time.
2. Pop: a deep test pops to surface on any red (nightly, release, or a selected run). The other tests that cover the same files pop with it.
3. A popped test sinks again only by rule 1, counted from the fix.
4. `tools/move_levels.py` applies the rules from the run ledger. A move lands in a PR like any other change, so the diff shows it.

### Platform or product

Each manifest entry and each source folder carries `kind`:

- **platform**: code many parts depend on. In this repo: `src/NetSec.Core/`, the Host start and route plumbing, `tools/`, `acceptance/tools/`, and the shared app shell and composables.
- **product**: one lesson, walk, tour or screen.

A platform change runs everything, because many tests stand on it. A product change runs only its picks. The PR body states the kind. A PR that touches both is a platform PR.

Theo splits his own work about 50/50 between the two (@21:20). The plan records our ratio each week as a health number. It sets no target.

### Nightly run

An OS scheduled task runs the full gate at 02:00 under `heavy_lock.py`, when no agent waits. It appends one line to `docs/_runs/nightly.md`: date, commit, N of M passed, escapes. A red pops tests by rule 2 and blocks merges whose picks include the popped tests.

## Steps

1. **Weed (before any sinking).** Echo runs the `test-anti-patterns` and `test-gap-analysis` passes over the suites. Tests that check nothing get deleted in their own PR, each with the reason. A test with no failure mode never sinks; it goes.
2. **Spike: the covers map.** Build `covers` for 5 Playwright specs and 5 C# test classes from coverage data (V8 coverage for the app, coverlet for .NET). Record whether the map is stable across 2 runs. Its output goes in this plan before sign-off.
3. **Picker and manifest**, with SKIP rows in the gate. Red first: a branch that touches a deep test's file must pick that test.
4. **Move rules and the nightly task.**
5. **House rule change.** Rule 2 of the test regimen (`~/.claude/agents/echo.md`) changes from "full gate on every change" to "the picked tests on every gate, plus the full run nightly and at release". Steve approves the text.

## Non-goals

1. No agent decides a level by judgment.
2. No change to acceptance/ ownership. Echo still owns acceptance/ and its clauses.
3. No test deletion without a reason line in the PR.

## Boundary and failure routing

- Free: the picker, the manifest, the move rules, the nightly ledger, test deletions with reasons (each via PR and review).
- Needs Steve: the regimen rule 2 text, the OS scheduled task, and any change to the release sweep.
- A picker that cannot map a file falls back to running everything (rule 4). A nightly run that cannot take the lock records SKIPPED with the reason. It never records PASS.

## Owners

- Kody: picker, manifest tooling, nightly task, gate SKIP rows.
- Echo: weeding pass, move-rule tests, regimen text draft.
- Jared: review of each step.

## Anchor

The nightly full run is the anchor. It shares no code with the picker, and it runs every test on the same commit. An escape count above 0 means the picker is wrong.
