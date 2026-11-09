# Test garden: plan

Status: DRAFT for Steve's sign-off. Steve picked option A on 2026-11-09 (stability levels plus change-based selection plus a full nightly run). Revision 2 closes Jared's 6 design blockers from the review at `60c8313`. Decision 4 below is open for Steve.

## The problem

1. Every gate runs every test. The app suite is 270 Playwright tests and took 35.5 min at `d1cce14` on a quiet machine. On a loaded machine the same suite took 1.4 h.
2. Heavy runs go one at a time through `tools/heavy_lock.py`. On 2026-11-09 one wait ended with `LOCK_TIMEOUT` after 120 min, and five agents waited in one queue.
3. A long wait costs tokens. An agent that waits past the prompt-cache lifetime reloads its context on the next turn at full price.
4. Most of the time goes to tests that guard code the branch does not touch.

## The goal

A gate runs the tests the change needs. Tests that stayed green for a long time sink below the surface and run on a schedule. A failure pops the tests near it back to the surface until the fix holds.

## Kill condition

The work ends when both results hold, by 2026-11-30:

1. On 5 consecutive product branches, the median gate time is 10 min or less. Gate time is the wall time in the gate's own log while it held `heavy_lock.py`. The log records the machine's process count at the start, and a run counts only when that count is under a limit. The spike measures the machine's idle process count and sets the limit at that count plus 20.
2. In the first 14 days of nightly runs, at least 10 PRs merge on a picked run, and the escape count is 0, or each escape has a mapping fix merged with a red-first test. If fewer than 10 picked-run PRs merge, the window extends until 10 do.

**Escape.** A nightly red is bisected to the merged PR that caused it (`git bisect` over the merges since the last green nightly, running only the red test units). The red is an escape when that PR merged on a picked run that passed. A red that passes on rerun is a flake. It is still logged, with the rerun result, and it counts as red for the sink streak.

## Prior art

1. Test impact analysis: Bazel's affected-target query (`bazel query 'rdeps(//..., set(<changed files>))'`) runs the targets that depend on the changed files. We take the idea. We have no build graph, so the dependency map comes from coverage plus fixed lists.
2. Predictive test selection at Meta (Machalica et al., "Predictive Test Selection", 2019) picks tests with a learned model and keeps a full run behind it. We take the full run behind the picker. We reject the learned model, because a rule must decide (house rule: deterministic first).
3. Test tiers (smoke, regression, release). We take the tiers. We reject tier by judgment: a program moves tests, never an agent.
4. Theo (t3.gg), "Coding Isn't About Code Anymore", 2026-11-09:
   - @38:05 He deleted about half of the unit tests in T3 Code (about 250,000 lines). Of 11,000 deleted tests he brought back 4, and he reports no regression that a deleted test would have caught. This is his self-report, with no data shown.
   - @39:14 When a bad test appears, the team asks the agent that wrote it why, and fixes the guidance at the root.
   - @40:20 One fast check (under about 45 s) runs on every PR with real data and prints its number in the PR.
   - @36:58 A slow check makes agents miss prompt-cache reads.

Where we differ: Theo deletes. We do both. A test that checks nothing gets deleted (step 1). A test that checks something stable sinks (step 2).

## The design

### Levels

| Level | Runs when | Holds |
|---|---|---|
| Surface | Every gate | Tests for the open feature or bug, every popped test, every new test, and every changed test unit |
| Deep | Nightly, at release, and on any gate whose change touches a file the test covers | Tests that stayed green past the sink rule |
| Release | Release only | Long soaks and the full acceptance sweep |

Acceptance clauses are not picked. The clauses a gate names (`-Clauses`) always run, and every clause runs nightly and at release. Echo owns that set.

### The manifest

One file, `tests/levels.json`. One entry per test unit (a Playwright spec file, a C# test class, a tools test file):

```json
{ "id": "app/e2e/dh-walk.spec.ts", "level": "deep",
  "covers": ["app/src/walks/dh/**", "src/NetSec.Core/Labs/DhWalks.cs", "src/NetSec.Host/Walks/DhWalkRoutes.cs"],
  "coversFrom": ["v8", "coverlet-host"] }
```

`covers` comes from coverage data only, never by hand. The `coversFrom` field names the source of each map. Streaks and moves live in the ledger, not in the manifest (see "Ledger").

### Kind: platform or product

The picker computes kind from paths. No agent states it.

1. **Product** is only what one list names: `tests/product-paths.txt`. Proposed start: `app/src/walks/**`, `app/src/tours/lesson-*.json` (see run-everything rule 2), and `src/NetSec.Core/Labs/**` if Steve picks decision 4 A.
2. **Platform** is every other path, including any new folder. A new folder runs everything until a PR adds it to the product list.

A PR that touches any platform path is a platform PR. The picker prints the kind and the paths that set it.

### The picker

`tools/pick_tests.py --base <merge-base>` reads `git diff --name-status -M <merge-base>` and matches both the old and the new path of each rename or delete. It prints the test list and the reason for each pick:

1. All surface tests.
2. Every changed test unit, at any level.
3. Each deep test whose `covers` matches a changed file.
4. Each test unit that the ledger shows red in its latest nightly or release run. A pop takes effect on the next gate, before any move PR merges.
5. All tests, when any changed path is platform.
6. All tests, when any changed path is on the run-everything list (below).
7. All tests, when no test unit's `covers` holds a changed file.

The gate prints one row per skipped test unit as SKIP with its level. A skipped test never reads PASS.

### Run-everything list

`tests/run-everything.txt` names files that coverage cannot see, because code reads them at run time or build time:

- `app/package.json`, `app/package-lock.json`, `*.csproj`, `Directory.Build.*`, `global.json`
- `app/playwright.config.ts`, `app/e2e/*.ts` that no spec is named for (`walk.ts`, `contrast.ts`, `ports.ts`)
- `tools/gate.ps1`, `tools/gate_app.ps1`, `tools/heavy_lock.py`
- `acceptance/vectors/**`
- `app/src/tours/**` and `app/src/glossary.json`, until the spike shows a tour file maps to the specs that read it

A change to any of these runs everything.

### Cross-process coverage

A Playwright spec drives the Release Host in its own process. V8 coverage sees only `app/src`. The spike runs coverlet on the live Host process during each spec, and merges that map into the spec's `covers` (`coversFrom: coverlet-host`). If the spike cannot produce a stable Host map, every `src/NetSec.Host/**` path stays platform.

### Ledger

`docs/_runs/levels-ledger.jsonl`, one line per test unit per run:

```json
{ "unit": "app/e2e/dh-walk.spec.ts", "commit": "d1cce14", "run": "nightly", "result": "pass", "retried": false, "at": "2026-11-20T02:41:00Z" }
```

`result` is `pass`, `fail` or `skip`. A pass with `retried: true` counts as red for the streak.

### Move rules (deterministic)

1. Sink: a surface test sinks after 10 runs in a row with `result: pass` and `retried: false`, across at least 7 days.
2. Pop: a deep test pops on any red. With it pop the test units whose `covers` holds a file in the red test's `covers` that changed since that test's last green run.
3. A popped test sinks again only by rule 1, counted from the fix.
4. `tools/move_levels.py` reads the ledger and writes the levels. A pop works at once through picker rule 4. A sink lands in a PR, so the diff shows it.

### Nightly run

An OS scheduled task runs the full gate at 02:00 under `heavy_lock.py`, when no agent waits. It appends to the ledger, and one summary line to `docs/_runs/nightly.md`: date, commit, N of M passed, escapes. A run that cannot take the lock records SKIPPED with the reason. It never records PASS.

## Decisions

1. Option A (Steve, 2026-11-09).
2. The default kind is platform. Only listed paths are product.
3. A pop takes effect at once. A sink goes through a PR.
4. **OPEN for Steve.** The lesson and walk engines live in `src/NetSec.Core/Labs/`. If all of Core is platform, most lesson work runs everything, and kill condition 1 cannot be met.
   - **A (recommended):** `src/NetSec.Core/Labs/**` is product, with per-lab covers from coverlet. The rest of Core stays platform. This holds only if the spike shows the Labs map is stable across 2 runs.
   - **B:** all of Core stays platform, and kill condition 1 counts only app and Host branches.

## Steps

1. **Weed (before any sinking).** Echo runs the `test-anti-patterns` and `test-gap-analysis` passes over the suites. Tests that check nothing get deleted in their own PR, each with the reason. A test with no failure mode never sinks; it goes.
2. **Spike: the covers map.** For 5 Playwright specs and 5 C# test classes, build `covers` from V8 coverage, coverlet on the test process, and coverlet on the live Host process. Record whether each map is the same across 2 runs, and whether a Labs file maps to its lab's tests. Measure the machine's idle process count. The output goes in this plan before sign-off, and it settles decision 4 and the Host rule.
3. **Picker, manifest, lists and ledger**, with SKIP rows in the gate. Red first: a branch that touches a deep test's covered file must pick that test; a branch that touches a run-everything file must run everything; a new folder must run everything.
4. **Move rules, bisect, and the nightly task.**
5. **House rule change.** Rule 2 of the test regimen (`~/.claude/agents/echo.md`) changes from "full gate on every change" to "the picked tests on every gate, plus the full run nightly and at release". Steve approves the text.

## Accepted risks

1. A semantic merge conflict: two PRs, each green on its picks, that break together. Only the nightly run catches it, up to 24 h later.
2. A coverage map misses a path that a test reads in a way coverage cannot see and that no list names. The nightly run catches it, and the fix adds the path to a list.

## Non-goals

1. No agent decides a level or a kind by judgment.
2. No change to acceptance/ ownership. Echo still owns acceptance/ and its clauses.
3. No test deletion without a reason line in the PR.

## Boundary and failure routing

- Free: the picker, the manifest, the lists, the move rules, the nightly ledger, test deletions with reasons (each via PR and review).
- Needs Steve: decision 4, the regimen rule 2 text, the OS scheduled task, and any change to the release sweep.
- A picker that cannot map a file runs everything (picker rule 7). A spike that cannot build a stable map keeps that area platform.

## Owners

- Kody: picker, manifest tooling, lists, ledger, nightly task, gate SKIP rows.
- Echo: weeding pass, move-rule tests, regimen text draft.
- Jared: review of each step.

## Anchor

The nightly full run is the anchor. It shares no code with the picker, and it runs every test on the same commit. An escape count above 0 means the picker or a list is wrong.
