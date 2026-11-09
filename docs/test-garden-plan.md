# Test garden: plan

Status: SIGNED OFF by Steve, 2026-11-09. Steve picked option A (stability levels plus change-based selection plus a full nightly run), approved the regimen rule 2 change, and set the nightly run to a deterministic script with Haiku only on failure.

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
2. In the first 14 days of nightly runs, at least 10 PRs merge on a picked run, and the escape count is 0, or each escape has a mapping fix merged with a red-first test. If fewer than 10 picked-run PRs merge, the window extends until 10 do. If either result is not met on 2026-11-30, the report states N of 10 merges and the escape count, and Steve decides whether to continue.

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
4. Each popped test unit (see "Popped state"). A pop takes effect on the next gate, before any move PR merges.
5. All tests, when any changed path is platform.
6. All tests, when any changed path is on the run-everything list (below).
7. All tests, when no test unit's `covers` holds a changed file.

The gate prints one row per skipped test unit as SKIP with its level. A skipped test never reads PASS.

### Run-everything list

`tests/run-everything.txt` names files that coverage cannot see, because code reads them at run time or build time:

- `app/package.json`, `app/package-lock.json`, `*.csproj`, `Directory.Build.*`, `global.json`
- `app/playwright.config.ts`, and the e2e helpers by name: `app/e2e/walk.ts`, `app/e2e/contrast.ts`, `app/e2e/ports.ts`, plus the global setup file if one exists. A `*.spec.ts` file is a test unit, so it is not on this list.
- `tools/gate.ps1`, `tools/gate_app.ps1`, `tools/heavy_lock.py`
- `acceptance/vectors/**`
- `app/src/tours/**` and `app/src/glossary.json`, until the spike shows a tour file maps to the specs that read it

A change to any of these runs everything. The run-everything list beats the product list when a path is on both.

### Cross-process coverage

A Playwright spec drives the Release Host in its own process. V8 coverage sees only `app/src`. The spike runs coverlet on the live Host process during each spec, and merges that map into the spec's `covers` (`coversFrom: coverlet-host`). If the spike cannot produce a stable Host map, every `src/NetSec.Host/**` path stays platform.

### Ledger

The ledger lives outside every worktree, at the fixed path `E:/dev/ns-state/levels-ledger.jsonl`. The picker and `move_levels.py` read it through the setting `NETSEC_STATE_DIR` (default `E:/dev/ns-state`). It is append-only. Only `nightly.ps1` and the gate write to it, and no builder's worktree holds it. One line per test unit per run:

```json
{ "unit": "app/e2e/dh-walk.spec.ts", "commit": "d1cce14", "run": "nightly", "result": "pass", "retried": false, "at": "2026-11-20T02:41:00Z" }
```

`result` is `pass`, `fail` or `skip`. A pass with `retried: true` counts as red for the streak.

`run` is `nightly`, `release` or `branch`. Only `nightly` and `release` lines count toward the sink streak and the `popped()` window, because only they test main. `branch` lines are kept for timing only.

### Popped state

One function, `popped(unit)`, used by both the picker and `tools/move_levels.py`. A qualifying red for `unit` is the latest nightly or release red that is either:

1. a red of `unit` itself, or
2. a red of another unit R, where `unit`'s `covers` holds a file that is in R's `covers` and changed between R's last green run and that red (move rule 2's companion pop).

`unit` is popped when it has a qualifying red and, since the latest such red, `unit` itself has fewer than 10 runs with `result: pass` and `retried: false`, or those runs span less than 7 days. The function reads the ledger, the manifest's `covers`, and `git diff` between the two commits. The manifest level does not change it.

A red on a branch gate belongs to that branch. It pops nothing.

### Move rules (deterministic)

1. Sink: a surface test sinks after 10 runs in a row with `result: pass` and `retried: false`, across at least 7 days.
2. Pop: a deep test pops on a nightly or release red. With it pop the test units whose `covers` holds a file in the red test's `covers` that changed since that test's last green run.
3. A popped test sinks again only by rule 1, counted from the fix. The `popped()` function enforces this.
4. `tools/move_levels.py` reads the ledger and writes the levels. A pop works at once through picker rule 4. A sink lands in a PR, so the diff shows it.

### Nightly run

A Windows scheduled task runs `tools/nightly.ps1` at 02:00, when no agent waits. The script is deterministic end to end: no model runs on a green night.

0. One-time setup, by a human: create `E:/dev/ns-nightly`, run `npm ci` in its `app/`, then run `python -I tools/electron_dist.py check` (from #355). Record that commit in `E:/dev/ns-state/nightly-setup.txt`. It is the "last nightly's commit" for the lockfile check on the first night. Without this step, the first night exits 2 by design.
1. Fetch `origin/main`. In the dedicated worktree `E:/dev/ns-nightly` (never a builder's worktree), run `git checkout --detach origin/main` and `git clean -fd`. The clean has no `-x`, so `app/node_modules` stays.
2. If `app/package-lock.json` changed since the last nightly's commit, exit 2: SKIPPED "lockfile changed: run npm ci by hand". The script never installs a package (house rule 8a). If `node_modules` or the Electron binary is missing, exit 2 with the gate's TOOL_MISSING line.
3. Build the Release Host (`dotnet build src/NetSec.Host -c Release`). This is a build, not an install.
4. Run the full gate under `heavy_lock.py`, with the wait capped until 06:00. Past that, exit 2: SKIPPED, naming the lock holder. The scheduled task is set to "do not start a new instance", so nights never stack.
5. Append one ledger line per test unit to the ledger, and one summary line to `E:/dev/ns-state/nightly.md`: date, commit, N of M passed, escapes.
6. On a red, first rerun the red units once on the same head. A pass there is a flake: it is logged per the escape definition, and there is no bisect. A unit that is red again goes to the bisect (`tools/bisect_red.py`): `git bisect --first-parent` over main's merges since the last green nightly, running only the red units. On the first night, the base is the merge commit of this plan. The bisect records the PR that caused each red, and whether that PR merged on a passing picked run (an escape).
7. Exit codes are fixed: 0 green, 1 red, 2 SKIPPED (with the reason). A run that cannot finish never records PASS.

**Model on failure only.** When the exit code is 1 or 2, the script hands off to a model, the house rule "deterministic first, model on escalation":

- The model is the `triage-tier` policy in `tools/nightly.json`, set to `haiku` for now (Steve, 2026-11-09). The script resolves the name at run time, so a later change is one line.
- The script calls `claude -p --model <tier>` with one skill invocation and arguments (`nightly-triage <ledger line> <report path>`), never inline prompt text.
- The model reads the gate log, the ledger lines and the bisect result. It writes one triage note to `E:/dev/ns-state/nightly-triage-<date>.md`: the red test units, the PR that caused each one, and a one-line cause guess labelled as a guess.
- The model may only read files and write that one note. The script passes `--allowedTools "Read,Grep,Glob,Write(E:/dev/ns-state/nightly-triage-*.md)"` and `--disallowedTools "Bash,Edit,WebFetch,WebSearch"`. It has no git push, no merge, no other file edits, and no package installs.
- The gate log is untrusted text, because a test can print anything. With no Bash and no outbound tool, an instruction hidden in the log has no way to act.
- The credential is Steve's subscription login. The scheduled task's environment holds no `ANTHROPIC_API_KEY` (house rule: subscription over API, never fall over to a key).
- The pop happens without the model, through `popped()`. The model only explains.

## Decisions

1. Option A (Steve, 2026-11-09).
2. The default kind is platform. Only listed paths are product.
3. A pop takes effect at once. A sink goes through a PR.
4. The lesson and walk engines live in `src/NetSec.Core/Labs/`. `src/NetSec.Core/Labs/**` is product, with per-lab covers from coverlet, and the rest of Core stays platform (option A, signed off with the plan). This holds only if the spike shows the Labs map is stable across 2 runs. If it does not, all of Core stays platform, and kill condition 1 counts only app and Host branches (option B). Steve may still pick B outright.
5. The nightly run is a deterministic script. A model runs only on a red or a SKIPPED night, and only to write a triage note (Steve, 2026-11-09).
6. Regimen rule 2 changed in `~/.claude/agents/echo.md` (Steve, 2026-11-09).

## Steps

1. **Weed (before any sinking).** Echo runs the `test-anti-patterns` and `test-gap-analysis` passes over the suites. Tests that check nothing get deleted in their own PR, each with the reason. A test with no failure mode never sinks; it goes.
2. **Spike: the covers map.** For 5 Playwright specs and 5 C# test classes, build `covers` from V8 coverage, coverlet on the test process, and coverlet on the live Host process. Record whether each map is the same across 2 runs, and whether a Labs file maps to its lab's tests. Measure the machine's idle process count. The output goes in this plan before sign-off, and it settles decision 4 and the Host rule.
3. **Picker, manifest, lists and ledger**, with SKIP rows in the gate. Red first: a branch that touches a deep test's covered file must pick that test; a branch that touches a run-everything file must run everything; a new folder must run everything.
4. **Move rules, bisect, and the nightly task.**
5. **House rule change.** Done 2026-11-09: rule 2 of the test regimen (`~/.claude/agents/echo.md`) now reads "the picked tests on every gate, plus the full run nightly and at release", for repos with a picker.
6. **The `nightly-triage` skill.** A utility skill that the nightly script calls. It holds the triage steps and the note format. It is distilled from the first red nights triaged by hand, never drafted cold; until then the script writes the red list and the bisect result with no model note. Its regression set holds at least 3 past reds, with at least 1 where the right answer is "cause unknown".

## Accepted risks

1. A semantic merge conflict: two PRs, each green on its picks, that break together. Only the nightly run catches it, up to 24 h later.
2. A coverage map misses a path that a test reads in a way coverage cannot see and that no list names. The nightly run catches it, and the fix adds the path to a list.

## Non-goals

1. No agent decides a level or a kind by judgment.
2. No change to acceptance/ ownership. Echo still owns acceptance/ and its clauses.
3. No test deletion without a reason line in the PR.

## Boundary and failure routing

- Free: the picker, the manifest, the lists, the move rules, the nightly ledger, test deletions with reasons (each via PR and review).
- Needs Steve: creating the Windows scheduled task (registering it on his machine), any widening of the triage model's tools, and any change to the release sweep.
- A picker that cannot map a file runs everything (picker rule 7). A spike that cannot build a stable map keeps that area platform.

## Owners

- Kody: picker, manifest tooling, lists, ledger, nightly task, gate SKIP rows.
- Echo: weeding pass, move-rule tests, regimen text draft.
- Jared: review of each step.

## Anchor

The nightly full run is the anchor. It shares no code with the picker, and it runs every test on the same commit. An escape count above 0 means the picker or a list is wrong. The ledger sits outside every worktree and is append-only by convention. Any agent on this machine can still write to `E:/dev/ns-state`. Only `nightly` and `release` lines move a test, and only `nightly.ps1` and the release sweep write those kinds.
