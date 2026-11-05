# Bugfix: a fork's frames could come before session.forked

Date: 2026-11-05. Author: Richard. Branch `feat/v0`. Red `5ef5c55`.

Past finding: `2026-11-05-bugfix-lab-clock.md`. It held the rule to run a cheap control first, so I ran the failing test on clean `main` before blaming V0.

## Diagnosis

`HostLiveTests.Catalog_attack_forks_with_the_same_seed_and_names_the_check` failed once on `feat/v0`. It is no V0 fault: alone, it passed 8 of 8 on `feat/v0` and 7 of 8 on `main` at `892ea52`.

`HostSocket.Attack` sent `session.forked` after `Begin` returned, and the lab had already started by then. So the fork's own frames could pass it. `CONTRACT.md` 5.2 gives the order as `session.started`, `session.forked`, `trace`, `session.finished`. When a fast lab finished first, a client that stops reading at `session.finished` never saw `session.forked`.

Falsifier: the first frame after `session.started` must be `session.forked`. Without the fix it reads `trace` every time, so the order is wrong on each run, and the failure seen was only its rare visible form.

## A pin that did not work

My first test, `3235ffa`, repeated the attack 40 times and looked for `session.forked` anywhere before `session.finished`. It passed with and without the fix, because the race shows on a cold Host and the loop warms it. That commit is not a red. The test now asserts the first frame, and this form is red on every run without the fix.

## Scope ledger

| Change | Behaviour |
|---|---|
| `HostSocket.Begin` takes an `afterStarted` action, run inside the announce step | `session.forked` now goes before the lab starts |
| `Begin` returns nothing | Its one reader of the result is gone |

Not built: nothing for `session.started`, which already went first.

Cue: `Assert.Contains() Failure` on the `session.forked` frame, at 37 ms, on the one run the race lost.

## Proof

| Check | Result |
|---|---|
| Red, no fix | Failed 2 of 2: `Expected: "session.forked"`, `Actual: "trace"` |
| Fix | Passed 3 of 3 |
| Sweep | `session.forked` has one send. `session.started` is sent from the announce step, and nothing else follows `Begin` |

Observability seam: a test on frame order would have caught this at S0. The race itself stayed hidden because `UntilFinished` reads only to the end.

Reviewer: none yet. It touches a shared path, so Jared re-checks it.
