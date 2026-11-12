# S0: the 43 bench rows of AO-0 are closed (2026-11-12)

Conclusion: `AO-0.row-list-matches` reads PASS at slice S0. 209 of 209 rows match `acceptance/ao-rows.tsv`.

## The run

| Item | Value |
|---|---|
| Head of the run | c6e1c1ba55e632c36805b09da8ba97e1c9464f11 (the head of PR #430). The merge of #430 (aac0e8b) has the same tree: `git diff --stat c6e1c1b aac0e8b` prints nothing |
| Command | `acceptance/run.ps1 -AoSlice S0 -Clauses AO,<18 SELF clauses> -AoBenchReport <folder>/ao-bench.json`, through `tools/heavy_lock.py` |
| Run report | `docs/_runs/acceptance-20261112-083150.md` and `.json` |
| Bench report that the run read | `docs/_runs/2026-11-12-S0-ao-bench.json` (the run read it under the name `ao-bench.json`) |
| SHA-256 of the bench report | `436795e73284cb257ae245e552ee1dce740868caf2d70ae949151a72058add85` (7401 bytes) |
| `commit` field of the bench report | `46b2a410a2dda99f823fc003f13d65c58e5bbe56`, the commit of the tag `bench-s0-46b2a41` |

Result lines of the run:

```
145 of 248 clauses PASS (32 FAIL, 71 NOT RUN); M = 622
self-checks: 18 of 18 PASS
```

The detail of `AO-0.row-list-matches`, from the field `detail` of that row in `docs/_runs/acceptance-20261112-083150.json` (the `.md` report prints no detail for a PASS row):

```
209 of 209 rows match the row list for slice S0 Bench report: ao-bench.json (the report's commit 46b2a410a2dda99f823fc003f13d65c58e5bbe56 has the measured code and data of the head (src/NetSec.Core, src/NetSec.Core.NetCF, src/AsyncProxy.Local, src/AsyncProxy.Local.NetCF, acceptance/groups/algo/Frozen, Directory.Build.props, Directory.Build.targets, src/Directory.Build.props, src/Directory.Build.targets, Directory.Packages.props, global.json, NuGet.config, bench; bench/files by content)).
```

## The 43 rows

| Rows | Count | Before | Now |
|---|---|---|---|
| AO-6 speed rows (source: bench) | 15 | absent from a run with no bench report | match the row list, judged from the numbers of the bench report |
| AO-9 `.time` rows (source: bench) | 14 | absent from a run with no bench report | match the row list, judged from the numbers of the bench report |
| AO-9 file rows (source: suite) | 14 | NOT RUN `AO9_FILES_ABSENT` | PASS |

15 + 14 + 14 = 43. Before this run 166 of 209 rows matched.

## What is not PASS, and why that is correct at S0

Each row below has the state that the row list names for slice S0. So the run exits with code 1, and AO-0 is PASS.

| State | Count | Rows |
|---|---|---|
| FAIL `AO5_ALLOCATES` | 29 | allocation rows that later slices close |
| FAIL `AO_TABLE_BUILT_AT_STARTUP` | 2 | `AO-3.aes.no-startup-build` on net10 and cf |
| FAIL `AO_WALK_CALLS_AESKEY_HELPER` | 1 | `AO-7.walk-calls-only-block-entries` |
| NOT RUN `PRODUCT_MISSING` | 67 | forms that later slices add |
| NOT RUN `NO_TABLES` | 4 | table rows of later slices |

## How to check

1. `git cat-file blob HEAD:docs/_runs/2026-11-12-S0-ao-bench.json | sha256sum` gives the SHA-256 above.
2. `git rev-parse 46b2a410a2dda99f823fc003f13d65c58e5bbe56^{commit}` resolves, and `git ls-remote origin refs/tags/bench-s0-46b2a41` names the same commit.
3. A new run with `-AoBenchReport docs/_runs/2026-11-12-S0-ao-bench.json` on a head with the same measured code gives the same AO-0 detail, with that file name.

## Limits

1. The bench report states its commit. The suite compares the measured code and data of that commit with the head. It cannot prove that the benchmark ran on that commit.
2. The speed numbers are recorded. One ratio is judged, from slice S1: `AO-6.aes-block.net10`.
3. The run report holds the folder of the worktree as a drive path, as each run report before the change that makes those paths relative.

## Disposition

The S0 bench rows are closed. The next change under the measured paths makes this bench report stale, and the bench rows then read FAIL `AO_BENCH_OTHER_COMMIT` until a new report exists.
