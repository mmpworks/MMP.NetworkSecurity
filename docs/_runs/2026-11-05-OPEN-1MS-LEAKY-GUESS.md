# Open: 1 ms failure of the lesson 11 leaky-guess test, 2026-11-05

Status: OPEN. Cause unknown. Recorded by Echo.

## What happened
1. Test: `Guess_against_the_leaky_compare_recovers_the_secret_and_fails_no_check` (`tests/NetSec.Tests/NativeTests.cs`).
2. One run failed after 1 ms on net48. It was the first `dotnet test` run in a fresh worktree (`E:\dev\ns-flake`). A full acceptance run was building in another tree at the same time.
3. The failure message was lost (a `grep` cut it off). The test prints `FailedCode` and `FailedCheck`, so the next occurrence names itself.

## What is known
1. The failure is not a timing miss. A timing miss needs the whole guess loop. Passing runs take 330 to 356 ms on net48.
2. PR #121 retries only `TimingNotSeparated`. A different code still fails at once. So #121 neither causes nor hides this failure.

## Candidate cause (unproven)
First use of the native library in a fresh tree. `NativeLib.Ensure()` builds `native\bin\x64\netsec_ct.dll` with `native\build.cmd` when the file is missing, then loads it with `LoadLibraryW`.

## Attempts to reproduce (all 0 failures)
| Attempt | Runs |
|---|---|
| Clean rebuild | 3 |
| `native\bin` deleted before each run | 6 |
| Same, with 40 `native\build.cmd` builds running in a second tree | 8 |
| Parallel loops (net48 x2, net10.0 x1) | 45 |
| Serial net48 runs | 12 |

## If it recurs
1. Copy the failing message first (`FailedCode`, `FailedCheck`, and the stack).
2. Note whether `native\bin\x64\netsec_ct.dll` existed before the run.
3. Send both to the lead.

Disposition: keep open until a second occurrence gives a message. No re-pin.
