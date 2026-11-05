# Bugfix: flipped-length test, 2026-11-05

Conclusion: the race was in the test. The product behaves correctly, so no product file changes. The test now fixes the order of the two deadlines and proves a named end on each side, in both orders.

Past finding: no past entries.

## Diagnosis

1. Two sides wait on a read after a length byte flips. The side whose deadline fires first reports `LINK_DEADLINE` and closes the link.
2. The other side reads that close, so its engine reports `PEER_CLOSED_EARLY`. The S0 test had equal deadlines and asserted `LINK_DEADLINE` on the server, so it failed when the client fired first.
3. Falsifier: a client forced to fire first must give the server `PEER_CLOSED_EARLY`. A throwaway test with the S0 assertion gave `Expected: "LINK_DEADLINE"`, `Actual: "PEER_CLOSED_EARLY"`, 1 of 1.
4. Main's #22 made the test stable with a 300 ms server deadline and a 5000 ms client deadline. That left the client's deadline unproven, and `Assert.NotNull` accepted any client error.

## Decision on the second side

`PEER_CLOSED_EARLY` is the correct outcome for the second side. That side did not time out. Its peer hung up. `LabPair.Named` already drops this code when a lab picks the error to report, so a lab reports the real failure in either order.

## Scope ledger

| Change | File |
|---|---|
| The test becomes a theory with two orders. Each order asserts the exact code on each side, and `read deadline` on the side that timed out | `tests/NetSec.Tests/CoreTests.cs` |
| New test: with equal deadlines, each side ends by name and at least one side names the deadline | `tests/NetSec.Tests/CoreTests.cs` |

| A second flake, found by this gate. `Process.Kill` can throw `Win32Exception` (`Access is denied`) when the process is already exiting. Main's #47 fixed it in `TapRun`. The bridge test's cleanup had the same shape, so it now catches the exception, and the existing 5 s wait follows. Seen once, in `TapRun`, with the stack as evidence. I could not force it on demand, so it has no red run | `tests/NetSec.Host.Tests/BridgeLiveTests.cs` |

Not built: no product change, and no change to `EnginePump` or `MemoryLink`. `src/NetSec.Host/CeProcess.cs` also calls `Kill`, and it is left alone because it is product code outside this flake.

Cue: the failure value, `PEER_CLOSED_EARLY` in place of `LINK_DEADLINE`, named the race. The S0 test had no doc naming it. #22 later named it in a comment.

## Proof

| Check | Result |
|---|---|
| Baseline | 3 of 3 on net10.0 and 3 of 3 on net48 |
| 100% CPU load, net10.0 | 30 of 30 runs, 90 of 90 test cases |
| 100% CPU load, net48 (CF binaries) | 20 of 20 runs, 60 of 60 test cases |
| Whole suite, quiet machine, with `--blame-hang-timeout 120s` | 12 of 12 runs on net10.0, 12 of 12 runs on net48, no hang |
| Mutation: the deadline reports `LINK_LOST` | 3 of 3 tests red |
| Mutation: the deadline never fires | 3 of 3 tests red, `the future did not finish in 20 s` |
| Mutation: a peer close is not named | 3 of 3 tests red, `the future did not finish in 20 s` |

Deviation from the bugfix steps: this PR has no red commit. The product was already correct, so nothing turns a committed failing test green. The replay above and the three mutations stand in for the red SHA and the revert-check.

## Class sweep

Closed. Each pair of pumps in `src/`:

| Site | Deadlines | Reads the second side's code? |
|---|---|---|
| `Labs/FrameEngine.cs` (`LabPair`) | Equal | Handled: `Named` drops `PEER_CLOSED_EARLY` and `LINK_LOST` |
| `Labs/Labs.cs` (`EchoLab`) | Equal | No lesson 0 row flips a length, so no row expects `LINK_DEADLINE` here |
| `CeDevice/Program.cs` socket loop | Equal, 15 s | Runs a clean echo, so no deadline fires |

## Observability seam (agent's own report)

Closing question: what data would have made this diagnosis one step? Each side's deadline start and fire time in the failure message. A candidate only, not built.
