# Bugfix: Go tap test, 2026-11-05

Conclusion: main's #70 fixes the second cause of this flake, and it holds at every level I could force. I dropped my own stricter test change, because I could not show a failure it would prevent. This entry records the named mechanism and the proof.

Past finding: `2026-11-05-bugfix-pump-deadline.md`. Its forced replay and mutation checks shaped this run, so I forced the race at one line in place of waiting for it.

## Error

```
Assert.Equal() Failure: Collections differ
                          (pos 1403)
Expected: [..., 228, 128, 23, 3, 3, ...]
Actual:   [..., 228, 128]
```

Source: `ns-s4ssh/acceptance/.work/run-20261105-064133/trx-net48/net48.trx`, on a tree that holds #47 and not #70. `Expected` is the tap log. `Actual` is the trace. So the tap logged one more TLS record (`23 3 3`) than the trace held. #47 fixed a different error, `Win32Exception` from `Process.Kill`.

## Mechanism

1. `EnginePump.SendWire` writes the bytes to the socket, and it records `wire.sent` after the write completes.
2. So the tap can log a record before the trace holds it.
3. The test before #70 stopped waiting as soon as the tap was not behind the trace, and then compared. #70 waits for equal lengths.

Falsifier: a delay at that one line must fail the test before #70 every time, and it must leave #70 green. Both held.

Ruled out for this error: shared `go build` output, because a clash would fail inside `TapExe` and this error comes after both runs of bytes. A shared port, because `TapRun` listens on port 0.

## Proof

Each cell counts test runs passed. The test holds two tap runs.

| Check | Before #70 | #70 |
|---|---|---|
| Natural, 100% CPU, net48 | 29 of 30 | 40 of 40 |
| Natural, 100% CPU, net10.0 | 30 of 30 | Not run |
| 50 ms delay before `_sink.Write(sent)`, net48 | 0 of 5 | 10 of 10 (with the pause below) |
| 50 ms delay before `_sink.Write(sent)`, net10.0 | 0 of 5 | 10 of 10 (with the pause below) |
| 100 ms pause between the wait and the comparison, net48 and net10.0 | Not run | 30 of 30 |

The natural failure rate is low, so 40 clean runs alone do not prove a fix: at 1 failure in 30, a clean run of 40 happens by chance about 1 time in 4. The forced delay is the stronger proof.

## The stricter version I dropped

It waited for the tap to exit, so that the log was final, and then let the trace catch up.

| Check | Result |
|---|---|
| Natural, 100% CPU | 40 of 40 on net48, 30 of 30 on net10.0 |
| 50 ms delay | 5 of 5 on each build |
| Mutation: the trace drops short `wire.sent` records | Red |
| Mutation: one traced wire byte differs | Red |

Why I expected a gap in #70: equal lengths could be a passing moment before the last record, and the comparison reads the tap again later. I could not produce that failure. If the same error returns with the tap ahead at a record boundary, use this version.

Not run: the two mutations against #70. Its final `Assert.Equal` is the same line as in the version I dropped.

## Class sweep

| Site | Result |
|---|---|
| `tests/` | This is the only test that compares a tap log with a trace |
| `acceptance/groups/bridge/BridgeRun.cs` line 276 | `Thread.Sleep(1200)` before the A10a comparison. Same class, and a fixed sleep can lose this race under load. Not touched (D11). Change request sent to the lead |

## Other finding

`CS2012` on `src/NetSec.Core.NetCF/obj/Release/net35/NetSec.Core.dll` hit 1 of my builds and 1 A9 run after a source change. A `dotnet test -f net48` build log prints `NetSec.Core.NetCF ->` twice. Hypothesis, not proven: two project instances with different global properties compile into one `obj` folder at once.

## Observability seam (agent's own report)

Closing question: what data would have made this diagnosis one step? The TRX error text in the report of the lane that failed. I found it only by searching each worktree's `.work` folder.
