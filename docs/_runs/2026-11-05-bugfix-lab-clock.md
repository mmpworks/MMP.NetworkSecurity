# Bugfix: lesson 9 stamped events with the real clock

Date: 2026-11-05. Author: Richard. Branch `fix/lab9-clock`, off `230a18f`. Red `26c8a60`. Fix `6ecfe12`.

Past finding: `2026-11-05-bugfix-step-before-first-event.md`. Its void run came from a failed build, so this run read the first output for a compile error. The first try did fail to compile (CS0246), and it did not count as red.

## Diagnosis

`TransportRequest` had no clock. `GlassTlsChannel.cs:38,146,166`, `SshProbe.cs:88,92`, and `BridgeHops.cs:291` each fell back to `MonotonicClock`. Lesson 9 is the only lab that opens engines through a factory, so only lesson 9 differed.

Falsifier: run labs 0 to 10 with `FixedClock`. If lesson 9 stamps every event from that clock, the diagnosis is wrong. Result: 1 of 11 failed, naming these streams and no others:

```
these streams took another clock: clock/ce/ssh, clock/ce/ssh/wire, clock/gateway/bridge, clock/gateway/ssh, clock/gateway/ssh/wire, clock/gateway/tls13, clock/gateway/tls13/wire, clock/server/tls13, clock/server/tls13/wire
Failed!  - Failed:     1, Passed:    10, Skipped:     0, Total:    11 - NetSec.Tests.dll (net10.0)
```

Cue: Echo's golden dry run showed one field, `atMicros`, differing in one lab. No doc named it. Lesson 8 passes `c.Clock` (`Lesson08Ssh.cs:71,74`), which was the working sibling.

## Scope ledger

| Change | Behaviour |
|---|---|
| `TransportRequest.Clock`, `HopServerOptions.Clock` | Added. Null means the real clock, so `Node` and `CeDevice` are unchanged |
| `GlassTlsChannel`, `SshProbe.NewSession`, `BridgeHops`, `GlassSshLink`, `CeDeviceFlow` | Pass the clock on. `GlassSshLink` gains one constructor argument, and its only caller changes |
| `Lesson09Bridge.HopOptions` | Sets it to `c.Clock` |

Not built: nothing for `Probe` and its streams, since they serve no lab.

UX: no failure branch. A learner sees no change, because the Host's clock is the same real clock.

New-hole check: a Host run still passes `MonotonicClock` as `c.Clock`. No fallback was added on the lab path.

## Proof

| Check | Result |
|---|---|
| New test, on the fix | 11 of 11 pass, net10 |
| Revert-check, all source out | 1 of 11 fails, net10 |
| Neighbour mutation, one hop loses its clock | 1 of 11 fails, naming only `clock/gateway/ssh` and its wire stream |
| Test file diff, red to head | Empty |
| `tests/NetSec.Tests` | 630 of 630 on net10.0, 630 of 630 on net48 |
| `pwsh acceptance/run.ps1 -Clauses A10,A10a,A9` | 14 of 14 PASS, M = 259 |
| `python tools/layer_check.py src/NetSec.Core` | 120 files, 0 problems |

Sweep: closed. `git grep "new MonotonicClock"` under `src/NetSec.Core` leaves `Probe` and `SshProbe` probe streams, which serve no lab, the `EnginePump` overload with no clock, and the `?? new MonotonicClock()` defaults. The new test covers labs 0 to 10. Lesson 11 stays out, since it measures real time.

Lane: this fix touches 6 files, so the skill names the `bugfix-graph` workflow. I walked its steps inline, because the lead asked for a small PR and every change is one mechanical argument. So it had no separate refuter node. Same author wrote test and fix. Reviewer: none yet.

Observability seam: a same-seed compare in the builder suite would have found this at S5. Echo's golden clause now does that job.
