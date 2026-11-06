# Bugfix: lesson 7's round trip count under load

Date: 2026-11-06. Author: Richard. Branch `fix/wire-sent-before-write`, off `cbebb1e`. Red `b8d993f`. Fix `c7d5c27`.

Conclusion: `EnginePump` logged `wire.sent` after the link write, so a peer could answer and log first. Under load, the session list then held a reply ahead of the message it answers, and lesson 7 showed 1 round trip where the run took 2. The pump now logs before the write.

Past finding: `2026-11-05-bugfix-tap-trace-order.md` names this mechanism for another test, and its forced delay shaped the test here. It changed this run: I forced the order with a slow link, and did not wait for a low-rate failure.

## Diagnosis

Read first: `lab.ts` `raceStats`, then `EnginePump.SendWire`. `raceStats` counts direction changes across two pumps, in session order. `SendWire` wrote to the sink only after the link write completed.

Falsifier: a swap must show as a reply ahead of its request in a saved trace, with nothing else different. It did. In a failing run, the server's `ServerHello` holds seq 10, and the client's `ClientHello` holds seq 16. The order is s, s, s, c, c, c, c, s, s, c, which is 3 direction changes, and `floor(3 / 2)` is 1.

Nancy's hypothesis was right on the class. The swap I saw is at `ClientHello`, not the last flight.

Cue: the counter failed only under load, and `raceStats` read one order across two pumps. `2026-11-05-bugfix-tap-trace-order.md` already said that the pump logs after the write.

## Proof

Real Host at a non-test port, 2 pinned cores, 8 burner threads under load. `/api/sessions/{id}/events` was read after each run.

| Run | Wrong count | Values |
|---|---|---|
| Main `cbebb1e`, no load (control) | 0 of 100 | 2 x100 |
| Main `cbebb1e`, under load | **3 of 100** | 2 x97, 1 x3 |
| Fix, under load | 0 of 100 | 2 x100 |
| Fix, under load, second run | 0 of 300 | 2 x300 |

At 3 in 100, 400 clean runs by chance is about 5 in a million. The forced test is the stronger proof:

| Test, slow link | Red `b8d993f`, both builds | Fix, both builds |
|---|---|---|
| `A_reply_is_never_logged_ahead_of_the_message_it_answers` | Failed | Passed |
| `A_message_is_in_the_trace_when_its_bytes_go_to_the_link` | Failed | Passed |

The app's own `raceStats`, bundled from `lab.ts`, gave 1 on all 3 saved failing traces, and 2 on the control trace. So the port in the probe is not the only witness.

Revert-check: with `EnginePump.cs` from `b8d993f`, the two tests fail again. `git diff b8d993f HEAD -- tests` is empty.

Gates on the fix:

- `dotnet test tests/NetSec.Tests -c Release`: 702 of 702 on both builds.
- `dotnet test tests/NetSec.Host.Tests -c Release`: 161 of 161.
- `pwsh acceptance/run.ps1 -Clauses A5,A6,A7,A8,A10,A10a,A11,A17.mock.golden-trace-equal`: 69 of 69, with the real peers and the golden clause.

Not run: `e2e/lesson-7.spec.ts`, which needs a turn on the test ports. The other acceptance groups.

## Scope ledger

Two behaviour changes. `wire.sent` reaches the sink before the link write, in place of after it. A failed write logs `wire.write.failed` on the wire stream (red `dc73c97`: 3 of 7 order tests fail on both builds, on the pump before this fix). The second change adds no event to a run with no failed write. `raceStats` does not change. The diagram's arrow order improves by the same change.

Not built: a client-stream rule in `raceStats`. It gave the right count on 200 of 200 traces, and it would leave the diagram wrong. The cause is in the pump.

## New hole

A write that fails now leaves a `wire.sent` for bytes that may not have left. A `wire.write.failed` event follows it, with the error code and the `wire.sent` event id, and such a run ends failed. The run's result alone cannot say this: when the engine has already failed, `Conclude` drops the link error, so a lost alert ends with no error. Jared found this. His harness gave `wire.sent Alert`, status Failed, error none, bytes sent 0. `acceptance/CONTRACT.md` line 61 says `wire.sent` is for "the bytes it wrote". That holds on a run that succeeds. Echo owns that text.

A tap log can now lag the trace, where before the trace lagged the tap. `#70`'s test waits for equal lengths, so either order passes.

## What the learner sees

| Branch | The learner sees |
|---|---|
| Normal run | "round trips before data" reads 2 for TLS 1.1 and 1 for TLS 1.3 |
| A slow machine | The same counts, and arrows in cause order |
| A write fails | The run ends failed. The message it tried stays in the list, its arrow still draws, and the event log shows `wire.write.failed` after it. `raceStats` still counts the message |

## Class sweep, closed

| Site | Result |
|---|---|
| `Bridge/CeDeviceFlow.cs:65` | Already logs before the write. This working sibling is the shape the fix took |
| `EnginePump.cs:313`, `wire.received` | Logged after the read, which is after the sender's log, so it stays in cause order |
| `EnginePump.cs:329`, engine events | Logged before `SendWire` |
| `Tls13Lab.cs:105`, `Lesson11Timing.cs:234`, `CeDeviceFlow.cs:143`, `:183` | No link write depends on them |

Gem check: no gem covers ordering a shared log across two writers. One use site, so I record no new gem. The preventative rule is in the code comment: log an effect before it can cause another writer's log.

## Observability seam (agent's own report)

What data would have made this one step? The session order and each pump's stream order, side by side, in the failed test's output. The spec printed only `Expected 2, received 1`.
