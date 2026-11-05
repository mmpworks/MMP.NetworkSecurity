# Bugfix: lost first step, 2026-11-05

Conclusion: `StepGate.Step()` dropped a step when no event waited at the gate. The gate now holds one such step for the next event.

Past finding: `2026-11-05-bugfix-tap-trace-order.md`. A forced run there was void because its build had failed, so this run checked that each build succeeded before it trusted a test result.

## Diagnosis

1. `session.started` goes out before the lab reaches its first event, and a lab can do slow work first: sockets, keys.
2. A `session.step` that arrives in that gap found an empty queue in `StepGate.Step()`, which did nothing and reported nothing.
3. The first event then waited at the gate with no step coming. The app's 3 s resend hid this.

Falsifier: if the step were lost anywhere else (the socket, the session lookup), the gate test would pass and the live test would still fail. The gate test failed on its own, and the fix to the gate alone turned the live test green.

## What the learner sees

| Branch | Before | After |
|---|---|---|
| Step arrives after the first event reached the gate | The event appears | The event appears |
| Step arrives before the first event reached the gate | Nothing for 3 s, until the app resends | The event appears |
| The app sends a second step in that gap | Nothing lost | One event appears, and the next event still waits |

## Scope ledger

| Change | File |
|---|---|
| A step with no event waiting is held for the next event. More such steps add nothing. `Run` and `Pause` clear it | `src/NetSec.Core/Io/EnginePump.cs` |

`StepGate` lives in Core, and the Host is its only product caller, through `Stepper(m)?.Step()`. Not built: no change to the Host, and no change to the app's resend.

Cue: the app's comment "A step command can be lost while an engine starts up", and a step handler whose `if` has no `else`.

## New-hole check

A held step lets one event pass with no later click. A step the app resends after its first step already released an event can release the next event early. That is a skipped pause, and the event still reaches the learner in order. The app's resend can now go away, which closes this.

## Proof

| Check | Result |
|---|---|
| Red commit `c6740bb`: gate tests | 2 of 6 failed on each build |
| Red commit `c6740bb`: live Host, lessons 0, 1, 3, 4, 6, 7, 8 | Lessons 0, 1 and 3 timed out at 20 s in that run. Which lessons lose the race varies by run |
| After the fix: gate tests | 6 of 6 on each build |
| After the fix: live Host, 7 lessons | 7 of 7 |
| After the fix: live Host at 100% CPU | 15 of 15 runs, 7 lessons per run |

No test file changed after the red commit.

## Class sweep

Closed. `StepGate` is the only gate that can hold, and `FreeRunGate` passes all. `session.run` sets the gate open with no waiter needed, so it has no gap. `session.pause` clears a held step.

## Observability seam (agent's own report)

Closing question: what data would have made this diagnosis one step? A count of steps that found no waiter, in the session's trace. A candidate only, not built.
