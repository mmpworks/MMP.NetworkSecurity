# Bugfix: a lost CE write logged no event

Date: 2026-11-06. Author: Richard. Branch `fix/ce-lost-write-event`, off `4ed98c8`. Red `e960e45`.

Conclusion: `ExternalForwardLink.Send` logged `wire.sent` and returned the write with no failure event. So `acceptance/CONTRACT.md` line 61 had an exception. It now logs `wire.write.failed` as `EnginePump` does.

Past finding: `2026-11-06-bugfix-wire-sent-order.md` added the event for the pump, and its review named this site.

## Diagnosis

Read first: `CeDeviceFlow.cs`, `ExternalForwardLink.Send` and its caller. Falsifier: a closed link must fault the write and leave no failure event. It did: `Sequence contains no matching element` on the `wire.write.failed` lookup, on both builds.

Cue: Jared's note on #162, reading `CONTRACT.md` line 61 against every site that writes `wire.sent`.

## Scope ledger

1. `ExternalForwardLink.Send` logs `wire.write.failed` on a failed write. The caller still sees the fault.
2. `TraceEventDraft.LostWrite` holds the event's fields, so the pump and the CE build one shape.

Not built: a check of `Send`'s fault in `CeDeviceFlow`. It observes the fault and goes on to `Receive`, so the result's code comes from the read. See the finding below.

## New hole

None found. A clean write logs the same one `wire.sent`, and the new test pins that.

## What the learner sees

| Branch | The learner sees |
|---|---|
| Normal run | No change |
| The CE's write fails | The run ends failed, and the event log shows `wire.write.failed` after the `wire.sent` |

## Class sweep, closed

`"wire.sent"` is written in 2 places in `src`: `EnginePump.SendWire` and `ExternalForwardLink.Send`. Both now log the event. The other `IDeviceLink` paths run through `EnginePump`.

## Finding, not fixed

`CeDeviceFlow` does not read the result of `link.Send`. After a lost write, `result.Code` names the failed read or a closed peer, and it never names the write. The trace now holds the write's failure. This changes a result code, so it is a separate decision.

## Observability seam (agent's own report)

What data would have made this one step? A list of the sites that write each event type. The sweep above is a grep today.
