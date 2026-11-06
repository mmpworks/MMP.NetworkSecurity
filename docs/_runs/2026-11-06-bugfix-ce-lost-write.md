# Bugfix: a lost CE write logged no event

Date: 2026-11-06. Author: Richard. Branch `fix/ce-lost-write-event`, off `4ed98c8`. Red `e960e45` and `1f34908`.

Conclusion: `ExternalForwardLink.Send` logged `wire.sent` and returned the write with no failure event. So `acceptance/CONTRACT.md` line 61 had an exception. It now logs `wire.write.failed` as `EnginePump` does. `CeDeviceFlow` also went on to read after a lost write, so the result named the wrong cause or the run waited out its limit. It now stops and names the write.

Past finding: `2026-11-06-bugfix-wire-sent-order.md` added the event for the pump, and its review named this site.

## Diagnosis

Read first: `CeDeviceFlow.cs`, `ExternalForwardLink.Send` and its caller. Falsifier: a closed link must fault the write and leave no failure event. It did: `Sequence contains no matching element` on the `wire.write.failed` lookup, on both builds.

Cue: Jared's note on #162, reading `CONTRACT.md` line 61 against every site that writes `wire.sent`.

## Scope ledger

1. `ExternalForwardLink.Send` logs `wire.write.failed` on a failed write. The caller still sees the fault.
2. `TraceEventDraft.LostWrite` holds the event's fields, so the pump and the CE build one shape.
3. `CeDeviceFlow` reads the result of `link.Send`. A lost write ends the relay, closes both sides, and sets `result.Code` from the write. Jared asked for this in the same PR.
4. `CeRunOptions.Link` lets a test hand the flow a link. Null means `LinkKind` picks, so no caller changes.

## New hole

None found. A clean write logs the same one `wire.sent`, and the new test pins that.

## What the learner sees

| Branch | The learner sees |
|---|---|
| Normal run | No change |
| The CE's write fails | The run ends failed at once, its result names the lost link, and the event log shows `wire.write.failed` after the `wire.sent` |

## Class sweep, closed

`"wire.sent"` is written in 2 places in `src`: `EnginePump.SendWire` and `ExternalForwardLink.Send`. Both now log the event. The other `IDeviceLink` paths run through `EnginePump`.

## Observability seam (agent's own report)

What data would have made this one step? A list of the sites that write each event type. The sweep above is a grep today.
