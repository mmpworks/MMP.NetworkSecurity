# Logical clock on trace events: plan

Status: draft for the lead's sign-off. Owner: Richard. Date: 2026-11-08.

## The problem

Each side of a run writes its own trace stream, and the Host receives the streams through separate pumps. The order in which events from two sides reach the Host changes between runs of one seed. So "what each side knows" and the two-run view can show different orders for one seed. Nancy measured this over 80 runs (her issue holds the data).

## The goal

Every engine-stream event carries a logical clock. Two runs of one seed give every engine-stream event the same clock. The page orders by (clock, side) instead of by arrival.

## Kill condition

The work ends when this holds, and a reader can check it with no judgement: a Host test runs one seed 20 times, 10 of them with the machine under extra load, and every engine-stream event has the same clock in all 20 runs. The count is 20 of 20, recorded in `docs/_runs/` with its date.

## Prior art and constraints

1. `docs/learnings.md` item 3: TCP chunking changes between runs, and `wire.received` follows it. So socket events live on their own stream, `<streamId>/wire`, and runs are compared on the engine streams only. This plan keeps that rule. The clock goes on engine streams only.
2. Lamport, "Time, Clocks, and the Ordering of Events in a Distributed System" (1978), cited from recollection and not re-read for this plan: each process adds 1 per event, and a receive takes max(own, sender's) + 1. Our difference: the engines share no side channel, and the clock must not travel inside the protocol bytes. So the Host computes the clock from the streams it already receives.
3. The arithmetic: the largest session has a few hundred events (lesson 10 has 183). The clock is one integer per event, plus a small table per session. No storage or rate concern exists.

## The design

1. Where: `SessionManager.Write`, the one place every event of a session passes. The clock is written beside `seq` in the stored, saved and broadcast line, as `"clock": n`. No existing field changes.
2. Sides: one clock per engine stream (per actor). Wire streams (`<streamId>/wire`) get no clock of their own (decision 2 below).
3. Send and receive: an engine event of type `<protocol>.message.sent` from A to B takes the next ordinal on link A to B and records its clock. The k-th `<protocol>.message.received` at B from A is the receive of that k-th send. TCP keeps order on a link, so the ordinals match.
4. Rule: each engine event takes own + 1. A receive takes max(own, the matched send's clock) + 1.
5. A receive that reaches the Host before its send is held, and written when the send arrives (decision 1 below).

## Open decisions (the lead ranks these)

1. A receive whose send has not reached the Host yet.
   - A. Hold that one event until its send arrives. Then each stream's events stay in order, and only the receiving stream waits, for a few milliseconds. A receive is held only when the peer has an engine stream in this session; otherwise it is written at once with own + 1. My pick.
   - B. Write the event at once and send its clock later in a second frame. Nothing waits, but each consumer must merge two frames.
2. Wire events.
   - A. No clock. The page already draws from engine events and `wire.sent`. My pick, because a clock on a varying stream promises a fixed order it cannot keep.
   - B. Each wire event borrows its engine event's clock. The sent side has a clear engine event. The received side does not, because one read can hold part of a message or several messages.
3. Saved traces written before this change have no clock. The replay orders them by `seq`, as today. No rewrite of old files.

## Non-goals

1. No change to `wire.received` or to the per-read wire stream.
2. No clock inside protocol bytes, and no change to any engine.
3. No reordering of the live broadcast beyond the held receives in decision 1A.

## Boundary and failure routing

1. I may build, test and file a PR without asking once the lead signs off this plan.
2. The lead approves the decisions above, and any change to an existing field.
3. If the spike shows engine streams differ between same-seed runs, I stop and report. That would break the base assumption, and the plan changes before any build.

## Spike before build

Run lesson 1 and lesson 10 with one seed, 20 times each, 10 of them under extra load. Count the events per stream, and compare each engine stream's list of (type, message). Expected: the engine streams match in 20 of 20, and the wire streams may differ. The result goes in this file before the build starts.

## Anchor

The kill-condition test is written before the implementation: same seed, 20 runs, 10 under load, all engine-stream clocks equal. A second test pins the rule on a fixed two-side trace: a receive takes max(own, sender) + 1.
