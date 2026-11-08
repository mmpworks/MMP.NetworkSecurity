# Logical clock on trace events: plan

Status: decisions 1, 2 and 3 ranked by the lead on 2026-11-08; Jared's 3 review items folded in; for Jared's second read before any code. Owner: Richard. Date: 2026-11-08.

## The problem

Each side of a run writes its own trace stream, and the Host receives the streams through separate pumps. The order in which events from two sides reach the Host changes between runs of one seed. So "what each side knows" and the two-run view can show different orders for one seed. Nancy measured this over 80 runs (her issue holds the data).

## The goal

Every engine-stream event carries a logical clock. Two runs of one seed give every engine-stream event the same clock. The page orders by (clock, side) instead of by arrival.

## Kill condition

The work ends when this holds, and a reader can check it with no judgement: a Host test runs one seed 20 times per case, 10 of them with the machine under extra load, and every engine-stream event has the same clock in all 20 runs. The cases are lessons 1, 7, 9, 10 and 11, the lesson 7 recording fork (`L7-decrypt-recording`, the attacker stream), a replay fork (`L6-replay-sale`), an inject fork (`L5-clear-close-notify`) and a drop fork (`L5-flip-record-length`). The count is 20 of 20 for each of the 9 cases, recorded in `docs/_runs/` with its date. The drop case reaches 20 of 20 after #309 (decision 3). The test prints the first differing entry per stream for any run that differs, so a rare race names itself.

## Prior art and constraints

1. `docs/learnings.md` item 3: TCP chunking changes between runs, and `wire.received` follows it. So socket events live on their own stream, `<streamId>/wire`, and runs are compared on the engine streams only. This plan keeps that rule. The clock goes on engine streams only.
2. Lamport, "Time, Clocks, and the Ordering of Events in a Distributed System" (1978), cited from recollection and not re-read for this plan: each process adds 1 per event, and a receive takes max(own, sender's) + 1. Our difference: the engines share no side channel, and the clock must not travel inside the protocol bytes. So the Host computes the clock from the streams it already receives.
3. The arithmetic: the largest session has a few hundred events (lesson 10 has 183). The clock is one integer per event, plus a small table per session. No storage or rate concern exists.

## The design

1. Where: `SessionManager.Write`, the one place every event of a session passes. The clock is written beside `seq` in the stored, saved and broadcast line, as `"clock": n`. No existing field changes.
2. Sides: one clock per engine stream (per actor). Wire streams (`<streamId>/wire`) get no clock of their own (decision 2 below).
3. Send and receive: engine events carry no `from` or `to`. An engine stream is named `<actor>/<connection>`. A link is an ordered pair (sender, receiver) on one connection name. An engine event whose type ends in `.sent` takes the next ordinal on its link and records its clock. The k-th event whose type ends in `.received` at the receiver is the receive of the k-th send. TCP keeps order on a connection, so the ordinals match. The match is by ordinal, never by message name: a send named "Alert" is received as "alert level 1, number 0".
   - A connection name may have more actors than 2, if only 2 of them write `.sent` or `.received` events on it. Lesson 7's `tls11` has client, server and attacker, and only client and server send or receive. Lesson 9's `bridge` has 4 actors, and none of them sends or receives on it; the gateway's two hops are the separate connections `ssh` and `tls13`.
   - If more than 2 actors write `.sent` or `.received` on one connection name, the receiver is ambiguous. That is an error, never a silent guess: the Host writes the events of that connection with own + 1 and `"unmatched": true`, and sends one `clock.link-ambiguous` frame naming the connection and its actors. A Host test runs every lesson and every attack fork and requires no such frame, so an ambiguous lesson cannot ship.
4. Rule: each engine event takes own + 1. A receive takes max(own, the matched send's clock) + 1.
5. A receive that reaches the Host before its send holds its whole engine stream, not only itself. The next event on the same stream needs own + 1, and own must include the receive's clock, so every later event of that stream waits behind the held receive. When the send arrives, the held events are written in stream order. Other streams keep flowing. `seq` is given at write, so a held event's `seq` is higher than the `seq` of events from other streams written while it waited. Within one stream, `seq` order and stream order stay the same. In the spike this never happened in 1,500 matched pairs, so the hold is a safety net.
6. The attacker is its own clock side. A message the attacker injects or replays is a send on the attacker's side, so a receive of it matches the attacker's send. Today the attacks change bytes inside the pump, and a replay is a second send by the client's own engine (`L6-replay-sale`), so no attacker stream sends yet. The rule is the seam for an attack that does.
7. A receive with no send by the end of the session is written with `"unmatched": true` and own + 1. It is never held past the session end, so a dropped or injected message cannot freeze the trace. The release runs in stream order: the unmatched receive is written first, and the events held behind it then take its clock as their base. A send with no receive needs no flag; the inject and drop forks each leave one in every run.
8. Events with no clock: wire events, and any event written outside an engine stream (for example `key.in-use` on the `keys` stream), carry no `clock`. The page places such an event right after the last engine event of the same side that came before it in that side's order, and sorts it there by (that clock, side). A `wire.sent` follows the engine event that produced it; a `wire.received` follows the last engine event of its side before it. An event before any engine event of its side (the `keys` stream at session start) sorts at clock 0. So the bytes grid and "What each side knows" never fall back to arrival order, and #305's interim rule can go.

## Decisions

1. A receive whose send has not reached the Host yet: A, hold that one event until its send arrives, with design items 6 and 7 (the attacker side, and "unmatched" at session end). Ranked by the lead, 2026-11-08. B was to write the event at once and send its clock in a later frame. What would change it: a receive reaching the Host before its send in practice, which the spike measured at 0 of 920.
2. Wire events: A, no clock. Ranked by the lead, 2026-11-08. A clock on a varying stream promises a fixed order it cannot keep.
3. The drop fork's tail race: A, fix the race first, in its own issue and PR (#309). Ranked by the lead, 2026-11-08, and Jared voted A. The kill condition then holds 20 of 20 for the drop fork, with no allowance. #309's diagnosis: both sides wait on the same read deadline, so either can time out first, and the deadline failure writes no trace event.
4. Saved traces written before this change have no clock. The replay orders them by `seq`, as today. No rewrite of old files.

## Non-goals

1. No change to `wire.received` or to the per-read wire stream.
2. No clock inside protocol bytes, and no change to any engine in this work. The tail race in decision 3 is its own issue.
3. No reordering of the live broadcast beyond the held receives in decision 1.

## Boundary and failure routing

1. I may build, test and file a PR without asking once the lead signs off this plan.
2. The lead approves the decisions above, and any change to an existing field.
3. If the spike shows engine streams differ between same-seed runs, I stop and report. That would break the base assumption, and the plan changes before any build.

## Spike before build

Run lesson 1 and lesson 10 with one seed, 20 times each, 10 of them under extra load. Count the events per stream, and compare each engine stream's list of (type, message). Expected: the engine streams match in 20 of 20, and the wire streams may differ. The result goes in this file before the build starts.

Result, 2026-11-08, seed 3, on main 0b4c3e1 (throwaway test `ClockSpikeTests` on local branch `spike/clock-counts`, commit noted in the PR):

| Lesson | Engine streams | Engine lists equal to run 1 | Wire event counts seen |
|---|---|---|---|
| 1 | 3 | 20 of 20 (10 idle, 10 under load) | server/aes/wire: 7, 6 or 5 idle; 3 or 5 under load. client/aes/wire: 7 in all 20 |
| 10 | 7 | 20 of 20 (10 idle, 10 under load) | client/auth-mtls/wire: 9 or 10 (12 in an earlier run); the other 5 wire streams fixed |

So the base assumption holds: engine streams repeat for one seed, idle and loaded, and wire streams do not. A first run of the spike reported 1 of 20, because the stream ids start with the session id. Stripping that prefix fixed the spike, not the product.

Second result, 2026-11-08, seed 3, on main 10bcd03, with the attack forks the lead asked for. 20 runs per case, 10 under load. Sends and receives are matched by (connection, sending actor) and ordinal (design item 3):

| Case | Engine lists equal to run 1 | Matched pairs | Receives before their send | Receives with no send | Sends with no receive |
|---|---|---|---|---|---|
| Lesson 1 | 20 of 20 | 140 | 0 | 0 | 0 |
| Lesson 10 | 20 of 20 | 460 | 0 | 0 | 0 |
| Lesson 11 (attacker actor) | 20 of 20 | 0 (its engines write no `.sent` or `.received` events) | 0 | 0 | 0 |
| Replay fork, `L6-replay-sale` | 20 of 20 | 60 | 0 | 0 | 0 |
| Inject fork, `L5-clear-close-notify` | 20 of 20 | 160 | 0 | 0 | 20 (1 per run: the swapped message) |
| Drop fork, `L5-flip-record-length` | 11 of 20 | 100 | 0 | 0 | 20 (1 per run: the message cut short) |

Notes:
1. The drop fork's 9 differing runs differ only in one event at the end of a stream: `check.result peer stayed until the end`, present in some runs and missing in others (1 idle run on the server stream, 4 loaded runs on the server stream, 4 loaded runs on the client stream). Every earlier event matched. Decision 3 covers it.
2. A first pass of this spike gave lesson 11 19 of 20 and the drop fork 8 of 20, without printing which entry differed. The rerun gave 20 of 20 and 11 of 20. Lesson 11 may hold a rare race too; the kill-condition test will show it if so.
3. The only name differences in matched pairs are cosmetic: a send named "Alert" is received as "alert level 1, number 0" (lesson 10, and the inject fork).
4. A first pass matched by `from` and `to`, which engine events do not carry, and its pair counts were wrong. Matching by connection fixed the spike, not the product.

Third result, 2026-11-08, seed 3, on main 10bcd03, for Jared's review item 2 (connections with more than 2 actors). 20 runs per case, 10 under load:

| Case | Engine lists equal to run 1 | Matched pairs | Receives before their send | Actors that write sends or receives, per connection |
|---|---|---|---|---|
| Lesson 7 | 20 of 20 | 440 | 0 | tls11: client, server. tls13: client, server |
| Lesson 7 recording fork, `L7-decrypt-recording` | 20 of 20 | 500 | 0 | tls11: client, server (the connection has 3 actors; the attacker writes no send or receive). tls11-ecdhe: client, server |
| Lesson 9 (gateway, 2 hops) | 20 of 20 | 580 | 0 | ssh: ce, gateway. tls13: gateway, server. bridge: 4 actors, none sends or receives |

Over the 3 spike results, 1,500 matched pairs had 0 receives reach the Host before their send.

## Anchor

The kill-condition test is written before the implementation: same seed, 20 runs per case for the 9 cases above, 10 under load, all engine-stream clocks equal, with the first differing entry printed for any run that differs. Fixed-trace tests pin the rules:
1. A receive takes max(own, sender) + 1.
2. A receive that arrives before its send holds its whole stream, and the stream is written in order when the send arrives, so no later event of that stream has a clock below the receive's.
3. A receive with no send is written at session end with `"unmatched": true`, and the events held behind it follow in stream order.
4. A send from the attacker side matches a receive like any other send.
5. A connection where 3 actors write sends or receives gives one `clock.link-ambiguous` frame and no guessed match.
6. A clockless event (wire, `keys`) sorts right after its side's last engine event before it, or at clock 0 before any.
