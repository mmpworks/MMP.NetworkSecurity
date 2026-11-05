# MMP.NetworkSecurity: UX design

Author: Nancy (SPA engineer). Date: 2026-11-04. Status: ready to build (slice S8, with a thin version in S0).
Stack: Electron + Vue 3 + Vuetify + splitpanes + raw SVG, the same shell as `MMP.GasPumpSimulator/app/src`.

## Conclusion

1. One screen, five panels: lesson rail, live sequence diagram, byte inspector, secrets panel, tour panel.
2. Every pixel that moves comes from one trace event. The UI invents no bytes, no secrets, and no check results.
3. The tour sits on top of a step-gated engine. A step waits for the learner. Back and replay read the saved trace.
4. Five wow moments (section 2). Each names the event that drives it.
5. Disposition: build as written. Section 9 lists three calls that need Steve's eye in the morning.

## 0. What the UI reads from the Host

The PRD (D4) says every engine step emits a trace event. The UI needs these fields on each event. Host owner confirms them in S0.

| Field | Meaning |
|---|---|
| `seq` | Per-session sequence number, starts at 1 |
| `sessionId`, `seed` | The seed makes a replay produce the same bytes |
| `actor` | `client`, `server`, `ce`, `gateway`, `bank`, `reader` |
| `type` | Dotted name, for example `tls.record.sent`, `kex.share.computed`, `keys.installed`, `check.result` |
| `from`, `to` | Lane names, only on events that cross the wire |
| `wire` | Hex of the bytes on the wire (ciphertext when protected) |
| `plain` | Hex of the bytes before protection (glass-box only) |
| `fields[]` | `{name, offset, length, kind, visibleToWire, gloss}`. `kind` is one of `header`, `length`, `random`, `key`, `cipher`, `mac`, `id`, `data` |
| `secrets[]` | `{holder, name, hex, derivedFrom[]}`. Present only when `holder` gained the value at this event |
| `check` | `{name, result: pass or fail, code, detail}` |
| `waiting` | `{actor}` on `state.waiting` events: whom the engine waits for |
| `traceId`, `hop` | Span the bridge lesson across two hops |

Host commands the UI sends over the WebSocket: `session.start {lesson, seed, mode: step|run}`, `session.step`, `session.run`,
`session.pause`, `session.attack {atSeq, kind, offset, xor}`, `session.load {file}`, `session.save`.
Errors carry `code`, `message`, `retryable`, `requestId` (house rule).

## 1. Main layout

Minimum window 1280x800. Four regions in splitpanes. Panel sizes persist per user in `localStorage` (wrapped in try/catch).

```
+-----------------------------------------------------------------------------------------+
| TOP BAR: title | TRAINING ONLY | [Tour|Free play] | [Endpoints|Eavesdropper|Both] | speed | theme |
+--------+-------------------------------------------------+------------------------------+
| RAIL   | DIAGRAM (sequence, zoomable)         60% height | TOUR PANEL            55% h  |
| 220 px |                                                 |  title, text, Try it, Back/Next|
| 11     +-------------------------------------------------+------------------------------+
| lesson | BYTE INSPECTOR (hex + field spans)   40% height | SECRETS PANEL         45% h  |
| items  |                                                 |  one column per actor        |
+--------+-------------------------------------------------+------------------------------+
| STATUS BAR: session id, seed, event N of M, engine state (stepping / running / waiting for <actor>) |
+-----------------------------------------------------------------------------------------+
```

### 1.1 Top bar

| Item | Behavior | testid |
|---|---|---|
| TRAINING ONLY chip | Always visible on glass-box sessions. Amber outline, lock-off icon. Popover: "This engine shows its keys on purpose. Never use it with real secrets." Satisfies A16. When the OS transport is active the chip reads `OS TRANSPORT` and the secrets panel hides values | `training-only-label` |
| Mode switch | Tour or Free play | `mode-switch` |
| View switch | Endpoints, Eavesdropper, Both (split diagram) | `view-switch` |
| Speed | 0.5x, 1x, 2x. Scales animation time only. Does not change engine order | `speed-select` |
| Host chip | Green `engine connected`, amber `connecting`, red `engine offline` | `host-chip` |

### 1.2 Lesson rail

Eleven rows, one per lesson. Row = number, title, status dot (not started, in progress, finished), and a one-line subtitle in 8th grade words.
The rail collapses to numbers below 1100 px width. Finished means the learner reached the last tour step. A lock never blocks a lesson: all 11 are open.

### 1.3 Live sequence diagram

1. Lanes are vertical lines with a header chip: `Client | Server` for lessons 1 to 8 and 10. `CE device | Gateway | Server` for lesson 9. Lesson 6 uses `Reader | Bank`. Lesson 7 uses two stacked diagrams (section 2, moment 6).
2. Time flows downward. Row height 56 px. One arrow per `from`/`to` event. The label shows the message name and its byte count.
3. The diagram draws a row only after its event arrives. Nothing is drawn ahead of the engine. The `state.waiting` event draws a pulsing ring on the lane that holds the next move.
4. Arrow style: readable bytes use the readable color with a solid line. Protected bytes use the encrypted color with a hatched line. Fails use the fail color with a dashed outline and an X icon.
5. Packet chip: while an arrow animates, a chip shows the first 8 bytes and the total length, taken from `wire`. Duration 600 ms at 1x.
6. Clicking an arrow selects its event. The inspector and the secrets panel jump to that event. Keys `Up` and `Down` move the selection.
7. A check badge sits at the receiving lane when a `check` event follows. Pass is a check mark in the pass color. Fail is the red X plus the check name.

### 1.4 Byte inspector

1. Hex dump, 16 bytes per row, offset column, ASCII column. Virtualized. Records up to 16 KB render without lag.
2. Each parsed field is a colored span from `fields[]`. Span color follows `kind` (table in section 4). A field name label sits under the first byte of its span.
3. Hovering a span or its name in the field list highlights both, and shows the field's `gloss` in a popover.
4. A toggle shows `wire` or `plain`. Default is `wire` in Eavesdropper view and `plain` in Endpoints view.
5. A field list (right side of the inspector) shows name, offset, length, and decoded value. Clicking a row selects the bytes.
6. Byte selection plus the `Flip this byte` button starts an attack (section 7).
7. In Eavesdropper view the inspector parses only fields where `visibleToWire` is true. The rest is one block labeled `unreadable without the key (N bytes)`.

### 1.5 Secrets panel

1. One column per actor on screen. Each column lists the secrets that actor holds now.
2. A row appears only when a `secrets[]` entry names that holder at or before the selected event. Moving the selection back removes rows that did not exist yet.
3. A row shows name, first 8 bytes and last 4 bytes of the value, length, and `derivedFrom` chips. Click shows the full hex. Copy button on each row.
5. In Eavesdropper view the panel shows one column: `Eavesdropper`. It lists only public values (random numbers, key shares). It stays short, and that is the point.

### 1.6 Tour panel

Title, 2 to 4 short paragraphs, glossary terms underlined, a `Try it` block when the step has one, and the buttons `Back`, `Replay step`, `Next`. A progress line reads `Step 4 of 12`. Free play replaces the tour with the event log (section 3.4).

## 2. The cool moments

Each moment names the real event that drives it. No timer-only animation exists.

| # | Moment | What the learner sees | Driven by |
|---|---|---|---|
| 1 | **The scramble** | A record leaves the sender as readable bytes. At the instant `keys.installed` fires, the next `tls.record.sent` plays a per-byte morph: each byte flips through random glyphs and lands on its ciphertext value. The color changes from the readable blue to the encrypted amber and the hatch pattern fades in | `keys.installed`, then the next event that has both `plain` and `wire` of equal length |
| 2 | **Two views of one wire** | The `Endpoints / Eavesdropper` switch re-renders the same session. Endpoints show the message names and plain fields. Eavesdropper shows the same arrows, but the protected rows turn into amber noise with the label `unreadable`. A counter reads `Eve learned 3 of 7 messages` | `fields[].visibleToWire` and `wire` vs `plain` |
| 3 | **Two sides, one key** | Two 32-cell grids, one in each actor's column. Cells fill in as each side emits its `kex.secret.computed` event. When both values exist and are equal, thin lines tie cell to cell and the grids glow. For ML-KEM the decapsulating side fills later, so the learner watches the second side catch up. In the hybrid case, the grid has 64 cells: 32 from X25519 and 32 from ML-KEM | Two `secrets[]` entries with matching `hex`. The UI compares the two real values |
| 4 | **Break it, see the name** | Select a byte, press `Flip this byte`. The Host reruns the session with that tamper (same seed). The first check that fails lights red in the diagram, the check list, and the tour panel, with its name (`Finished verify_data`, `AEAD tag`, `HMAC compare`) and the alert code. The later rows show `session stopped` | `check` event with `result: fail` |
| 5 | **The key ladder with burned keys** | DUKPT lesson: a ladder of keys from the base key down to the transaction key. After each sale the used rungs get a char-and-crack animation and turn gray with the label `erased from reader memory`. The reader column shrinks. The bank column keeps the base key and re-derives any rung on demand | `dukpt.key.derived`, `dukpt.key.erased`. The reader state list comes from the Host |
| 6 | **Old vs new race** (lesson 7) | Two diagrams side by side, same clock. Counters: messages sent, round trips, bytes. TLS 1.3 needs fewer round trips. The learner can press `Run both` and watch the lanes advance together. Counts come from the two traces | Two sessions with the same start time |
| 7 | **The onion** (lesson 9) | One PIN travels CE to gateway to server. Three nested rectangles (PIN block locked by DUKPT, inside SSH, then inside TLS 1.3) peel at each hop. At the gateway the outer layer opens, and the inner PIN block stays closed with the label `gateway cannot open this` | `traceId` spans, `hop`, `fields` with nesting depth |

Rules for all moments:
1. `prefers-reduced-motion` turns every animation into a 150 ms fade plus a static outline.

## 3. Tour model

### 3.1 Step schema

Tour files live in `app/src/tours/lesson-NN.json`. One file per lesson. A test (A14) loads every file and fails on a dangling `bind`.

```json
{
  "id": "L5-S04",
  "lesson": 5,
  "title": "The server answers with its key share",
  "text": ["The server sends its half of the key exchange.", "It is 1,120 bytes. Part of it is a locked box made with ML-KEM."],
  "glossary": ["key-share", "ml-kem"],
  "bind": { "kind": "event", "eventType": "tls.handshake.sent", "match": { "actor": "server", "message": "ServerHello" } },
  "highlight": ["diagram:message=ServerHello", "inspector:field=key_share", "secrets:row=server.kem_shared_secret"],
  "tryIt": {
    "id": "L5-S04-T1",
    "label": "Switch to the eavesdropper view",
    "action": { "type": "set-view", "value": "eavesdropper" },
    "expect": { "type": "view", "value": "eavesdropper" }
  },
  "unlock": { "mode": "action", "ref": "L5-S04-T1" }
}
```

| Field | Rule |
|---|---|
| `id` | `L<lesson>-S<nn>`. Never reused. Playwright and saved progress use it |
| `text` | 1 to 4 strings, 1 to 3 sentences each. STE style. Tour text scores grade 8.9 or lower (A15) |
| `glossary` | Term ids that appear in `text`. Test: every `{{term:id}}` in text exists in `glossary.json` |
| `bind.kind` | `event` or `concept`. A `concept` step shows no live event. It names the lesson idea only. Test: a step with `bind.kind: event` must name an `eventType` that the engine can emit in that lesson |
| `bind.match` | Optional field filter on the event. The first event that fits is the one the step waits on |
| `highlight[]` | Grammar `<panel>:<kind>=<name>`. Panels: `diagram`, `inspector`, `secrets`, `rail`, `check`. Highlight draws a 2 px focus ring plus a numbered badge |
| `tryIt.action.type` | `set-view`, `flip-byte`, `run-attack`, `toggle-field`, `press-run`, `select-event` |
| `tryIt.expect` | What the UI must observe. For attacks: `{ "type": "check", "name": "Finished verify_data", "result": "fail" }` |
| `unlock.mode` | `event` (bound event arrived), `ack` (learner pressed Got it), `action` (try-it expected state seen), `check` (named check result seen) |
| `pause` | `after-bound-event` (default) or `none` (the engine keeps running through this step) |

### 3.2 The tour pauses the engine

1. A tour session starts with `mode: step`. The engine halts before each event until the UI sends `session.step`.
2. On entering a step, the UI sends `session.step` repeatedly until the bound event arrives. The UI waits on a round-trip per event, so each event draws as it arrives.
3. The engine halts after the bound event (`pause: after-bound-event`). The learner reads, inspects bytes, hovers terms.
4. `Next` enables when the step's `unlock` is met. A `Try it` step shows `Next` as disabled with the hint line `Do the try-it first`.
5. A disabled `Next` always has a one-line reason under the button. Test id `next-reason`.

### 3.3 Back and replay

1. Every event lands in the in-memory list and in the NDJSON session file. The tour cursor is an index into that list.
2. `Back` moves the cursor to the previous step's bound event. The UI redraws diagram, inspector, and secrets from the stored list. The engine is untouched.
3. `Next` past the end of the stored list asks the engine for more events.
5. A session saves on exit as `sessions/<lesson>-<seed>-<time>.ndjson`. `Open saved trace` loads it in replay mode. The status bar shows `REPLAY` in the info color. Replay is read-only: Try-it actions that need the engine are disabled with a reason.
6. An attack forks the session. The Host reruns the lesson with the same seed and the tamper. The fork opens in a tab labeled `attack: <check name>`. The original tab stays intact.

### 3.4 Free play

1. The tour panel becomes the event log: one row per event with seq, actor, type, and check badge. Filters: actor, type, checks only.
2. Controls: `Run`, `Pause`, `Step`, `Restart`, seed field, `Open saved trace`.
3. Every attack button for the lesson shows in an `Attacks` drawer (section 7).
4. Glossary popovers stay on. Highlights come only from the learner's selection.

## 4. Color, states, keyboard, zoom

### 4.1 Tokens

Pair for readable vs encrypted: blue and amber (Okabe-Ito family). Both pass for the common forms of color blindness. Color never carries meaning alone: encrypted bytes also carry a hatch pattern and the text label, and fails carry an X icon and a dashed outline.

| Token | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#0e1318` | `#f6f8fa` | App background |
| `--surface` | `#151c23` | `#ffffff` | Panels |
| `--text` | `#e6edf3` | `#1b2229` | Body text |
| `--readable` | `#56b4e9` | `#0072b2` | Readable bytes, plain arrows |
| `--encrypted` | `#e69f00` | `#a85a00` | Encrypted bytes, hatched arrows |
| `--secret` | `#b39dff` | `#6a4fc2` | Secret values and key chips |
| `--pass` | `#3fb950` | `#1a7f37` | Check passed (with check icon) |
| `--fail` | `#ff6b6b` | `#c4242f` | Check failed (with X icon, dashed outline) |
| `--focus` | `#ffffff` | `#000000` | 2 px focus ring |
| `--warn` | `#e0a82e` | `#8a6100` | TRAINING ONLY chip |

Field-span colors (`kind`): `header` gray, `length` teal `#009e73`, `random` sky `#56b4e9`, `key` violet (`--secret`), `cipher` amber (`--encrypted`), `mac` pink `#cc79a7`, `id` yellow `#f0e442` (dark) / `#8a7a00` (light), `data` white at 60 percent. Each span also gets a 2 px underline whose dash pattern differs by kind.

Contrast: body text and chips meet WCAG AA (4.5:1) in both themes. A test checks the tokens by script.
Vuetify themes: `nsDark`, `nsLight`. CSS variables live in `style.css` under `:root[data-theme]`, the same split as `theme.ts` in GasPumpSimulator.

### 4.2 Empty, loading, error

| State | Where | What shows | testid |
|---|---|---|---|
| Empty (no session) | Diagram and inspector | Lane headers for the chosen lesson, the line "Start the tour to see the first message", buttons `Start tour` and `Free play` | `empty-state` |
| Loading | Whole app on launch | Skeleton lanes, host chip amber, text "Starting the engine". After 8 s: "Still starting. Check that port 5180 is free" | `loading-state` |
| Check failed | Diagram, tour | Not an error. It is a result. Fail color plus name | `check-fail-badge` |
| Engine error | Banner under top bar | Message, stable `code`, `retryable`, `requestId`, buttons `Retry` (if retryable) and `Copy details`. The session list stays readable | `error-banner` |
| Host offline | Whole app | Red host chip, banner with `Retry`. The app keeps showing the last session in replay mode | `host-offline` |

### 4.3 Keyboard

| Key | Action |
|---|---|
| `Right` or `N` | Next step (when enabled) |
| `Left` or `B` | Back |
| `Space` | Step one engine event (free play), or Replay step (tour) |
| `R` | Run or pause |
| `Up` / `Down` | Select previous or next event in the diagram |
| `Tab` | Move through panels: rail, diagram, inspector, secrets, tour |
| `E` | Toggle Endpoints and Eavesdropper |
| `T` | Toggle Tour and Free play |
| `S` | Skip the current animation |
| `+` `-` `0` | Zoom in, out, fit (on the focused diagram or inspector) |
| `Arrow keys` with `Shift` | Pan the zoomed diagram |
| `F` | Open the focused panel in the lightbox. `Esc` closes it |
| `?` | Open the shortcut sheet |
| `Esc` | Close a popover, the lightbox, or the sheet |

All controls reach focus in a logical order, show a 2 px focus ring, and carry an `aria-label`. The diagram has an `aria-live="polite"` line that reads each new event ("Server sent ServerHello, 1,120 bytes").

### 4.4 Zoom (house rule: images on web pages zoom)

1. The diagram and the inspector zoom from 25 percent to 400 percent. Ctrl+wheel, pinch, buttons, and keys all work.
2. Drag pans. Double-click fits to the panel.
3. `F` opens the panel in a full-window lightbox with the same controls.

## 5. Glossary popovers

1. Source: `app/src/glossary.json`. Entry: `{ "id": "nonce", "term": "nonce", "short": "A number used only once.", "long": "..." }`.
2. `short` is one sentence, 20 words or fewer, grade 8 or lower. `long` is optional and shows under `More`.
3. Tour text marks terms as `{{term:nonce}}`. The renderer draws a dotted underline. Only the first use of a term in a step gets the underline.
4. Hover (300 ms delay) or focus opens the popover. `Esc` closes it. A tap works on touch. The popover never covers the term.
5. Seed list (about 45): AES, block, key, IV, nonce, ECB, CBC, GCM, tag, hash, MAC, HMAC, CMAC, KDF, HKDF, key share, X25519, ML-KEM, hybrid, ciphertext, plaintext, handshake, transcript, record, alert, certificate, CA, chain, signature, Ed25519, ML-DSA, TLS, SSH, host key, session key, DUKPT, KSN, BDK, PIN block, token, DPoP, mTLS, role, capability, constant-time, downgrade.
6. Test: every `{{term:id}}` and every `<Term id>` resolves. Every glossary `short` passes the grade script.

## 6. Stable `data-testid` names

Pattern: kebab-case. Lists use `-<n>` for index or `-<name>` for a stable key. The names never change after S8 lands.

| Area | testids |
|---|---|
| App | `app-root`, `host-chip`, `training-only-label`, `mode-switch`, `view-switch`, `speed-select`, `theme-select`, `status-bar`, `engine-state`, `replay-chip` |
| Rail | `lesson-rail`, `lesson-item-<1..11>`, `lesson-status-<1..11>` |
| Diagram | `diagram`, `diagram-lane-<actor>`, `diagram-message-<seq>`, `diagram-chip`, `diagram-check-<seq>`, `diagram-follow`, `diagram-zoom-in`, `diagram-zoom-out`, `diagram-zoom-fit`, `lightbox`, `lightbox-close` |
| Inspector | `inspector`, `inspector-toggle-wire-plain`, `inspector-byte-<offset>`, `inspector-span-<fieldName>`, `inspector-field-row-<fieldName>`, `flip-byte-button` |
| Secrets | `secrets-panel`, `secrets-col-<actor>`, `secret-row-<actor>-<name>`, `secret-reveal-<actor>-<name>`, `convergence-grid-<actor>`, `convergence-match` |
| Tour | `tour-panel`, `tour-step-id`, `tour-progress`, `tour-text`, `tour-try-it`, `tour-try-it-action`, `tour-back`, `tour-next`, `next-reason`, `tour-replay`, `tour-run-to-end` |
| Free play | `event-log`, `event-row-<seq>`, `event-filter-actor`, `event-filter-type`, `free-run`, `free-pause`, `free-step`, `free-restart`, `seed-input`, `open-trace` |
| Attacks | `attacks-drawer`, `attack-<attackId>`, `attack-result`, `check-fail-badge`, `check-pass-badge`, `check-name` |
| Glossary | `term-<id>`, `term-popover`, `term-popover-short` |
| States | `empty-state`, `loading-state`, `engine-waiting`, `error-banner`, `error-code`, `error-retry`, `host-offline` |
| Race and onion | `race-left`, `race-right`, `race-count-messages-<left|right>`, `race-count-roundtrips-<left|right>`, `onion-layer-<n>`, `key-ladder`, `key-rung-<n>`, `key-rung-erased-<n>` |

## 7. Attack buttons

1. Each lesson lists attacks in the `Attacks` drawer and inline in `Try it` blocks.
2. An attack sends `session.attack {atSeq, kind, offset, xor}`. Kinds: `flip-byte`, `replay-message`, `swap-field`, `drop-message`, `rewrite-field`, `reuse-nonce`.
3. The result view shows: attack name, the byte or field changed, the check that caught it (`check-name`), the engine's alert code, and a "what this protects" sentence.
4. If no check catches an attack, the result says so and names the lesson point (for example ECB leaks patterns, so no check exists). The button never hides that outcome.

## 8. Lessons: screen, wow, attacks, catching check

| # | Lesson | On screen | Wow moment | Attack buttons | Check that catches it |
|---|---|---|---|---|---|
| 1 | Secrets and locks (AES) | Client, Server. Image lab: picture in, ciphertext out. Inspector shows 16-byte blocks | Moment 1 on a text message. ECB picture keeps its outline, CBC and GCM look like noise | Use ECB. Flip a ciphertext bit in CBC. Flip a bit in GCM. Reuse a GCM nonce | ECB: none (block-repeat counter shows the leak). CBC flip: none (one block garbles, the next block flips one bit). GCM flip: `GCM tag`. Nonce reuse: `nonce reuse detector` (the engine event, shown as a warning) |
| 2 | Tamper seals (hash, MAC, HMAC, CMAC) | Message, seal, verifier. Four tabs, one per primitive | Moment 4 early: one flipped bit changes about half the hash bits, drawn as a 256-cell diff | Flip a message bit. Flip a tag bit. Extend a plain hash `H(key+msg)` | `HMAC compare`, `CMAC compare`. Extension attack works on plain hash and fails on HMAC (`HMAC compare`) |
| 3 | Agreeing in public (X25519, ML-KEM, hybrid) | Client, Server, Eavesdropper column. Key shares in the inspector | Moment 3: grids converge. Hybrid shows 64 cells. Key share sizes shown from events: 1,216 B client and 1,120 B server | Swap the server share. Flip a byte of the ML-KEM ciphertext | `key confirmation MAC`. ML-KEM gives no error on a bad ciphertext (implicit rejection), so the grids stop matching and confirmation catches it |
| 4 | Who are you (signatures, certificates) | Client, Server, training CA lane. Certificate fields in the inspector | A chain drawn as three linked cards. Flip a byte and the link breaks in red | Flip a cert byte. Expired cert. Wrong name. Unknown CA | `signature verify`, `validity window`, `name match`, `chain to trust anchor` |
| 5 | TLS 1.3 message by message | Client, Server. 12 tour steps. Full secrets ladder (early, handshake, application) | Moment 1 at ServerHello, moment 2 on the encrypted extensions, moment 3 on the hybrid secret | Flip a byte in Finished. Flip a record byte. Replace the key share. Tamper ML-KEM ciphertext | `Finished verify_data`, `AEAD tag` (bad_record_mac), `transcript hash`, `Finished verify_data` |
| 6 | Key per sale (DUKPT) | Reader, Bank. Key ladder in the secrets panel. KSN counter | Moment 5: rungs burn. Reader memory shrinks while the bank re-derives | Replay a sale (same KSN). Flip the PIN block. Ask the reader for a past key | `KSN already seen`, `PIN block format check`, `key not in reader state` |
| 7 | The old world (TLS 1.1) | Two stacked diagrams, 1.1 and 1.3, one clock | Moment 6: race with message and round trip counters | Rewrite ClientHello to offer only 1.1. Connect a 1.1 client to the modern server. Flip a 1.1 record byte | `downgrade sentinel` (server random ends in DOWNGRD), `protocol_version alert`, `record HMAC` |
| 8 | SSH | Client, Server. Host key card, key exchange, user auth, tunnel | Host key fingerprint pops up on first connect. A changed key stops the session | Change the host key. Flip a packet byte. Wrong user key | `known_hosts match`, `packet MAC`, `userauth signature verify` |
| 9 | The bridge | CE device, Gateway, Server. Trace id spans two hops | Moment 7: the onion. Gateway cannot open the PIN block | Tamper hop 1 (SSH). Tamper hop 2 (TLS). Flip the PIN block | `packet MAC` (hop 1), `AEAD tag` (hop 2), `PIN block MAC at bank` |
| 10 | Client proof and permission | Client, Server, Token issuer. Token and proof parsed in the inspector | A token splits into header, claims, signature, and the claims text reads aloud in everyday words | Remove the client cert. Replay a DPoP proof. Change a token claim. Use a capability not granted. Replay a passkey challenge | `bad_certificate alert`, `jti already used`, `token signature`, `permission check`, `challenge already used` |
| 11 | Unmanaged space (timing) | Attacker, Target. Two histograms: leaky and constant-time | The guess loop recovers a secret byte by byte against the leaky compare, and fails on the constant-time one. Times are measured numbers | Guess against leaky compare. Guess against constant-time compare | `constant-time compare` (flat timing) catches the guess. Lab shows the measured nanosecond spread, with the run's machine noted |

## 9. Calls I am least sure about

1. **Step granularity.** The tour steps the engine one trace event at a time. A TLS 1.3 handshake can emit dozens of events, and the learner may feel stuck on small ones. The alternative is to group events per step.
2. **Attack as a forked session.** The attack reruns the lesson with the same seed in a new tab. This keeps the engine true to its trace, but it costs a rerun and breaks the feel of "flip a byte on the wire right now".
3. **Eavesdropper view relies on `visibleToWire` from the engine.** The UI could guess from the record type, but that risks fake data. The engine must label each field, which adds work to S3 and S4.
