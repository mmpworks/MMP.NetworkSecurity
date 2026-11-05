# Lesson 9: names the bridge lab emits

Conclusion: the lab and its 3 attack rows exist, and lesson 9 stays `built: false` until its tour and UI land. `LabCatalog.Find(9)` returns null, and the rows wait in `AttackCatalog.Lesson9Unreleased`. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05.

`docs/lessons-1-3-names.md` holds the rules for arrows, binds, fields, and the end of a run. `docs/lesson-ssh-names.md` and the TLS 1.3 lessons hold each engine's own messages. This file lists what is new.

## 1. Lanes and streams

`GET /api/lessons/9` returns the lanes `ce`, `gateway`, `server`. The events below with actor `reader` or `bank` have no lane. UX section 3 names only the three lanes, so the UI decides where those two show.

| Stream | Actor | `hop` | What it holds |
|---|---|---|---|
| `<session>/reader/bridge` | `reader` | none | `pin.block.locked` |
| `<session>/ce/bridge` | `ce` | none | `ce.envelope.taken`, `ce.reply.relayed` |
| `<session>/ce/ssh` and `/wire` | `ce` | `hop1` | The SSH client |
| `<session>/gateway/ssh` and `/wire` | `gateway` | `hop1` | The SSH server |
| `<session>/gateway/tls13` and `/wire` | `gateway` | `hop2` | The TLS 1.3 client, group `X25519MLKEM768` |
| `<session>/gateway/bridge` | `gateway` | none | `gateway.envelope.relayed` |
| `<session>/server/tls13` and `/wire` | `server` | `hop2` | The TLS 1.3 server |
| `<session>/bank/bridge` | `bank` | none | `secret.derived`, `check.result` |

Every event carries the one `traceId`. Arrows on `hop1` name `ce` and `gateway`. Arrows on `hop2` name `gateway` and `server`.

## 2. A control run, in order

1. `pin.block.locked` (`reader`, message `PinEnvelope`). `plain` holds the envelope: the card number and the KSN in clear, and the PIN block locked.
2. `ce.envelope.taken` (`ce`). `plain` holds the same envelope.
3. Hop 1 opens: `VersionLine`, `KexInit`, `KexEcdhInit`, `KexEcdhReply`, `NewKeys`, `ServiceRequest`, `ServiceAccept`, `UserauthQuery`, `UserauthPkOk`, `UserauthSigned`, `UserauthSuccess`, `ChannelOpenTunnel`, `ChannelOpenConfirmation`.
4. `ChannelData` (`ce` to `gateway`) carries the envelope.
5. Hop 2 opens at that first byte: `ClientHello` and the TLS 1.3 flight.
6. `gateway.envelope.relayed` (`gateway`). `detail` is `PIN block: gateway cannot open this`.
7. `ApplicationData` (`gateway` to `server`) carries the envelope.
8. At the bank: `secret.derived` (`dukpt.pin-key`), then `check.result` `PIN block MAC at bank`.
9. The reply goes back the same way. `ce.reply.relayed` shows `accepted`.
10. `Disconnect` ends hop 1, and an `Alert` (close_notify) ends hop 2.

## 3. The onion (UX moment 7)

The lab emits no nesting depth field. UX section 7 asks for `fields` with nesting depth, and I chose to bind each layer to an event, because the three layers come from three events. Nancy, please say if this does not fit.

| `onion-layer-<n>` | Bind to | Shows |
|---|---|---|
| 1, PIN block locked by DUKPT | `pin.block.locked` | The inner rectangle. It stays closed until step 8 |
| 2, inside SSH | `ChannelData` on `hop1` | Opens at the gateway |
| 3, inside TLS 1.3 | `ApplicationData` on `hop2` | Opens at the server |

The label `gateway cannot open this` binds to `gateway.envelope.relayed`.

## 4. Attacks

| Attack | One change | Outcome | Code | Check |
|---|---|---|---|---|
| `L9-tamper-hop1` | One flipped bit in the first `ChannelData` | `Rejected` | `SSH_PACKET_MAC` | `packet MAC` |
| `L9-tamper-hop2` | One flipped bit in the first `ApplicationData` | `Rejected` | `TLS13_AEAD_TAG` | `AEAD tag` |
| `L9-flip-pin-block` | One flipped bit in the locked PIN block, inside the gateway, after SSH and before TLS | `Rejected` | `DUKPT_MAC_MISMATCH` | `PIN block MAC at bank` |

The third row is the one to teach with. Both hop checks pass, because each hop protected the bytes it was given. Only the bank sees the change.

A refusal before the MAC passes writes no claimed trace id into `BankDecision.TraceId`. The `detail` names the id as a claim.

## 5. What the tour must say

1. **Where the host key pin comes from.** The CE holds a `known_hosts` line for its gateway before it connects. `SshSetup.KnownHostLine` builds that line from the training key. A real device gets this line when it is provisioned, and a device with no line stops at `SSH_HOST_KEY_UNKNOWN`. The check in this lab is `known_hosts match`.
2. **The CE cannot check the bank's reply.** `BankReply` is one result byte and a code, with no MAC. The design gives the CE no key that could check it. So `CE-RESULT ok:true` means "the reply said yes". A forged reply byte reads the same. A real system signs the reply for the party that acts on it.
3. **What the CE build can and cannot do.** The CE's code path, `CeDeviceFlow`, reads the card number and the KSN and holds no key that opens the PIN block. The `NetSec.Core.dll` beside the CE exe still contains the DUKPT code and `TrainingKeySource`, and the training keys are public by design (D5). So the boundary this lab shows is which code each role runs. It is no claim about what a binary hides, and nothing here has run on CE.
4. **The PIN pad holds a loaded key.** `PinPadCore.InjectedInitialKey` stands for a key loader's work. The pad role reads no base key, and a test pins that. The bank derives the same key from the base key.
5. **What the gateway sees.** The card number, the KSN, and the trace id, all in clear inside SSH. It cannot open the PIN block.

## 6. The lab and the five processes

The lab runs the bridge's own code in one process, so a learner can step through it. `A10` runs the same `BridgeHopServers`, `CeDeviceFlow` and `BankHsmCore` as five processes. In that run a hop server learns the trace id from the first frame, so it holds its handshake events until then (`LateTraceSink`). In the lab the id is known at the start, so events flow as they happen.
