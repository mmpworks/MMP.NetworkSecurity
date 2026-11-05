# Learnings

Each correction goes here, newest slice last. Later slices read this file first.

## S0

1. **A CF exe needs `GenerateSupportedRuntime=false` and an `App.config` that names v4.0.** The SDK default writes `supportedRuntime v2.0.50727`. On this machine that exe printed nothing and exited 0, which reads as success. The Host and the tests require the `CE-READY` line for this reason.
2. **Only socket events carry `Wire`.** A10a joins every `wire` field of the client actor by direction and compares to the tap. So the engine event (`echo.message.sent`) carries `Plain` and `Fields`, and the pump's `wire.sent` and `wire.received` carry `Wire`, `From`, and `To`. The program design first said an engine event carries `Wire`. That shape would double the bytes. The design's "skips the gate" line for `wire.sent` is also dropped, because the tour binds to `wire.sent` and must pause on it.
3. **Socket events have their own stream, `<streamId>/wire`.** TCP chunking changes between runs, and `wire.received` follows it. The engine stream stays fixed across same-seed reruns, and a tamper plan addresses that stream. Compare runs on the engine streams only.
4. **`state.waiting` fires on a state change, never per `Feed`.** One event per `Feed` would make the engine's sequence numbers follow TCP chunking.
5. **`EngineOutput` holds `Items`, one event with its optional wire bytes.** The design had separate `Wire` and `Events`. The gate must hold each message and its bytes together, so the pump writes the bytes right after the event passes. `Wire` and `Events` stay as read-only views.
6. **Machine cannot name `AppChunk`, because the contract keeps it in Io.** `EngineOutput.App` holds `Machine.DeliveredChunk`, and the pump turns it into `AppChunk`.
7. **`tools/layer_check.py` carries two named exceptions from the contract:** `Io` names `NetSec.Bridge.DeviceProfile` by full name, and `Machine/IStepGate.cs` uses MMP.AsyncProxy.
8. **A test project reference to a CF project needs `SetTargetFramework="TargetFramework=net35"`.** `SkipGetTargetFrameworkProperties` leaves the test's own TFM on the build, and restore fails with NETSDK1005.
9. **`--socket-loop` closed the S0 spike.** `CE-RESULT` shows all four Begin pairs ran on the CF binaries on net48. The Compact Framework runtime itself has run nothing.
10. **`NetSec.Node` is not in S0.** `acceptance/run.ps1` reports the bridge group NOT RUN PRODUCT_MISSING until S5.
11. **A flipped length byte leaves a receiver waiting forever, so every real engine lesson (S3 on) needs a read timeout that ends in a named error.** The length promises bytes that never come, and no check runs. In free run the pump's deadline ends the wait with `LINK_DEADLINE` (`EchoLab` uses 30 s, and a test pins the code). In step mode the pump has no deadline, because a learner can read for an hour, so that wait still has no end. S3 must decide who ends it. A deadline in the engine's waiting state, counted only while the gate is open, is the first candidate.
12. **The toy is lesson 0 and sits outside `GET /api/lessons`, which holds lessons 1 to 11 (lead's ruling).** `session.start` accepts 0. `GET /api/lessons/0` gives its row.

## S1

1. **The `prim` group compiles as one program, so A1 and A2 stay NOT RUN until every Crypto type exists.** `Subject.Product.cs` names all of section 2.3. A partial Crypto folder fails the compile, and all 64 clauses report PRODUCT_MISSING, including the primitives that work. To read a partial result, add the rest of `acceptance/contract/Crypto.cs` as an uncommitted file (its bodies throw `NotImplementedException`, which maps to NOT RUN), run the clauses, and delete the file. The full gate reports the acceptance step as FAIL until both S1 lanes merge.
2. **The `FromBytes`, `Ek`, and `Dk` names hold, not `FromBigEndian` or `EncapsulationKey`.** The acceptance suite changed these names in `fdfcf81`. Read the merged `acceptance/contract/Crypto.cs` before you code to an older `CONTRACT.md` line.
3. **`X25519.Mult` does not refuse an all-zero result.** RFC 7748 leaves that check to the protocol. S3 must add it to the TLS 1.3 key share and S4 to the SSH exchange.
4. **`Ed25519.Verify` accepts a small-order public key.** A public key at y = 1 with R = B and S = 1 verifies for any message. RFC 8032 allows this. A protocol that needs a stronger rule adds its own check. `Verify` refuses a wrong length, S at or above L, a public key with y at or above p, a y with no square root, x = 0 with the sign bit set (RFC 8032 section 5.1.3 step 4), and an R that differs in bytes from the computed value. Go accepts the x = 0 case with the sign bit set, so a Go referee cannot catch it. A builder test pins it.
5. **`RsaPrivate` holds n and d only, so it runs the full-size exponent.** Parsing a PKCS#8 key can drop the CRT values. On a real device this makes a private operation slower than a CRT one by a factor of about 4 (standard estimate, not measured here).
6. **A2 tests valid ML-KEM exchanges only.** Implicit rejection and the key checks are reached by 36 NIST ACVP records in `tests/NetSec.Tests/vectors/mlkem768-acvp.txt`.
7. **For S4: `DhGroup14` returns 256 fixed bytes, and SSH hashes e, f, and K as mpints.** Strip the leading zeros, and add one 00 byte when the top bit is set. A value with a leading zero byte comes about 1 session in 256, so a run with no conversion can pass by luck. Test both forms: a value with a leading zero, and a value with the top bit set.
8. **For S4: an even RSA modulus reaches `BigUInt.ModPow` as an unnamed `ArgumentException`.** SSH host keys come from the wire, so S4 needs a named error before that call.
9. **For S4: `Pkcs1.VerifySha1` and `VerifySha256` throw `RSA_MESSAGE_TOO_LONG` on a modulus too short for the digest.** Other bad input returns false. S4 must catch this code when the key comes from the wire.

## Lessons 1 to 3

1. **Each side of a lab needs its own random stream.** Two pumps draw in an order the threads choose, so one shared stream gives different bytes on a same-seed rerun. `LabPair.Fork` draws a seed per side before the pumps start. Fork matching (`atSeq`) depends on this.
2. **A rule reads a value only through `FrameSession.Secret`, and `Effect.Secret` stores it.** The interpreter calls `Remember`, so a rule stays free of side effects except `Draw`, which reads the side's random stream in rule order.

## S2

1. **`openssl genpkey -outform DER` on OpenSSL 3.5.7 wrote a traditional `RSAPrivateKey`, not PKCS#8.** CONTRACT rule 5 needs `PrivateKeyInfo`. Run `openssl pkcs8 -topk8 -nocrypt` after it. `An_rsa_key_is_pkcs8_with_its_matching_spki` pins the format on both builds.
2. **`TrainingKeySource.Find` throws `TRAINING_KEY_UNKNOWN` for an unknown id.** It never returns null. A symmetric key's `CopyPublic` gives an empty array.
3. **`DukptPinPad.Next` uses a new counter on each call (CONTRACT.md).** The S5 `PinEnvelope` holds one KSN, a PIN block, and a MAC. So S5 needs both keys under one counter and must add a method to the pad that returns several working keys for one counter. The derivation already allows it: `DukptDerivation.Working` takes the usage per call.
4. **Lesson 6 has no MAC on the wire, by the UX row.** A flipped PIN block must reach `PIN block format check`, and a MAC would catch it first. `DUKPT_MAC_MISMATCH` stays for S5.
5. **`held` does not fall on every sale.** A sale erases one register and can fill lower ones with child keys: 32 after the load, then 31, 31, 30, 31. UX moment 5 says "the reader column shrinks". The lab reports the true count, and the tour must not promise a steady fall.
6. **The one-bit limit of 16 is from recollection of X9.24-3, which is paid.** The free vectors do not state it. Both sides agree past it in `DukptTests`, because the bank walks any counter.
7. **`DUKPT_COUNTER_EXHAUSTED` needs a pad that starts late.** Sales alone need about 2^31 calls to reach it. An internal constructor starts a pad at counter `0xFFFF0000`, and `NetSec.Tests` sees it through `InternalsVisibleTo`.
8. **`PumpTests.A_flipped_length_byte_...` raced.** Two 300 ms deadlines, so the client could close first, and the server then reported `PEER_CLOSED_EARLY`. It failed 1 of 2 gate runs. The server's deadline now comes first. A test with two deadlines must say which one ends first.
9. **The lab's reader session holds no base key.** Only `BankSession` holds it, and a test scans the reader's trace for it. S5 keeps this shape across processes (D13).
10. **A test under `#if NET` in `tests/NetSec.Tests` turns A9 red.** `A9.cf.same-suite-passes-on-net48-skips-pinned` compares the net10.0 and net48 test sets. PR #13 did this and blocked every lane. A BCL-only check goes in `tests/NetSec.Host.Tests`, which runs on net10.0 only. Run `pwsh acceptance/run.ps1 -Clauses A9` on every PR that adds a test.
11. **Record a KSN only after the sale passes every check (Jared's review of PR #22).** A ledger that records first lets a forged block under the next KSN burn it, and the real sale then gets `DUKPT_KSN_REPLAY`. `DukptBank.OpenPinSale` holds this order. S5: `Bank-HSM` checks the MAC first, then calls `OpenPinSale`.
12. **A trace event states what the code did.** The lab reported `dukpt.initial` as erased and only dropped a reference. `Lesson06Dukpt.LoadReader` now clears the array before the event, and the trace holds its own declared copy. The managed-heap caveat never excuses skipping the clear.
13. **Do not clone keys to count them.** `HeldKeys` makes uncleared copies, so the lab reads `HeldCount`. Use `HeldKeys` only where a caller needs the bytes.
14. **Open question: strength of a derived key.** `DukptDerivation.Working` lets an AES-128 derivation key make an AES-256 working key. A reviewer recalls a rule against a derived key stronger than its parent. X9.24-3 is paid, so this is unverified, and the code does not refuse it.

## S3

1. **Decision: the read deadline counts only while the gate holds no event.** This closes S0 item 11. `EnginePump` restarts its clock while `StepGate.IsHolding` is true, so a learner can read one event for an hour. A read that stays open with nothing at the gate has no one left to wake it, and `LINK_DEADLINE` ends it, in free run and in step mode. `LabPair` now passes 30 s on both gates. A gate with no `IGateState` keeps the plain deadline. S5: `RemoteStepGate` must implement `IGateState`, or a node process in step mode gets a deadline that ignores the learner.
2. **`X25519.Mult` all-zero results are refused in `KeyExchange`, on both roles.** The code is `TLS13_X25519_ZERO`. S4 still owes the same check in the SSH exchange.
3. **A rule keeps a value with `Effect.Store(Action)`.** The rule returns the closure and the interpreter runs it, so the rule stays free of side effects. `Effect.Secret` plus `Remember` from lessons 1 to 3 holds byte arrays only. TLS keeps a suite and a parsed certificate too. It emits no trace event.
4. **A protocol with more than one kind of message uses `Effect.SendAs` and the 6-argument `InboundMessage`.** The trace type then names the kind: `tls.handshake.sent`, `tls.record.sent`, `tls.alert.sent`.
5. **A key share or ML-KEM ciphertext tamper is caught by the AEAD tag, not by Finished.** `ux-design.md` section 8 names `transcript hash` and `Finished verify_data`. The two sides hold different keys, so the first sealed record fails first. `docs/lessons-4-5-names.md` holds the corrected rows. A Finished flip must happen at the Plain tamper point, because a Wire flip fails the tag first.
6. **`ProbeRequest.Tamper` keeps its contract type `NetSec.Labs.TamperPlan`, which sits above `Io`.** `tools/layer_check.py` now names it as the second full-name exception, and it fails on any other `NetSec.Labs` name in `Io`.
7. **Lesson 4 and 5 attack rows use fixed byte offsets.** `Tls13Lab` lists the layout beside each constant. A change to the ClientHello extension order or the server name moves them, and `Every_attack_in_the_catalog_is_caught_by_its_named_check_beside_the_control` fails.
8. **The record-length attack must flip the last record of a flight.** A larger length on an earlier record is filled by the records after it, and the receiver then fails the tag and never waits.
9. **`Probe` throws `NotImplementedException` for TLS 1.1 and SSH until S4.** The suite maps that to NOT RUN. A7 and A8 stay NOT RUN for that reason, and S4 removes `Probe.NeedBuilt`.
10. **The glass client offers no CCS and an empty session id, and tolerates a CCS from the peer.** OpenSSL and Go accept this. The glass server echoes the client's session id and sends no CCS.
11. **`EncryptedExtensions` has no `group unchanged` check.** Design section 2.6 lists one. The group check runs at ServerHello, against the one group the client offered, so a second check at `ee` would always pass and show the learner nothing.
