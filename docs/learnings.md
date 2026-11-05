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
4. **`Ed25519.Verify` accepts a small-order public key.** A public key at y = 1 with R = B and S = 1 verifies for any message. RFC 8032 allows this. A protocol that needs a stronger rule adds its own check. `Verify` does refuse S at or above L and a public key with y at or above p.
5. **`RsaPrivate` holds n and d only, so it runs the full-size exponent.** Parsing a PKCS#8 key can drop the CRT values. On a real device this makes a private operation slower than a CRT one by a factor of about 4 (standard estimate, not measured here).
6. **A2 tests valid ML-KEM exchanges only.** Implicit rejection and the key checks are reached by 36 NIST ACVP records in `tests/NetSec.Tests/vectors/mlkem768-acvp.txt`.

## S7

1. **Timing cases taken one after the other measure the machine, and they do not measure the compare.** This machine has 24 logical CPUs. A whole-case sample of the constant-time compare moved its mean between about 12 and 19 ticks from run to run. Sequential constant-time |t| ran from 3.7 to 230, and a control with two identical cases reached 89. So `TimingLab.Interleaved` takes turns of 100 samples between its two cases, and the lab uses it. `TimingLab.Sample` stays sequential because the contract names it.
2. **One run under |t| 4.5 is not a promise on this machine, even for identical cases.** Over 20 interleaved runs of 100,000 samples per case, the constant-time compare went over 4.5 in 5 of 20 runs (median 1.97, max 9.07). The identical-case control went over 4.5 in 1 of 20 (median 1.49, max 6.32). A second pass with ABBA turns gave 6 of 20 and 3 of 20. The largest mean difference was 0.18 ticks, against about 11 ticks for the leaky compare. So the lab prints `controlT` beside `constantTimeT`, and its check uses the 3 x rule only. Do not write "constant-time |t| stays under 4.5" in a tour.
3. **The lab's guess loop stretches each secret byte to a 1,024-byte block.** One loop pass takes about 0.33 ns, and the clock tick is 100 ns. Each round tries every candidate, so drift lands on all of them. At 10 rounds the lab missed a byte in 2 of 5 control runs. At 50 rounds it recovered the secret in 30 of 30 attack-row runs.
4. **A timing event has no wire bytes, so it carries its numbers as JSON text in `Plain`.** `TraceEvent` has no general payload field. The schemas are in `Native/TimingReport.cs`.
5. **A control run must have no failed check (A11.catalog).** So the constant-time guess reports its result with no check in a control run, and it fails the `constant-time compare` check only on the attack row. Each attack row holds one `LabOption` and no plan, because a row may change one field.
6. **`TimingVerdict` is `{LeakyT, ConstantT, Threshold, Separated}`, and `TimingJudge.Judge` takes four cases, per the contract on main.** The contract changed while this slice was open, so the first shape `{T, Separates}` went away. `TimingJudge.PairT` gives the t of one pair, for the control and the managed compare.
7. **`build.cmd` prints `'vswhere.exe' is not recognized` under vcvars when `vswhere` is off PATH.** The build still passes. Ignore the line.
8. **`LabTests` joined the non-parallel `timing` collection,** because `AttackCatalog.All` will hold timing rows at release, and a sibling test's load would change a measurement.
9. **Lesson 11 stays `built: false` until its tour and UI land, so no learner reaches it without the accuracy text (lead's ruling after Jared's review).** `LabCatalog.Find(11)` returns null, and `AttackCatalog.All` holds no lesson 11 row. `built` stays one decision with one control. The release steps are in `docs/lesson-11-names.md`.
10. **A failed guess proves only that the loop failed.** The check text names the samples per candidate, and the guess event names the stretch and the same-process timer. Do not write "flat timing" as a result of the lab.
