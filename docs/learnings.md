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
12. **Each side of a lab needs its own random stream.** Two pumps draw in an order the threads choose, so one shared stream gives different bytes on a same-seed rerun. `LabPair.Fork` draws a seed per side before the pumps start. Fork matching (`atSeq`) depends on this.
13. **A rule reads a value only through `FrameSession.Secret`, and `Effect.Secret` stores it.** The interpreter calls `Remember`, so a rule stays free of side effects except `Draw`, which reads the side's random stream in rule order.
14. **The toy is lesson 0 and sits outside `GET /api/lessons`, which holds lessons 1 to 11 (lead's ruling).** `session.start` accepts 0. `GET /api/lessons/0` gives its row.
