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
