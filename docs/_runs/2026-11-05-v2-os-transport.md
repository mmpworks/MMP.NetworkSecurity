# Slice V2, the OS transport: gate run, 2026-11-05

Result: `A16.os-transport.writes-no-secret-bytes` PASS. 220 of 260 clauses PASS across all groups. Base `main` bddb4de.

## What changed

1. `src/NetSec.Host/OsTransport/OsTransportFactory.cs` picks the lab for `transport: os`. Only lesson 5 has an OS path. Any other lesson gives `OS_TRANSPORT_NOT_BUILT`, and a missing `NETSEC_OS_PEER` gives `OS_TRANSPORT_NO_PEER`. Both refusals come before any session exists.
2. `src/NetSec.Host/OsTransport/OsTls13Lab.cs`: Windows `SslStream` speaks TLS 1.3 to `NETSEC_OS_PEER`. When `SSL_CERT_FILE` is set, its certificates are the only roots. The lab sends one line and reads one line back. Its events carry metadata only and no secret.
3. An os session says `transportKind: os` and `trainingOnly: false`. Its key log route answers HTTP 409 `KEYLOG_NOT_KEPT`. An attack on it gives `ATTACK_NOT_ON_OS_TRANSPORT`.
4. `transport: real` still picks the OS transport, because the app sends it until Nancy's chip PR lands. Remove the old name after that PR.
5. `REAL_MODE_NOT_BUILT` is gone from `ErrorCodes`. Four codes are added.

## Red first

Red commit `27d9ae7` holds four live tests (`OsTransportLiveTests`) and the changed `real` check in `HostLiveTests`. All 4 new tests failed on the code before the fix: the Host ran `transport: os` as a glass session. No test file changed after `27d9ae7` (`git diff --stat 27d9ae7 -- tests` is empty).

## Gate, step by step

| Step | Result |
|---|---|
| `python tools/layer_check.py src/NetSec.Core` | 122 files, 0 problems |
| `python -I tools/secret_guard.py` (V2 files staged) | exit 0 |
| `dotnet build src/NetSec.Core.NetCF` | Build succeeded |
| `dotnet test tests/NetSec.Tests -f net10.0` | 664 of 664 passed |
| `dotnet test tests/NetSec.Tests -f net48` | 664 of 664 passed |
| `dotnet test tests/NetSec.Host.Tests` | 89 of 89 passed. `main` has 85. V1's vault tests and the guard shape tests are not on this base |

## Acceptance

| Run | Result |
|---|---|
| `-Clauses A1,...,A8` | 147 of 147 PASS |
| `-Clauses A9,A10,A10a,A11,A12` | 31 of 31 PASS |
| `-Clauses A13,A14,A15,A15a` | 21 of 22 PASS, 1 NOT RUN (`NOT_A_FRESH_RUN`) |
| `-Clauses A16` | 8 of 8 PASS |
| `-Clauses A17` | 13 of 52 PASS, 24 FAIL, 15 NOT RUN |

Against the A17 control on 1e375f6, 6 verdicts changed and none went from PASS. 4 copy and UI clauses went NOT RUN to PASS. `A17.ui.show-keys-switch` (V3) went NOT RUN to FAIL. `A17.payment.known-answer-vectors-through-flow-code` (V6) went NOT RUN to FAIL, because this worktree holds the fetched X9 vectors and the clause now reaches the unbuilt `my-payment` flow.

## Left open

1. The app's chip and button: `store.ts:100` and `:206` test `'real'`, and `App.vue` says "Real mode". That is Nancy's part of V2 (`docs/modes-design.md` 7.1).
2. Rebase on `main` after #125 merges. V1 also changes `Program.cs` (session start) and `SecurityLiveTests.cs`, in other lines.

## Friction

1. One acceptance run of A9 to A15a together ran past the 10-minute limit. The groups had to run in smaller batches.
