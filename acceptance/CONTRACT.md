# Contract between the suite and the build

Conclusion: the suite compiles against the public signatures in `docs/program-design.md` section 2, and against the members listed here
that the design names but does not spell out. The suite marks each of those ASSUMED. Builders implement the ASSUMED shape, or send the
acceptance author a change request with the shape they want. A builder never edits `acceptance/` (D11).

Proof that the suite compiles against this contract: `pwsh acceptance/run.ps1 -Contract` builds every clause group, on net10.0 and on
net48 with the CF build of MMP.AsyncProxy, against the stub in `acceptance/contract/`. The stub holds the signatures and nothing else.

## 1. Rules the suite sets

| # | Rule | Why |
|---|---|---|
| 1 | Each Core folder in the design table is the namespace `NetSec.<Folder>` (`NetSec.Crypto`, `NetSec.Io`, `NetSec.Keys`, `NetSec.Pki`, `NetSec.Machine`, `NetSec.Trace`, `NetSec.Errors`, `NetSec.Platform`, `NetSec.Dukpt`, `NetSec.Tls13`, `NetSec.Bridge`, `NetSec.Labs`, `NetSec.Auth`, `NetSec.Native`). `layer_check.py` reads `using` lines, so the folder names must show in the namespaces | The design gives no namespace. One rule keeps every clause group compiling |
| 2 | The assembly is `NetSec.Core` in both builds. Paths the suite reads: `src/NetSec.Core/bin/Release/net10.0/NetSec.Core.dll`, `src/NetSec.Core.NetCF/bin/Release/net35/NetSec.Core.dll`, `src/NetSec.CeDevice/bin/Release/net35/NetSec.CeDevice.exe`, `src/NetSec.Node/bin/Release/net10.0/NetSec.Node.dll`, `src/NetSec.Host/bin/Release/net10.0/NetSec.Host.dll` | `run.ps1` builds each project with `dotnet build -c Release` (the CF ones with `-p:NetCFRefDir=`) and reads these files |
| 3 | `src/NetSec.Core/NetSec.Core.csproj` exists from S0. Until it does, every product clause is NOT RUN PRODUCT_MISSING and a clause that passes anyway is reported FAIL SUITE_BUG_VACUOUS_PASS | Keeps "no product, no PASS" true |
| 4 | A compile error that names a missing type or member of NetSec.Core is NOT RUN PRODUCT_MISSING with the first errors. Any other compile error in a clause group is FAIL ACCEPTANCE_COMPILE_ERROR | A signature drift shows as NOT RUN with the compiler's words |
| 5 | Training key material formats: `ITrainingKey.CopyMaterial()` returns the 32-byte seed for Ed25519 and X25519, a PKCS#8 `PrivateKeyInfo` DER for RSA, and raw bytes for AES and DUKPT keys. `CopyPublic()` returns 32 bytes for Ed25519 and X25519 and a `SubjectPublicKeyInfo` DER for RSA. The `KeyIds` strings are the lower-case hyphen forms: `ca-root`, `server-tls-ed25519`, `server-tls11-rsa`, `ssh-host-ed25519`, `ssh-host-rsa`, `ssh-client`, `dukpt-bdk-128`, `dukpt-bdk-256`, `token-issuer`, `attacker-ed25519` | The suite hands the same key to a Go or OpenSSL referee and needs a format both sides read |
| 6 | Secret names in trace events (`TraceSecret.Name`) are the NSS key log labels for TLS 1.3: `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, `EXPORTER_SECRET` | A6 compares them with the OpenSSL key log |
| 7 | A failed check reaches the trace as a `TraceEvent` with `Check.Passed == false` and a stable `Check.Code` (the code names in the design tables), even when `Open` faults. The suite reads the code from the trace, not from an exception type | One place to read a named error |
| 8 | A cut role (acceptance/roles.json) is a decision of the lead. It never comes from a builder | D11 |

## 2. Members the design names without a shape (ASSUMED)

| Area | Member | Clause that needs it |
|---|---|---|
| Crypto | `MlKemPair.EncapsulationKey` (ek, 1184 B), `.DecapsulationKey` (FIPS 203 dk, 2400 B); `MlKemSealed.Ciphertext`, `.SharedSecret` | A2 ML-KEM |
| Crypto | `BigUInt.FromBigEndian(byte[])`; `Pkcs1.VerifySha1(RsaPublic, message, signature)`, `VerifySha256(...)`, `SignSha1(RsaPrivate, message)` | A1 RSA |
| Dukpt | `DukptBank(bdk)` with `InitialKey(ikid8)`, `DerivationKey(ikid8, counter)`, `WorkingKey(ikid8, counter, DukptKeyUse, keyBytes)` | A3 vectors |
| Dukpt | `DukptPinPad(initialKey, ikid8)` with `Counter`, `NextTransaction()`, `WorkingKey(use, keyBytes)`, `StateRegisters()` (every key register held now). The constructor erases its copy of the initial key | A3 1,000 sales, erasure |
| Dukpt | `DukptKeyUse` (X9.24-3 codes: 0x1000 PIN, 0x2000/0x2001/0x2002 MAC, 0x3000/0x3001/0x3002 data, 0x0002 key encryption); `PinBlock.EncryptFormat4(pinKey, pin, pan, random8)`, `TryDecryptFormat4(pinKey, block, pan, out pin)` | A3 |
| Tls13 | `Tls13KeySchedule(suiteName)` with `EarlySecret(psk)`, `HandshakeSecret(early, ecdhe)`, `MasterSecret(handshake)`, `DeriveSecret(secret, label, transcriptHash)`, `ExpandLabel(secret, label, context, length)`, `TrafficKey`, `TrafficIv`, `FinishedKey` | A4 |
| Keys | `TrainingKeySource()` (no arguments); `KeyAlgorithm` members | A5, A7, A8, A16 |
| Pki | `TrainingCa(ITrainingKeySource)` with `RootCertificateDer` and `IssueServerCertificate(dnsName, spkiDer, notBefore, notAfter)`; the glass server presents a leaf for `localhost` that this CA signs | A5, A6, A7 |
| Io | enums `EngineRole {Client, Server}`, `KexGroup {X25519, X25519MlKem768}`, `SshSuite {Modern, Legacy}`, `Tls11Suite {RsaAes128CbcSha, EcdheRsaAes128CbcSha}`; `TransportRequest.Tls11Suite`; `AppChunk {Channel, Bytes}`; `ChannelInfo {Protocol, Suite, Group, PeerName}` | A5, A7, A8 |
| Io | `ISshChannel : ISecureChannel` with `IFuture<int> OpenExec(string command)` and `IFuture<int> OpenTunnel(string host, int port)`. Data of a channel arrives in `Receive()` with `AppChunk.Channel` set; an empty `Bytes` array ends the channel | A8 |
| Machine | `TamperResult.Unchanged` and `TamperResult.Replace(byte[])` | A7 sentinel |
| Platform | `MonotonicClock()` | A11 |
| Labs | `AttackCatalog.All` (AttackDefinition[]), `LabCatalog.Find(int lesson)`, `LabResult {Completed, FailedCode, FailedCheck}`, `AttackOutcome {Rejected, Accepted, NoCheck}`. Attack rows expect the check names of `ux-design.md` section 7: `bad_certificate alert`, `jti already used`, `token signature`, `permission check`, `challenge already used` | A11 |
| Auth | `Token.IssueEdDsa(keys, issuerKeyId, subject, roles, expiresUtc)` returning a compact JWS | A11 |
| Native | `NativeCompare.Leaky(a, b)`, `.ConstantTime(a, b)` (true when equal), `.AbiVersion()`; `TimingVerdict {T, Separates}`; `CompareKind {Leaky, ConstantTime}` | A12 |

## 3. Process contract

The process-level clauses (A10, A10a) and the Host clauses start your executables. They link no product code.

| Program | Command line the suite uses | Lines it prints on stdout | Notes |
|---|---|---|---|
| `NetSec.CeDevice.exe` | `--pinpad P --gateway G --trace T --trace-id ID --link glass-ssh\|external-forward --suite modern\|legacy [--seed N] --pool 25` | `CE-READY pool=<w>/<c> ptr=<n> clr=<v>` within 10 s; `CE-RESULT {json}` at the end | From the design, section 6. P is a port the CE listens on for the PIN pad. G is the gateway port to connect to (the tap, or the ssh.exe forward). T is the trace collector |
| `NetSec.Node --role bankhsm` | `--listen B --trace-port T --trace-id ID [--seed N]` | `NODE-READY role=bankhsm port=<n>`; one `BANK-RESULT {"ok":bool,"code":"...","pinBlockPlain":"<hex>"}` per envelope | `pinBlockPlain` is the 16-byte clear PIN field in hex. `code` is the failed check code when `ok` is false |
| `NetSec.Node --role server` | `--listen S --bank-port B --trace-port T --trace-id ID [--seed N]` | `NODE-READY role=server port=<n>` | Glass TLS 1.3 server. Forwards the envelope to the bank |
| `NetSec.Node --role gateway` | `--listen G --server-port S --link glass-ssh\|external-forward --suite modern --trace-port T --trace-id ID [--plain-listen Q] [--tamper-envelope] [--seed N]` | `NODE-READY role=gateway port=<n>` | Glass SSH server on G, glass TLS 1.3 client `X25519MLKEM768` to S. `--plain-listen Q` also allows an SSH tunnel to 127.0.0.1:Q (the ssh.exe -L run). `--tamper-envelope` flips one byte of the PIN envelope after the SSH layer and before the TLS layer |
| `NetSec.Node --role pinpad` | `--ce-port P --pin 1234 --pan 4111111111111111 --sales 1 --trace-port T --trace-id ID [--seed N]` | `PINPAD-RESULT {"ksn":"<12 byte hex>","pinBlockPlain":"<16 byte hex>"}` | Exits after the sale |
| `NetSec.Node` | `--print-training-key <keyId>` | `material <hex>` and, for asymmetric keys, `public <hex>` | Lets the process-level clauses read training keys without linking Core |
| `NetSec.Host` | environment `NETSEC_PORT`, `NETSEC_TOKEN`, `LOCALAPPDATA`; optional `NETSEC_REAL_PEER=127.0.0.1:<port>` | binds `127.0.0.1:NETSEC_PORT` | `LOCALAPPDATA` moves the session folder. `NETSEC_REAL_PEER` (ASSUMED) tells real mode which TLS 1.3 server lesson 5 connects to |

Trace line fields (NDJSON, one object per line, `ux-design.md` section 0 and `program-design.md` section 2.1): `actor`, `type`, `from`, `to`, `wire` (hex), `plain` (hex), `secrets[]` (`holder`, `name`, `hex`), `check` (`name`, `result` pass or fail, `code`), `traceId`, `hop` (`hop1` for CE to gateway, `hop2` for gateway to server), `streamId`, `streamSeq`, `message`.
The actor at the client end of a hop emits one event for each chunk it sends and each chunk it receives. Its `wire` fields, joined in order by direction (`to` the server end, `from` the server end), equal the bytes the tap saw (A10a).

## 4. Product files the text clauses read

| File | Needed shape |
|---|---|
| `app/src/tours/lesson-NN.json` | An array of steps, or `{ "steps": [...] }`, as `ux-design.md` section 3.1. A step may carry `claims`: `[{ "id", "text", "source" }]`, where `source` names a document and section. A15a needs at least one claim in some tour |
| `app/src/glossary.json` | `{ "terms": [{ "id", "term", "short" }] }` or a plain array |
| `docs/_verdicts/a15a-lesson-NN.json` | `{ "reader": "<agent>", "authors": ["<agent>"], "claims": [{ "id", "verdict": "accurate" }] }`. The reader is not an author. Until the file exists the clause is NOT RUN ACCURACY_READER_PENDING |
| `GET /api/lessons` | A list of `{ lesson, built, ... }` for lessons 1 to 11 |
| `GET /api/ce` | `label` equals `CF-compiled, run on the desktop CLR, never run on CE` |
| `app/src` | The same wording appears in the UI source. Lesson 6 states that a managed heap can keep copies. Lesson 11 states that managed code has no constant-time guarantee. Every lesson has a step with `Built to show the parts. Do not copy.` |
| UI | The renderer reads the Host address and token from `window.netsec.host = { port, token }` or from `?port=&token=` in the URL. A `transport-switch` test id selects real mode (ASSUMED; `ux-design.md` section 6 names none). The chip `training-only-label` reads `TRAINING ONLY` on glass and `OS TRANSPORT` in real mode |
