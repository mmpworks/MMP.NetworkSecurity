# Contract between the suite and the build

Conclusion: the suite compiles against the public signatures in `docs/program-design.md` sections 2 and 11, and against the members listed
here that the design names but does not spell out. The suite marks each of those ASSUMED. Builders implement the ASSUMED shape, or send
the acceptance author a change request with the shape they want. A builder never edits `acceptance/` (D11).

Proof that the suite compiles against this contract: `pwsh acceptance/run.ps1 -Contract` builds every clause group, on net10.0 and on
net48 with the CF build of MMP.AsyncProxy, against the stub in `acceptance/contract/`. The stub holds the signatures and nothing else.
`contract/Seams.cs` holds the seams of section 11. `contract/Io.cs`, `contract/Labs.cs` and `contract/Crypto.cs` hold sections 1 to 3.

## 1. Rules the suite sets

| # | Rule | Why |
|---|---|---|
| 1 | Each Core folder in the design table is the namespace `NetSec.<Folder>` (`NetSec.Crypto`, `NetSec.Io`, `NetSec.Keys`, `NetSec.Pki`, `NetSec.Machine`, `NetSec.Trace`, `NetSec.Errors`, `NetSec.Platform`, `NetSec.Dukpt`, `NetSec.Tls13`, `NetSec.Bridge`, `NetSec.Labs`, `NetSec.Auth`, `NetSec.Native`). `layer_check.py` reads `using` lines, so the folder names must show in the namespaces | The design gives no namespace. One rule keeps every clause group compiling |
| 2 | The assembly is `NetSec.Core` in both builds. Paths the suite reads (design section 11): `src/NetSec.Core/bin/Release/net10.0/NetSec.Core.dll`, `src/NetSec.Core.NetCF/bin/Release/net35/NetSec.Core.dll`, `src/NetSec.CeDevice/bin/Release/net35/NetSec.CeDevice.exe`, `src/NetSec.Node/bin/Release/net10.0/NetSec.Node.exe`, `src/NetSec.Host/bin/Release/net10.0/NetSec.Host.exe`. A `.dll` beside the `.exe` of Node or Host is the fallback | `run.ps1` builds each project with `dotnet build -c Release` (the CF ones with `-p:NetCFRefDir=`) and reads these files |
| 3 | `src/NetSec.Core/NetSec.Core.csproj` exists from S0. Until it does, every product clause is NOT RUN PRODUCT_MISSING and a clause that passes anyway is reported FAIL SUITE_BUG_VACUOUS_PASS | Keeps "no product, no PASS" true |
| 4 | A compile error that names a missing type or member of NetSec.Core is NOT RUN PRODUCT_MISSING with the first errors. Any other compile error in a clause group is FAIL ACCEPTANCE_COMPILE_ERROR | A signature drift shows as NOT RUN with the compiler's words |
| 5 | Training key formats: `ITrainingKey.CopyMaterial()` returns the 32-byte seed for Ed25519 and X25519, a PKCS#8 `PrivateKeyInfo` DER for RSA, and raw bytes for AES and DUKPT keys. `CopyPublic()` returns 32 bytes for Ed25519 and X25519 and a `SubjectPublicKeyInfo` DER for RSA. The `KeyIds` strings are the lower-case hyphen forms: `ca-root`, `server-tls-ed25519`, `server-tls11-rsa`, `ssh-host-ed25519`, `ssh-host-rsa`, `ssh-client`, `dukpt-bdk-128`, `dukpt-bdk-256`, `token-issuer`, `attacker-ed25519` | A8 and A10 read these keys. The referees read the exported files, not these bytes |
| 6 | `ProbeResult.KeyLog` lines are NSS key log format: `LABEL clientRandomHex secretHex`. The four labels `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0` are compared with the referee. Extra lines are allowed and ignored (Go writes 4 lines, OpenSSL writes `EXPORTER_SECRET` and a comment line too) | A6. `acceptance/referees/README.md`, "Known limits" |
| 7 | A failed check reaches `ProbeResult.Code` and `CheckName`, and the trace as a `TraceEvent` with `Check.Passed == false` and a stable `Check.Code`. The suite reads the code, never an exception type | One place to read a named error |
| 8 | A cut role (acceptance/roles.json) is a decision of the lead. It never comes from a builder | D11 |

## 2. Members the design names without a shape (ASSUMED)

| Area | Member | Clause that needs it |
|---|---|---|
| Crypto | `Pkcs1.VerifySha1(RsaPublic, message, signature)`, `VerifySha256(...)`, `SignSha1(RsaPrivate, message)`: the design lists the names with `...` for the arguments | A1 RSA |
| Dukpt | `PinBlock.EncryptFormat4(pinKey, pin, pan, random8)` and `TryDecryptFormat4(pinKey, block, pan, out pin)` (ISO 9564 format 4). Section 11 names `PinBlock` only | A3 |
| Dukpt | `DukptKeyUsage` holds the X9.24-3 codes (0x1000 PIN, 0x2000/0x2001/0x2002 MAC, 0x3000/0x3001/0x3002 data, 0x0002 key encryption). `DukptKeyType` is 2 for AES-128, 3 for AES-192, 4 for AES-256. `DukptUse.Ksn` is 12 bytes: the 8-byte initial key id, then a 4-byte big-endian counter. Each `DukptPinPad.Next` call uses the next counter | A3 |
| Dukpt | `DukptBank` has no seam for the derivation key, so A3 checks the initial key and the working keys only | A3 |
| Tls13 | `Tls13Secrets` members are named per RFC 8446 and the suite finds them with case and underscores ignored: `EarlySecret`, `HandshakeSecret`, `ClientHandshakeTrafficSecret`, `ServerHandshakeTrafficSecret`, `MasterSecret`, `ClientApplicationTrafficSecret0`, `ServerApplicationTrafficSecret0`, `ExporterMasterSecret` (fields or properties of type `byte[]`). `Derive` takes no client Finished hash, so A4 does not check the resumption master secret | A4 |
| Keys | `TrainingKeySource()` (no arguments); `KeyAlgorithm` members | A8, A10, A11, A16 |
| Pki | `TrainingPki.Export(directory)` writes `root.pem`, `srv.pem`, `srv.key` (Ed25519 TLS server for `localhost`), `rsa.pem`, `rsa.key` (RSA TLS 1.1 server), `host.key`, `rsa-host.key` (OpenSSH private key format), `user.pub` (one `authorized_keys` line), `user.key` (OpenSSH format), `issuer.pub` (PEM SPKI of the token issuer). Section 11 says "named in section 9" and section 9 names `srv.pem`, `srv.key`, `rsa.pem`, `rsa.key`, `user.pub`. The rest of the names are ASSUMED | A5 to A8, A10, A11 |
| Io | enums `KexGroup {X25519, X25519MlKem768}` and `SshSuite {Modern, Legacy}`. `ProbeRequest.Suite` is the IANA suite name, for example `TLS_RSA_WITH_AES_128_CBC_SHA`. `ProbeRequest.TunnelTo` is `host:port`. `ProbeRequest.Send` is written after the handshake, or into the tunnel. `ProbeResult.Group` is the group name, `X25519` or `X25519MLKEM768`. `ProbeResult.Received` holds the bytes the peer sent back. `Probe.Listen` answers one session, and a server session sends `ProbeRequest.Send` after the handshake | A5 to A8 |
| Io | `ProbeResult.Code` for an untrusted chain is `CHAIN_NO_ANCHOR`. For a TLS 1.1 offer to a TLS 1.3-only server, `AlertReceived` is 70 | A5, A7 |
| Io | A glass SSH server (`Probe.Listen`, `Protocol = Ssh`) answers the exec command `echo hello` with `hello`, and accepts the `ssh-client` key from `user.pub` for any user name | A8 |
| Machine | `TamperResult.Unchanged` and `TamperResult.Replace(byte[])` | A10 |
| Platform | `MonotonicClock()` | A11 |
| Labs | `AttackCatalog.All` (AttackDefinition[]), `LabCatalog.Find(int lesson)`, `LabResult {Completed, FailedCode, FailedCheck}`, `AttackOutcome {Rejected, Accepted, NoCheck}`. Attack rows expect the check names of `ux-design.md` section 7: `bad_certificate alert`, `jti already used`, `token signature`, `permission check`, `challenge already used` | A11 |
| Auth | `Token.Issue(ITrainingKey, claimsJson)` returns a compact JWS (EdDSA) over the claims text as given. `Token.Verify(pub, jws, now)` takes the 32-byte Ed25519 public key. `DpopProof`, `Challenge`, `AccessRules` are reached through `AttackCatalog` rows only, so the suite does not call them | A11 |
| Native | `NativeCompare.Leaky(a, b)`, `.ConstantTime(a, b)` (true when equal), `.AbiVersion()`; `CompareKind {Leaky, ConstantTime}`. `TimingJudge.Judge(leakyFirst, leakyLast, constFirst, constLast)` takes four `TimingCase` samples (a difference in the first byte, and in the last byte) and returns `TimingVerdict {LeakyT, ConstantT, Threshold, Separated}` | A12 |

## 3. Process contract

The process-level clauses (A10, A10a) and the Host clauses start your executables. They link `NetSec.Core` only for `TrainingPki.Export`
and `TrainingKeySource`. Every process of section 11 prints `READY port=<p>` first and a final `RESULT {json}` line, and takes `--trace-file <path>`.
The command lines below come from section 11 and section 6. A flag marked ASSUMED is not in the design.

| Program | Command line the suite uses | Lines it prints on stdout | Notes |
|---|---|---|---|
| `NetSec.Node.exe --role bankhsm` | `--listen 0 --trace-file F [--seed N]` | `READY port=<p>`; one `RESULT {"pinBlockHex":"<hex>","code":"...","check":"..."}` | `code` is empty or `OK` when the bank recovered the PIN block. `--seed` is ASSUMED |
| `NetSec.Node.exe --role server` | `--listen 0 --bank P --trace-file F [--seed N]` | `READY port=<p>` | Glass TLS 1.3 server. Forwards the envelope to the bank |
| `NetSec.Node.exe --role gateway` | `--listen 0 --server P --link ssh --trace-file F [--tamper-envelope] [--seed N]` | `READY port=<p>` | Glass SSH server, glass TLS 1.3 client `X25519MLKEM768` to P. It accepts a `direct-tcpip` channel to any target, as the Go `gogateway` does, so the `ssh.exe -L` run works. `--tamper-envelope` (ASSUMED) flips one byte of the PIN envelope after the SSH layer and before the TLS layer |
| `NetSec.Node.exe --role pinpad` | `--listen 0 --pin 1234 --pan 4111111111111111 --trace-file F [--seed N]` | `READY port=<p>`; `RESULT {"ksn":"<12 byte hex>","pinBlockHex":"<clear PIN block hex>"}` (ASSUMED field names) | The CE connects to the PIN pad port. The PIN pad sends one envelope to the CE |
| `NetSec.CeDevice.exe` | `--pinpad P --gateway G --trace-file F --link glass-ssh\|external-forward --suite modern\|legacy [--seed N] --pool 25` | `CE-READY pool=<w>/<c> ptr=<n> clr=<v>` within 10 s; `CE-RESULT {json}` at the end | Section 6. P is the PIN pad port the CE connects to. G is the gateway side port (the tap, or the ssh.exe forward). The design names `--trace T`. Section 11 says `--trace-file`, and the suite uses that |
| `NetSec.Host.exe` | `--port P --token T`; environment `LOCALAPPDATA`; `NETSEC_REAL_PEER=127.0.0.1:<port>` for real mode | binds `127.0.0.1:P` | `LOCALAPPDATA` moves the session folder. `NETSEC_REAL_PEER` (ASSUMED) tells real mode which TLS 1.3 server lesson 5 connects to. The suite starts a lesson with `session.start` in `mode: step`, then sends `session.run` (ASSUMED value) |

Trace file lines (NDJSON, one object per line, `ux-design.md` section 0 and `program-design.md` section 2.1): `actor`, `type`, `from`, `to`, `wire` (hex), `plain` (hex), `secrets[]` (`holder`, `name`, `hex`), `check` (`name`, `result` pass or fail, `code`), `traceId`, `hop` (`hop1` for CE to gateway, `hop2` for gateway to server), `streamId`, `streamSeq`, `message`.
Each process emits a `wire.sent` event for the bytes it wrote to the socket after tamper (section 2.1). For one hop, the `wire.sent` bytes of the client end, joined in file order, equal the tap log client-to-server bytes. The `wire.sent` bytes of the server end equal the tap log server-to-client bytes (A10a).
All five processes use one `traceId`: the PIN pad makes it and the envelope carries it.

## 4. Product files the text clauses read

| File | Needed shape |
|---|---|
| `app/src/tours/lesson-NN.json` | An array of steps, or `{ "steps": [...] }`, as `ux-design.md` section 3.1. A tour carries `claims`: `[{ "text", "source" }]`, where `source` names a document and section (design section 11, A14 to A15a). A15a needs at least one claim in some tour |
| `app/src/glossary.json` | `{ "terms": [{ "id", "term", "short" }] }` or a plain array |
| `docs/_verdicts/a15a-lesson-NN.json` | `{ "reader": "<agent>", "authors": ["<agent>"], "claims": [{ "id", "verdict": "accurate" }] }`. The reader is not an author. Until the file exists the clause is NOT RUN ACCURACY_READER_PENDING |
| `GET /api/lessons` | A list of `{ lesson, built, ... }` for lessons 1 to 11 |
| `GET /api/ce` | `label` equals `CF-compiled, run on the desktop CLR, never run on CE` |
| `app/src` | The same wording appears in the UI source. Lesson 6 states that a managed heap can keep copies. Lesson 11 states that managed code has no constant-time guarantee. Every lesson has a step with `Built to show the parts. Do not copy.` |
| UI | The renderer reads the Host address and token from `window.netsec.host = { port, token }` or from `?port=&token=` in the URL. A `transport-switch` test id selects real mode (ASSUMED; `ux-design.md` section 6 names none). The chip `training-only-label` reads `TRAINING ONLY` on glass and `OS TRANSPORT` in real mode |
