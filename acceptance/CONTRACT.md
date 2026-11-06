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
| Tls13 | `Tls13Secrets` members are named per RFC 8446 and the suite finds them with case and underscores ignored: `EarlySecret`, `HandshakeSecret`, `ClientHandshakeTrafficSecret`, `ServerHandshakeTrafficSecret`, `MasterSecret`, `ClientApplicationTrafficSecret0`, `ServerApplicationTrafficSecret0`, `ExporterMasterSecret` (fields or properties of type `byte[]`). `Derive` takes no client Finished hash, so the suite asks for `public static Tls13Resumption Resume(Func<IHash> h, byte[] masterSecret, byte[] clientFinishedHash, byte[] ticketNonce)` with `byte[]` members `ResumptionMasterSecret` and `ResumptionSecret` (RFC 8446 7.1 `res master`, then `resumption` with the ticket nonce). Until it exists, `A4.rfc8448.exporter-and-resumption` is NOT RUN DERIVE_LACKS_RESUMPTION. It never passes without the resumption values | A4 |
| Keys | `TrainingKeySource()` (no arguments); `KeyAlgorithm` members | A8, A10, A11, A16 |
| Pki | `TrainingPki.Export(directory)` writes `root.pem`, `srv.pem`, `srv.key` (Ed25519 TLS server for `localhost`), `rsa.pem`, `rsa.key` (RSA TLS 1.1 server), `host.key`, `rsa-host.key` (OpenSSH private key format), `user.pub` (one `authorized_keys` line), `user.key` (OpenSSH format), `issuer.pub` (PEM SPKI of the token issuer). Section 11 says "named in section 9" and section 9 names `srv.pem`, `srv.key`, `rsa.pem`, `rsa.key`, `user.pub`. The rest of the names are ASSUMED | A5 to A8, A10, A11 |
| Io | enums `KexGroup {X25519, X25519MlKem768}` and `SshSuite {Modern, Legacy}`. `ProbeRequest.Suite` is the IANA suite name, for example `TLS_RSA_WITH_AES_128_CBC_SHA`. `ProbeRequest.TunnelTo` is `host:port`. `ProbeRequest.Send` is written after the handshake, or into the tunnel. `ProbeResult.Group` is the group name, `X25519` or `X25519MLKEM768`. `ProbeResult.Received` holds the bytes the peer sent back. `Probe.Listen` answers one session, and a server session sends `ProbeRequest.Send` after the handshake | A5 to A8 |
| Io | `ProbeResult.Code` for an untrusted chain is `CHAIN_NO_ANCHOR`. For a TLS 1.1 offer to a TLS 1.3-only server, `AlertReceived` is 70 | A5, A7 |
| Io | The glass TLS 1.1 server (`Probe.Listen` with `Protocol = Tls11` and `Suite` set to an IANA name) ends its session after one whole line from the peer, and puts that line in `ProbeResult.Received`. OpenSSL `s_client -tls1_1 -cipher <name>:@SECLEVEL=0` must report TLSv1.1 and verify code 0 against `root.pem` | A7 |
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
| `NetSec.Node.exe --role gateway` | `--listen 0 --server P --link ssh [--suite modern|legacy] --trace-file F [--tamper-envelope] [--seed N]` | `READY port=<p>` | Glass SSH server, glass TLS 1.3 client `X25519MLKEM768` to P. `--suite` (PR #80, default `modern`) picks the one SSH suite the gateway speaks; a CE on the other suite stops at `SSH_NO_COMMON_ALG`. A10 uses the default. It accepts a `direct-tcpip` channel to any target, as the Go `gogateway` does, so the `ssh.exe -L` run works. `--tamper-envelope` (ASSUMED) flips one byte of the PIN envelope after the SSH layer and before the TLS layer |
| `NetSec.Node.exe --role pinpad` | `--listen 0 --pin 1234 --pan 4111111111111111 --trace-file F [--seed N]` | `READY port=<p>`; `RESULT {"ksn":"<12 byte hex>","pinBlockHex":"<clear PIN block hex>"}` (ASSUMED field names) | The CE connects to the PIN pad port. The PIN pad sends one envelope to the CE |
| `NetSec.CeDevice.exe` | `--pinpad P --gateway G --trace-file F --link glass-ssh\|external-forward --suite modern\|legacy [--seed N] --pool 25` | `CE-READY pool=<w>/<c> ptr=<n> clr=<v>` within 10 s; `CE-RESULT {json}` at the end | Section 6. P is the PIN pad port the CE connects to. G is the gateway side port (the tap, or the ssh.exe forward). The design names `--trace T`. Section 11 says `--trace-file`, and the suite uses that |
| `NetSec.Host.exe` | `--port P --token T`, and also the environment `NETSEC_PORT`, `NETSEC_TOKEN` (section 5), because sections 5 and 11 differ and the suite sends both; `LOCALAPPDATA`; `NETSEC_OS_PEER=127.0.0.1:<port>` and `SSL_CERT_FILE=<peer certificate>` for the OS transport | binds `127.0.0.1:P` | `LOCALAPPDATA` moves the session folder. `NETSEC_OS_PEER` (ASSUMED, renamed from `NETSEC_REAL_PEER`) tells the OS transport which TLS 1.3 server lesson 5 connects to. The peer is an OpenSSL `s_server` with an RSA key (SslStream fails the handshake against an Ed25519 server certificate, modes-design.md section 7.1) and a self-signed certificate. `SSL_CERT_FILE` (ASSUMED) is the custom trust the OS transport must load for that certificate, since the system store does not hold it. `NETSEC_SECURITY_DIR` moves the `.security/` folder (section 5). The suite starts a lesson with `session.start` in `mode: step`, then sends `session.run` (ASSUMED value) |

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
| UI | The renderer reads the Host address and token from `window.netsec.host = { port, token }` or from `?port=&token=` in the URL. A `transport-switch` test id selects the OS transport (ASSUMED; `ux-design.md` section 6 names none). The chip `training-only-label` reads `TRAINING ONLY` on glass and `OS TRANSPORT` on the OS transport |

## 5. A17: security modes (what the Host must show)

Source: `docs/modes-design.md` and `docs/wizards-ux.md` on `main` at c65e1bb (PRs #99 to #103), sections 2, 3.3, 4, 5, 6, 8, 9. A row marked ASSUMED is a place where the design names no field or value.
The suite wrote the name it needs. A live Host that differs fails the clause at that field, and the message names it. The fake Host in `selftest/FakeHost/` is built from this section and from nothing else.

### 5.1 Process and routes

| Item | The suite uses | Notes |
|---|---|---|
| Start | `NetSec.Host.exe --port P --token T`, and `NETSEC_PORT`, `NETSEC_TOKEN`, `LOCALAPPDATA`, `NETSEC_SECURITY_DIR` (a temp folder), `NETSEC_OPENSSL`, `NETSEC_SSH` | A fresh `NETSEC_SECURITY_DIR` holds no `modes.json`, so Show keys is ON. A route under `/api/security` that the Host does not have answers with a bare 404, and the clause reads NOT RUN `PRODUCT_MISSING` |
| `GET /api/health` | `showKeys` (bool) | A run stops early with `SUITE_NEEDS_SHOW_KEYS_ON` when it reads false |
| `GET /api/security` | `types[]` with `typeId`, `mode` (`BuiltIn` or `Mine`), `state`, `version`; `showKeys` | `state` of a `BuiltIn` type is ASSUMED `BuiltIn`. Design 2.2 gives `Unconfigured`, `Configured`, `Verified`, `Broken` for `Mine` |
| `PUT /api/security/types/{typeId}/mode` `{ mode }` | | Going to `BuiltIn` always works, and the binding stays |
| `GET /api/security/readiness?lesson=N` | `mayRun`, `problems[]` with `typeId`, `code`, `detail` | `detail` names the type and its flow. Codes: `SECURITY_TYPE_NOT_READY`, `SECURITY_TYPE_NOT_PROVEN`, `SECURITY_TYPES_DISAGREE`. Field names follow `TypeProblem { TypeId, Code, Detail }` |
| `GET /api/security/types/{typeId}/key` | `hex` (Show keys ON), `fingerprint`, `version`, `provider`, `hidden` (`toggle` while OFF), `publicHex` (for `token.issuer`) | Field names ASSUMED. The read is an Export by the caller `host/key-route` (ASSUMED name), audited. A changed row gives `VAULT_UNWRAP_FAILED`. An audit that cannot be written gives `VAULT_AUDIT_FAILED` (design 8.5) |
| `GET`, `PUT /api/security/show-keys` `{ on }` | `on` | |
| `POST /api/security/flows/{flowId}/runs` | `runId`, `step` | Flows: `my-certificates`, `my-ssh`, `my-payment`, `my-login`, `my-lesson-keys` |
| `POST /api/security/runs/{id}/events` `{ event, stepSeq, data }` | `step` | `WIZARD_EVENT_NOT_ALLOWED` names the state and the event. `WIZARD_STEP_STALE` for an old `stepSeq`. `WIZARD_RUN_NOT_FOUND` (HTTP 404 with a code) for an unknown run |
| `GET /api/security/vault/keys` | `keys[]` with `name` (ASSUMED: the type id for flow keys, `exercise/signing` and `exercise/derive` for the exercise), `exportable`, `versions`, `fingerprint`, `hidden: non-exportable`, `publicHex` | The exercise keys list at once, with no flow made |
| `GET /api/security/vault/audit?after=N` | `rows[]` with `seq`, `caller`, `op`, `name`, `result`, `detail`, `prev_hash` | The table of design 4.1. The suite also reads `vault/vault.db` with Python sqlite3 (`checks/vaultdb.py`), and `vault/master.key` |
| `POST /api/security/vault/exercise/sign` `{ text }` | `{ keyName, version, inputHex, signatureHex, publicKeyHex, command, output, code }` | Design 4.3. The suite verifies with its own OpenSSL |
| `POST .../exercise/derive` `{ label }` | `{ keyName, version, label, outputHex, code }` | HKDF-SHA256 over the label. The same label gives the same output |
| `POST .../exercise/export` | HTTP 409, `code: VAULT_EXPORT_REFUSED` | Audited as a refused export |
| `POST .../exercise/audit-check` | `{ rows, firstBadSeq, code, limits }` | `firstBadSeq` is 0 or absent while the chain is whole. `limits` is the course text under every result, pass or fail. It names 3 changes the unkeyed chain cannot see: an edit to the newest row, rows cut from the end, and a full rewrite of every row (clause `A17.vault.audit-check-names-limits`) |
| `GET /api/sessions/{id}/events` | One JSON array of events (as the Host answers today) | |
| `GET /api/sessions/{id}/keylog` | | `KEYS_HIDDEN` while Show keys is OFF |
| `GET /api/lessons` | `attacks[]` with `attackId`, `kind`, `expectCode`, `available`, `whyNot`, and `field` for a `flip-byte` row | `available` and `whyNot` are in design 8.3. `field` is ASSUMED (design 3.4 says `TamperPlan.Field`) |

### 5.2 WebSocket

| Message | The suite reads | Notes |
|---|---|---|
| `session.start` `{ lesson, seed, mode, transport }` | `session.started` with `sessionId`, `transportKind`, `trainingOnly`, `sessionFile`, `showKeys`, `security[]` | The suite starts in `mode: step`, then sends `session.run`. `lesson: 20` gives `LESSON_NOT_BUILT`, because the vault exercise is routes and not a lab (design 4.3). A refusal is an `error` frame with `code` and `message`, and no trace event follows |
| `session.attack` `{ sessionId, attackId, mode: run }` | `session.started` (the fork), `session.forked`, `trace`, `session.finished` with `code` | The suite sends it on a new connection. The Host finds the parent by id |
| `trace` frame | `event` with `type`, `streamId`, `streamSeq`, `actor`, `message`, `wire`, `plain`, `fields[]`, `check`, `secrets[]` | `secrets[]` entry: `name`, `holder`, and `hex` while Show keys is ON. While OFF: `fingerprint` (`fp:` and 8 bytes of SHA-256 as hex), `length`, `hidden` |
| `key.in-use` event | `typeId`, `version`, `provider`, one `secrets[]` entry, on stream `<sessionId>/keys` | Design 6.3 gives the stream and the content. The three field names are ASSUMED. Opening the set called `Export(name, "host/lab-<n>")`, so the audit list holds one export row per vault key per start |

### 5.3 The wizard step

The suite drives a flow by step kind and by the events the step allows, so a state name never matters. The two design documents name states differently (`Make`, `Review`, `Check` in `modes-design.md` 8.2; `ChooseSource` and `Place`, `ReadBack`, `Prove` in `wizards-ux.md` 3.2) and agree on the kinds.

| Field | Value |
|---|---|
| `kind` | `explain` (first step), `choose` or `generate` (the make screens), `file` (the branch), `review`, `prove`, `done` |
| `allowed` | The events the table allows. The suite looks for `next` or `continue`, `choose` (with `{ source: make or files }`), `make`, `files` (with `{ paths }`), `check`, `back`, `cancel`. The event names are ASSUMED where the design names none |
| `errors[]` | Stop the step. `code`, `message` |
| `warnings[]` | Let the learner go on. `KEY_PATH_PERSONAL` is one. `code`, `message` |
| `facts[]` at the review step | One per type: `typeId`, `name`, `notAfter`, `algorithm`, `fingerprint` (design 8.4). The suite checks all types of the flow are there (15 of 15 across the five flows) and the fixed names |
| `facts[]` at the prove step | One per type: `typeId`, `judge` (`openssl`, `ssh.exe`, `none`), `says`, `command`, `output`, `passed` (design 8.6). `says` is a stable id: `checked-against-root`, `checked-with-openssl`, `checked-signature-only`, `checked-with-ssh-exe`, `no-outside-judge`. The words are in `app/src/wizard-copy.json` |
| `copy` | Copy ids shown. The first step of every flow carries `wizard.common.test-keys-only` |
| `back` | Allowed at the review step. It returns to the make screen, and making again writes a new version |

### 5.4 "Use my own files" (ASSUMED layout)

`paths` maps a key to an absolute path. For a type with a private key only (`token.issuer`, `device.enrolment`) the key is the type id and the file is an Ed25519 private key in PEM.
For the certificate flow the file at `<typeId>` is the certificate in PEM, and `<typeId>.key` is its private key. The root's `.key` is left out for a trust-only root.
`tls.trust` defaults to the root, and the suite also sends it. A leaf the root did not sign is refused at the check with a named code. An RSA or P-256 root is refused with `CERT_SIGNATURE_ALG_UNSUPPORTED`, and the message names the OS transport.
`CredentialSet.FromFiles(directory)` is the other route to a learner's key. The suite uses it to judge a glass server from outside (see 5.6, referee clauses). Its file names are in design 3.3.

### 5.5 Files in the product repository

| File | Shape |
|---|---|
| `app/src/wizard-copy.json` | An object from copy id to text (a string, a list of strings, or `{ text }`). `wizard.common.test-keys-only` reads: Use test keys only. This course shows your keys on screen and in saved files. |
| `tools/secret_guard.py` | Run from a repository root with no argument. Exit 0 when clean. Exit 1 and one line per problem, each naming the path, when a tracked or staged path is under `.security/`, ends in `.pfx .p12 .db .key .ndjson` (the files `acceptance/golden/**/*.ndjson` are exempt from the `.ndjson` rule only: they hold built-in training keys, which are public by design), is named `master.key id_rsa id_ed25519 known_hosts`, or holds a PEM private key block (the header line, a base64 body and the footer) outside the allow-list of 3 files. A sentence that only names the header is no key: `docs/modes-design.md`, `docs/modes-real-world.md` and `docs/wizards-ux.md` name it, and the guard must pass them (the suite found this on `main` at c65e1bb: a rule that matches the bare words flags the design itself) |
| `app/src/tours/lesson-NN.json` | A step may carry `textMine`. A claim carries `id`, `text`, `source` |
| `docs/_verdicts/a15a-lesson-NN.json` | As before. Now each claim verdict carries `textHash`, and `textRead` carries `textHash`, `stepsRead` and `problemsOpen`. `python -I acceptance/checks/docs_checks.py --root . --hashes` prints the hashes. A verdict with no hash reads NOT RUN `ACCURACY_VERDICT_UNBOUND`. A verdict for text that changed reads NOT RUN `ACCURACY_VERDICT_STALE` |
| `docs/_verdicts/cold-reader-lesson-10.json` | `{ reader: { name, kind: human or agent, freshContext }, clone: { fresh, commit }, keys: { issuerPublicHex }, run: { lesson: 10, token }, understoodWithoutHelp }`. A builder cannot be the reader. Until the file exists, A17.cold.lesson-10-fresh-clone reads NOT RUN `COLD_READER_PENDING` |
| `app/src` UI | Test ids `show-keys-switch` (aria-checked or checked) and `secret-row-*`. The words `Built-in key` and `My test key`, and no `Real` as a mode, transport or label. The chip `training-only-label` reads `OS TRANSPORT` on the OS transport. The A16 clauses use `transport: os` and `NETSEC_OS_PEER=127.0.0.1:<port>`, and trust the peer certificate through `SSL_CERT_FILE` |

### 5.6 Referee clauses on a learner's key

Group `a17probe` links `NetSec.Core`. It builds a `CredentialSet` with `CredentialSet.FromFiles(dir)` from files the suite made with OpenSSL and `ssh-keygen`, sets `ProbeRequest.Credentials`, and puts OpenSSL, Go `crypto/tls`, `ssh.exe` and Go `x/crypto/ssh` at the other end (design 3.3, decision O14).
It reaches the two members by reflection, so it compiles against a Core that lacks them, and every clause then reads NOT RUN `PRODUCT_MISSING`. With `--prop a17probe.training=1` the clauses use the training files and no `Credentials`, which proves the referee wiring on today's engines.

### 5.7 Open questions

1. **File layout of an import** (5.4). The design says one row per type, and a `chain.pem` beside the copies.
2. **Names marked ASSUMED in 5.1 to 5.3.** Each is one line to change in `groups/a17/` and in the fake.
3. **The state names** in `modes-design.md` 8.2 and `wizards-ux.md` 3.2 differ. The suite does not care, and the two documents should agree.
4. **Golden traces** wait for the lead's word.

## 6. A19: the AES walk, chapter 1 (what the build must show)

Source: `docs/walkthrough-design.md` on `main` at c19b151 (Jared's pass on d1368af, PR #146, then #150, #152 and #153), sections 2.2, 2.3, 2.6, 3.1, 3.3, 3.4, 3.5. A row marked ASSUMED is a name the design leaves open. A builder implements it or sends the acceptance author a change request.

| Area | The suite uses | Notes |
|---|---|---|
| Core | `AesKey.WalkEncrypt`, `WalkDecrypt`, `WalkKeyExpansion`, static `SubstitutionTable`, `InverseSubstitutionTable`; `AesStepKind`, `AesStep`, `AesBlockWalk`, `AesKeyWord` | Design 3.3. A table call returns a copy. `AesStep.Round`: encrypt 0 to Nr. Decrypt Nr down to 0: the first AddRoundKey has Round Nr, and each later group of steps has the Round of the key it ends with |
| Core | `WalkKeyExpansion` holds Nb * (Nr + 1) rows. A row with i below Nk holds only `Index` and `Word` | Richard confirmed this shape on #154 |
| `GET /api/walk/aes/tables` | `sbox`, `inverseSbox` as 512 hex characters. Open with Show keys OFF. `Cache-Control: no-store` | Design 3.4 |
| `GET /api/sessions/{id}/walk/aes/block?source=text&keyBits=128` | `source`, `keyBits`, `rounds`, `keySource`, `inputHex`, `keyWords[]`, `forward`, `inverse`, `wire` | Design 3.4. `forward` and `inverse` hold `input`, `output`, `steps[]` with `kind`, `round`, `state`, `roundKey` (only on AddRoundKey). `keyWords[]` holds every row, with `i`, `previous`, `rotated`, `substituted`, `rcon`, `afterRcon`, `keyBack`, `word`. A cell the row does not use is absent |
| Refusals | `code`, `message`, `retryable`, `requestId`. OFF: 409 `KEYS_HIDDEN`, checked before the session read. 404 `SESSION_NOT_FOUND`. Another lesson: 409 `WALK_NOT_BUILT`. Bad `source` or `keyBits`: 400 `WALK_BAD_ARGUMENT` | Design 3.4 |
| A bare 404 on a walk route | NOT RUN `PRODUCT_MISSING` | As for `/api/security` |
| Host source | `src/NetSec.Host/AesWalkRoutes.cs`. Each walk route is a string in the source, and is listed in `checks/walk_routes.json` | Design 3.5 |
| App files | `app/src/walk.ts`, `app/src/components/AesBlockWalk.vue`. No part of either S-box under `app/src` | Design 3.1, 3.7 |

UI test ids, all ASSUMED under the design's `aes-walk-` prefix:

| Test id | Shape |
|---|---|
| `aes-walk-tab`, `aes-walk-panel` | The tab shows when the run holds `aes.key`. A click fetches the block |
| `aes-walk-first-view` | Shows on the first view. It starts on an empty grid, and each Next adds one byte in position order |
| `aes-walk-next`, `aes-walk-back` | Next is disabled at the end of the walk |
| `aes-walk-cell-{r}-{c}` | Row r, column c. The text starts with the byte's 2 hex digits. An empty cell on the first view shows nothing or its position number. `data-letter` holds the byte's character when it is printable |
| `aes-walk-step-kind` | The step's name: an `AesStepKind` member. On the first view and the key rows it holds another word |
| `aes-walk-readable` | At the end of the walk it reads `Pump four is ok.` |
| `aes-walk-sbox-row`, `aes-walk-sbox-col`, `aes-walk-sbox-value` | After a click on a cell of a SubBytes or InvSubBytes step: one hex digit, one hex digit, and the 2-digit table value |
| `aes-walk-sbox-cell-{x}-{y}` | One table cell, with x and y as hex digits |
| `aes-walk-closed` | Shows while Show keys is OFF, with the sentence of design 3.5. No `aes-walk-cell-*` exists then |
