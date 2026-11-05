# MMP.NetworkSecurity: product requirements

Status: approved to build by Steve, 2026-11-04 ("You have full control"). Run unattended overnight.

## What

A teaching course in an Electron app. The learner watches a client prove who it is to a server, one
message at a time, on live traffic. A guided tour explains each message at 8th grade level.

The labs cover AES, MAC, HMAC, DUKPT, TLS 1.3 with post-quantum hybrid key exchange, TLS 1.1, SSH,
certificates, tokens, and permissions.

## Why

1. Steve wants to learn these techniques by seeing the bytes.
2. Fuel-site hardware runs Windows CE. Steve states that the CE device has only SSH and possibly TLS 1.1.
   The course must show how an old device and a new server meet, what that protects, and what stays exposed.

## Spike results (2026-11-04, run on this machine)

| Surface | Command or probe | Result | Effect on the design |
|---|---|---|---|
| .NET 10 ML-KEM | `MLKem.GenerateKey(MLKem768)`, encapsulate, decapsulate | Ciphertext 1088 B, shared secret 32 B, match | A referee for our ML-KEM |
| .NET 10 ML-DSA, SLH-DSA | `IsSupported` | ML-DSA true, SLH-DSA false | ML-DSA can be shown. SLH-DSA stays out |
| `SslStream` TLS 1.3 | Loopback pair | `Tls13`, `TLS_AES_256_GCM_SHA384` | Works, and shows no internals |
| `SslStream` key log | `SSLKEYLOGFILE` set, switch set | No file written | **Schannel hides its secrets, so a glass-box engine is required** |
| OpenSSL 3.5.7 (`/mingw64/bin/openssl`) | `-groups X25519MLKEM768` | `Negotiated TLS1.3 group: X25519MLKEM768`, key log 6 lines | Referee for hybrid TLS 1.3 |
| OpenSSL 3.5.7 | `-tls1_1 -cipher ALL:@SECLEVEL=0` | `Protocol: TLSv1.1` | Referee for TLS 1.1 |
| CF 3.5 references (`E:\dev\tools\netcf35-ref`) | `ilspycmd -l c` | Has `Rijndael`, `SHA1`, `MD5`, `RSA`, `DSA`, `TripleDES`. Lacks SHA-256, HMAC, any `SslStream`, ECDH | **All modern primitives must be written by hand in C# 3** |
| Go 1.26.2, `golang.org/x/crypto` v0.58.0 | `go get` | Resolves | Referee for TLS and SSH. There is no `sshd` on this machine |
| Windows `ssh.exe` | `-V` | OpenSSH 9.5p2 | Referee SSH client |
| MSVC | `cl.exe` under VS 2022 | Present (x64, x86 hosts) | Desktop native builds |
| CE compiler, emulator, device | Search of disks | None found | **Nothing can run on real CE in this run. The claim is CF-compiled binaries on the desktop CLR** |
| `tshark`, Wireshark | `which` | Absent | The app carries its own decoder |

## Standards used

| Topic | Source | Status |
|---|---|---|
| TLS 1.3 | RFC 8446, trace in RFC 8448 | Standard |
| Hybrid key exchange | RFC 10024, `X25519MLKEM768`, code point 0x11EC | Proposed Standard, August 2026 |
| ML-KEM | FIPS 203 | Standard |
| TLS 1.0 and 1.1 retirement | RFC 8996 | Best Current Practice |
| TLS 1.1 | RFC 4346 | Deprecated, taught as the legacy lab |
| SSH | RFC 4253, RFC 8731 (curve25519-sha256), RFC 8709 (ed25519) | Standard |
| AES DUKPT | ANSI X9.24-3-2017, vectors at x9.org | Vectors are free. The standard is paid |
| DPoP | RFC 9449 | Standard |
| AES, SHA-2, HMAC, CMAC, HKDF, GCM, X25519, Ed25519 | FIPS 197, FIPS 180-4, RFC 4231, RFC 4493, RFC 5869, SP 800-38D, RFC 7748, RFC 8032 | Standard |

## Decisions

| # | Decision | Reason |
|---|---|---|
| D1 | One shared C# 3 source tree compiles for .NET 10 and for CF 3.5 | The CE lab runs the same code the learner reads |
| D2 | Primitives and protocol engines are hand-written and glass-box | Spike: Schannel hides secrets and CF lacks the primitives |
| D3 | Socket loops run on MMP.AsyncProxy (sibling project reference) | Steve's request. AsyncProxy already has a CF build |
| D4 | Every engine step emits a trace event with bytes, parsed fields, and the secrets in use | "See the traffic" is the product |
| D5 | Keys come in two types. `ITrainingKey` can export bytes. `IKeyHandle` offers operations and never exports. The glass-box factory accepts only `ITrainingKey`, so a real key cannot enter it by type | Steve's request to swap for real keys later. Red team F6 |
| D6 | Real mode uses the OS transport (`SslStream`), shows metadata only, and writes no secret bytes. The glass-box engine carries a TRAINING ONLY label. Real-key routes for CE, SSH, and a DUKPT base key do not exist in this build (open item) | A teaching engine shows its keys and has had no side-channel review |
| D7 | The CE lab is SSH-2 plus TLS 1.1. A gateway bridges to the modern server. Engines are sans-IO (bytes in, bytes out, no sockets) behind `IDeviceLink`, with three links: GlassSsh, ExternalForward (`ssh.exe -L`), GlassTls11 | Steve's CE fact, 2026-11-04. The sentence has several readings, and this design stays right under each |
| D8 | C++ is a small native library (constant-time and leaky compare, timing lab). The code stays plain C-compatible so a CE compiler can take it later | Steve's "where needed in unmanaged space" |
| D9 | Electron + Vue 3 + Vuetify + Playwright, the same shell as MMP.GasPumpSimulator. Host is a .NET 10 minimal API + WebSocket | Known working stack. Lesson: spawn detached and handle EPIPE |
| D10 | Referees are outside the code under test: OpenSSL, Go `crypto/tls`, Go `x/crypto/ssh`, `ssh.exe`, a Go TCP tap, .NET 10 BCL, published vectors | Independent anchor |
| D11 | The test suite that grades the build lives in `acceptance/`. A separate agent writes it before S0. Builders never write there. A third agent runs it from a fresh clone and diffs `acceptance/` against the pinned commit | Red team F2. A builder can edit the tests it commits |
| D12 | Each slice ships its own lesson, tour, attacks, and e2e. `main` runs after every merge. The home page shows built and unbuilt lessons from the run results | Red team F10. Half a run must still be a usable course |
| D13 | DUKPT runs in separate PIN-pad and bank-HSM processes. The CE process and the gateway relay ciphertext only | Red team F8. X9.24-3 places the keys in secure devices at each end |
| D14 | The Host checks `Origin` and requires a session token on HTTP and WebSocket | Red team F6. A browser page can open a loopback socket |

## Assumptions to confirm with Steve

1. **CE SSH algorithms.** Unknown. Build both `curve25519-sha256` + `aes128-ctr` + `hmac-sha2-256` and the older `diffie-hellman-group14-sha1` + `aes128-cbc` + `hmac-sha1`.
2. **CE version.** Unknown. Target is CF 3.5, per the fence in MMP.AsyncProxy.
3. **SSH role.** Assume the CE device is the SSH client that opens a tunnel out to the gateway. Build the server side if time allows, so either direction can be shown.
4. **The one question for Steve on waking:** what runs on the box, and who starts the SSH? Readings: our code is the SSH client; an SSH binary on the box forwards a local port to our code; SSH is only how we reach the box for testing; the box is an SSH server only.
5. **DUKPT type at the site.** Unknown. AES DUKPT is built. Older hardware may use TDES DUKPT (recollection, unverified).
6. **TLS 1.1 on CE.** Unknown whether code can select it. CF `System.dll` has `ServicePointManager`, and a search found no `SecurityProtocolType`.
7. **"Real keys".** Assume test credentials and vendor test keys.

## Lessons

1. Secrets and locks: AES, modes, why ECB leaks (penguin-style picture lab).
2. Tamper seals: hash, MAC, HMAC, CMAC. Flip a bit and watch it fail.
3. Agreeing on a secret in public: X25519, then ML-KEM, then the hybrid.
4. Who are you: signatures and certificates, training CA.
5. TLS 1.3 message by message, with hybrid key exchange.
6. Key per sale: DUKPT, reader side and bank side.
7. The old world: TLS 1.1 side by side with TLS 1.3, and the downgrade attack.
8. SSH: host keys, key exchange, user auth, tunnels.
9. The bridge: CE to gateway to modern server, one PIN from reader to bank.
10. Client proof and permission: mutual TLS, signed tokens, DPoP, passkey-shaped challenge, roles vs capabilities.
11. Unmanaged space: why a compare must take the same time, C++ and C#.

Every lesson has attack buttons. Each attack names the check that caught it.

## Acceptance assertions (written before any code)

Each clause is one check. `acceptance/run.ps1` runs them from a fresh clone and writes `docs/_runs/`. Results are reported as N of M per clause, and M comes from `acceptance/clauses.json`.

| ID | Assertion | Anchor | Owning slice |
|---|---|---|---|
| A1 | AES (ECB, CBC, CTR, GCM), SHA-1, SHA-256, SHA-384, MD5, HMAC, CMAC, HKDF, X25519, Ed25519, RSA, TDES, DH group14 pass published vectors on both builds | Published vectors | S1, S4 |
| A2 | 10,000 random inputs for AES, HMAC, HKDF, and GCM match the .NET 10 BCL. 200 ML-KEM-768 rounds interoperate with .NET 10 `MLKem` in both directions | .NET 10 BCL | S1 |
| A3 | AES DUKPT matches the X9.24-3-2017 published vectors for AES-128 and AES-256 base keys. PIN-pad and bank sides agree for 1,000 sales. Used keys are absent from PIN-pad state. The tour states that a managed heap can keep copies | x9.org vectors | S2 |
| A4 | Key schedule secrets match the RFC 8448 trace byte for byte | RFC 8448 | S3 |
| A5 | Glass client completes TLS 1.3 against OpenSSL 3.5.7 and Go `crypto/tls`, with X25519 and with X25519MLKEM768. Glass server does the same if built. The referee reports the group. Clause count states which roles exist | OpenSSL, Go | S3 |
| A6 | The key log from our client equals the OpenSSL server key log for the same session | OpenSSL | S3 |
| A7 | Glass client completes TLS 1.1 against OpenSSL `-tls1_1`, for a named RSA key transport suite and a named ECDHE CBC suite. The same client gets alert 70 from a modern server. A TLS 1.3 client detects the `DOWNGRD` sentinel from OpenSSL | OpenSSL | S4 |
| A8 | Glass SSH client runs one exec and one tunnel against a Go `x/crypto/ssh` server, on the modern suite and on the legacy suite (group14-sha1, aes128-cbc, hmac-sha1, old RSA host key). A changed host key gives a named error, beside a passing control. Windows `ssh.exe` works against our server if built | Go, `ssh.exe` | S4 |
| A9 | The shared code compiles against `E:\dev\tools\netcf35-ref` with `LangVersion 3`. Each CF binary references the CF mscorlib key token. The same suite passes with CF binaries on net48. Skips match the pinned list in `acceptance/`, each with a reason. `git ls-files` finds no CF binary | CF references | All |
| A10 | End to end: PIN-pad, CE, gateway, server, and bank-HSM are separate processes, with the CE process built from CF binaries. A locked PIN block travels through SSH, then TLS 1.3 hybrid. The bank recovers it. Hop servers run once as Go `x/crypto/ssh` and Go `crypto/tls`, and once as our Gateway. One run goes through `ssh.exe -L`. A tamper at each hop gives a named error beside a passing control. CE and gateway memory traces hold no key and no clear PIN | Live run, Go referees | S5 |
| A10a | A Go TCP tap on each hop records bytes. Tap bytes equal trace bytes. Randoms differ across two runs | Go tap | S3, S5 |
| A11 | Mutual TLS, tokens, DPoP replay, and role checks each have a passing control and an attack that differs by one field and gets a named rejection. Our token verifies under a Go or .NET verifier. Passkey-shaped challenge and capabilities are cut first if time runs out | Go or .NET | S6 |
| A12 | The C++ library builds with `cl.exe` and loads from .NET 10 and from CF binaries on net48. The timing lab takes 100,000 samples per case, and the leaky compare separates from constant-time by a stated threshold on a Welch t statistic. The tour states that managed code has no constant-time guarantee | `cl.exe`, live run | S7 |
| A13 | The Electron app starts from a fresh temp clone beside sibling `MMP.AsyncProxy` and `E:\dev\tools\netcf35-ref`. Playwright walks every step of every built lesson against a live Host, never a recorded fixture. Screenshots are saved | Playwright | Each slice |
| A14 | Every tour step binds to a live trace event or is marked as a concept step. At most 30% of a lesson's steps are concept steps. A test fails on a dangling binding | Test over the tour files | Each slice |
| A15 | All tour text scores Flesch-Kincaid grade 8.9 or lower by script, and passes `tic-gate.py` | Script | Each slice |
| A15a | Each security claim in a tour cites a source section, and an agent that did not write it reads it for accuracy | Accuracy reader | Each slice |
| A16 | A real `IKeyHandle` given to the glass-box factory fails by type. Real mode runs `SslStream`, and a scan of its trace and session file finds no secret bytes. The UI labels the glass-box engine TRAINING ONLY. The UI and reports use the wording "CF-compiled, run on the desktop CLR, never run on CE" | Test, Playwright | S2, S8 |

## Slices (build order)

| Slice | Content |
|---|---|
| S0 | Skeleton: `acceptance/` first, two builds of one source tree, AsyncProxy reference, trace model, Host, Electron shell, tour engine, one live lesson end to end. Spike: a CF-compiled exe runs a socket loop on net48 |
| S1 | Primitives and ML-KEM |
| S2 | Keys seam and DUKPT |
| S3 | TLS 1.3 engine and hybrid |
| S4 | TLS 1.1 and SSH-2 |
| S5 | Gateway and the bridge |
| S6 | Authentication and permissions |
| S7 | C++ library and timing lab |
| S8 | Polish across lessons, real-mode switch, and a final red team |

Later slices read `docs/learnings.md`. Each correction goes there.

Cut order if time runs out: passkey and capabilities; glass TLS 1.3 server role; SSH server role; C# 3 for code that never reaches CE. Keep DUKPT, HMAC, TLS 1.3 client, and SSH client.

## Teaching accuracy rules (the tours must state these)

1. The gateway sees everything except the PIN block. The bridge makes things safer, and the tour lists what stays exposed.
2. The downgrade sentinel helps only a client that speaks TLS 1.3. A TLS 1.1-only device has nothing to check.
3. TLS 1.1 CBC: the explicit IV stops BEAST. MAC-then-encrypt leaves padding oracles (Lucky13). RC4 is banned by RFC 7465. RSA key transport lets an attacker record now and decrypt after a key theft. The lab forces the weak suite, because a default run picks the best case.
4. The hybrid protects key exchange only. Certificates stay classical.
5. Managed code has no constant-time guarantee. C++ results depend on the optimizer.
6. A passkey-shaped challenge is not WebAuthn.
7. Each lab carries the label: "Built to show the parts. Do not copy."
8. The course makes no compliance claims.

## Licence checklist

1. Keep X9 vectors behind a fetch script with SHA-256 and provenance.
2. Keep CF references out of the repo. A9 checks this.
3. Add third-party notices for Electron and Chromium.
4. Draw our own picture for the ECB lab.

## Non-goals

1. Production use of the glass-box engine. No FIPS validation.
2. Public release. The repo stays private until Steve says otherwise.
3. NuGet or any package publish.
4. A run on a real CE device or emulator in this overnight run. No third-party CE images get downloaded.
5. TLS 1.0, SSLv3, or attacks against any system other than our own loopback labs.

## Boundary

- **Free:** create and push the private repo, branches, PRs, merge own green PRs, pinned Go modules from the Go proxy, the x9.org vector PDF as data, loopback sockets, training keys.
- **Needs Steve:** make the repo public (ask Dave about X9 material and export rules first), publish anything, install system-wide software or services, buy anything, use any real key.
- **Failure routing:**
  - A build or test fails: fix it, or record the gap and move to the next slice. Never delete or skip a test to get green.
  - A hook or gate refuses: stop that step and report it. Never route around it.
  - A referee disagrees with our engine: the referee wins.
  - A standard or vector cannot be fetched: mark that assertion NOT RUN and name it.

## Unattended lines

- **Traded away:** latency. Nobody is waiting, so all checks run.
- **Accepted risks:** the engine shows keys by design, on loopback only, with training keys. No CE hardware proof yet.
- **Decision owner:** Steve for anything irreversible or outward-facing. Main Claude for the rest.
- **Reads:** public data class only. Holds no private data, so it lacks one leg of the lethal trifecta.

## Kill condition

The work ends when every clause in `acceptance/clauses.json` has a recorded result, or at 2026-11-05 09:00 local, whichever comes first.
The first line of the closing report is one PowerShell command that opens the app. The report states N of M per clause, with the command output in `docs/_runs/`, and names every clause not met.

## Closest prior art

- **Shape:** an observable protocol state machine with a tutorial on top.
- **Closest:** The Illustrated TLS 1.3 Connection (static bytes), Wireshark with a key log (live, no teaching), MMP.GasPumpSimulator (live sim with attacks).
- **Where we differ:** live traffic from our own open engine, the same code on .NET 10 and CF 3.5, and the learner can attack each step.
- **Arithmetic:** one learner on loopback, a few hundred trace events per handshake, about 2 KB each. A session stays under 10 MB. No store or queue is needed beyond a capped in-memory list and an NDJSON session file.
- **Gems checked:** `INDEX.md` has no crypto or tour gem. `seeded-hash-linked-custody-chain` is related to the tamper lesson only. `server-replaces-never-merges` applies to the UI store.
