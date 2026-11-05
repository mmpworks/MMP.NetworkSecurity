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
   The course must show how an old device and a new server meet safely.

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
| D5 | Training keys sit behind `IKeySource`. Transports sit behind a factory: glass-box or OS | Steve's request to swap for real keys later |
| D6 | Real secrets use the OS transport (`SslStream`). The glass-box engine carries a TRAINING ONLY label | A teaching engine shows its keys and has had no side-channel review |
| D7 | The CE lab is SSH-2 plus TLS 1.1. A gateway bridges to the modern server | Steve's CE fact, 2026-11-04 |
| D8 | C++ is a small native library (constant-time and leaky compare, timing lab). The code stays plain C-compatible so a CE compiler can take it later | Steve's "where needed in unmanaged space" |
| D9 | Electron + Vue 3 + Vuetify + Playwright, the same shell as MMP.GasPumpSimulator. Host is a .NET 10 minimal API + WebSocket | Known working stack. Lesson: spawn detached and handle EPIPE |
| D10 | Referees are outside the code under test: OpenSSL, Go `crypto/tls`, Go `x/crypto/ssh`, `ssh.exe`, .NET 10 BCL, published vectors | Independent anchor |

## Assumptions to confirm with Steve

1. **CE SSH algorithms.** Unknown. Build both `curve25519-sha256` + `aes128-ctr` + `hmac-sha2-256` and the older `diffie-hellman-group14-sha1` + `aes128-cbc` + `hmac-sha1`.
2. **CE version.** Unknown. Target is CF 3.5, per the fence in MMP.AsyncProxy.
3. **SSH role.** Assume the CE device is the SSH client that opens a tunnel out to the gateway. Build the server side too, so either direction can be shown.

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

Each is checked by a command. Results go in `docs/_runs/`. Every count is reported as N of M.

| ID | Assertion | Anchor | Owning slice |
|---|---|---|---|
| A1 | AES, SHA-1, SHA-256, SHA-384, MD5, HMAC, CMAC, HKDF, GCM, X25519, Ed25519 pass the published vectors on both builds | Published vectors | S1 |
| A2 | 10,000 random inputs for AES, HMAC, HKDF, and GCM match the .NET 10 BCL. 200 ML-KEM-768 rounds interoperate with .NET 10 `MLKem` in both directions | .NET 10 BCL | S1 |
| A3 | AES DUKPT matches the X9.24-3-2017 published vectors for AES-128 and AES-256 base keys. Reader and bank sides agree for 1,000 sales. Old keys are gone from reader state | x9.org vectors | S2 |
| A4 | Key schedule secrets match the RFC 8448 trace byte for byte | RFC 8448 | S3 |
| A5 | Glass client and server each complete TLS 1.3 against OpenSSL 3.5.7 and Go `crypto/tls`, with X25519 and with X25519MLKEM768. The referee reports the group | OpenSSL, Go | S3 |
| A6 | The key log from our client equals the OpenSSL server key log for the same session | OpenSSL | S3 |
| A7 | Glass client completes TLS 1.1 against OpenSSL `-tls1_1`. A modern server refuses it. The TLS 1.3 downgrade sentinel is detected | OpenSSL, Go | S4 |
| A8 | Glass SSH client works against a Go `x/crypto/ssh` server, including one exec and one tunnel. Windows `ssh.exe` works against our server. A changed host key is refused | Go, `ssh.exe` | S4 |
| A9 | The shared code compiles against `E:\dev\tools\netcf35-ref` with `LangVersion 3`. The same test suite passes with the CF binaries on net48. Skips are named | CF references | All |
| A10 | End to end: a CF-binary process sends a DUKPT-locked PIN block through SSH to the gateway, then TLS 1.3 hybrid to the server. The server recovers the PIN block. The trace spans both hops. A tamper at each hop fails by name | Live run, observed from outside the app | S5 |
| A11 | Mutual TLS, tokens, DPoP replay, passkey-shaped challenge, role and capability checks: each has a passing case and at least one failing attack. Our token verifies under a Go or .NET verifier | Go or .NET | S6 |
| A12 | The C++ library builds with `cl.exe`, loads from .NET 10 and from CF binaries on net48, and the timing lab shows leaky vs constant-time as measured numbers | `cl.exe`, live run | S7 |
| A13 | The Electron app starts from a clean checkout. Playwright walks every step of every tour. Every lesson is reachable. Screenshots are saved | Playwright | S8 |
| A14 | Every tour step binds to a live trace event or is marked as a concept step. A test fails on a dangling binding | Test over the tour files | S8 |
| A15 | All tour text scores Flesch-Kincaid grade 8.9 or lower by script, and passes `tic-gate.py` | Script | S8 |
| A16 | A test swaps `IKeySource` from training keys to a file source, and the labs still pass. The UI labels the glass-box engine TRAINING ONLY | Test, Playwright | S2, S8 |

## Slices (build order)

| Slice | Content |
|---|---|
| S0 | Skeleton: two builds of one source tree, AsyncProxy reference, trace model, Host, Electron shell, tour engine, one live lesson end to end |
| S1 | Primitives and ML-KEM |
| S2 | Keys seam and DUKPT |
| S3 | TLS 1.3 engine and hybrid |
| S4 | TLS 1.1 and SSH-2 |
| S5 | Gateway and the bridge |
| S6 | Authentication and permissions |
| S7 | C++ library and timing lab |
| S8 | All tours, attack buttons, e2e, polish, and a final red team |

Later slices read `docs/learnings.md`. Each correction goes there.

## Non-goals

1. Production use of the glass-box engine. No FIPS validation.
2. Public release. The repo stays private until Steve says otherwise.
3. NuGet or any package publish.
4. A run on a real CE device or emulator in this overnight run. No third-party CE images get downloaded.
5. TLS 1.0, SSLv3, or attacks against any system other than our own loopback labs.

## Boundary

- **Free:** create and push the private repo, branches, PRs, merge own green PRs, pinned Go modules from the Go proxy, the x9.org vector PDF as data, loopback sockets, training keys.
- **Needs Steve:** make the repo public, publish anything, install system-wide software or services, buy anything, use any real key.
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

The work ends when A1 to A16 each have a recorded result, or at 2026-11-05 00:00 local, whichever comes first.
The closing report states N of 16 with the command output in `docs/_runs/`, and names every assertion not met.

## Closest prior art

- **Shape:** an observable protocol state machine with a tutorial on top.
- **Closest:** The Illustrated TLS 1.3 Connection (static bytes), Wireshark with a key log (live, no teaching), MMP.GasPumpSimulator (live sim with attacks).
- **Where we differ:** live traffic from our own open engine, the same code on .NET 10 and CF 3.5, and the learner can attack each step.
- **Arithmetic:** one learner on loopback, a few hundred trace events per handshake, about 2 KB each. A session stays under 10 MB. No store or queue is needed beyond a capped in-memory list and an NDJSON session file.
- **Gems checked:** `INDEX.md` has no crypto or tour gem. `seeded-hash-linked-custody-chain` is related to the tamper lesson only. `server-replaces-never-merges` applies to the UI store.
