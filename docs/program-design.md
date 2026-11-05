# MMP.NetworkSecurity: program design

Author: Richard. Date: 2026-11-04. Status: ready to build. Inputs: `docs/prd.md` (with D11 to D14), `docs/ux-design.md`.
## Conclusion
1. One C# 3 source folder, `src/NetSec.Core`, compiles into two binaries with one assembly name: net10.0 and CF 3.5.
2. Protocol engines take bytes in and return bytes out. They hold no socket, no thread, and no future.
3. A rule returns a `StepDecision`. One interpreter applies the effects, so each effect emits its trace event by construction.
4. `EnginePump` is the only code that joins an engine to a socket. It runs C# 3 iterators on MMP.AsyncProxy on both builds.
5. The CE process is a CF-compiled exe on net48. `CeProfile` allows SSH and TLS 1.1, and refuses TLS 1.3 by a named code.
6. The Host adopts the event fields and WebSocket commands in `ux-design.md` section 0, plus the additions in section 5.

Style: modular monolith plus lab node processes. The arithmetic is in the PRD: one learner, a session under 10 MB, no store or queue.
### New evidence from this design pass (2026-11-04, this machine)
| Probe | Result | Effect |
|---|---|---|
| `ilspycmd` on `netcf35-ref` | Absent: `BigInteger`, `Span`, `HMAC`, `SHA256`, `SHA512`, `Aes`, `HashSet`, `DateTimeOffset`, `ThreadStatic`, `Assembly.GetReferencedAssemblies`, `Encoding.GetString(byte[])`. Present: `Stopwatch`, `RandomNumberGenerator.Create`, `DllImportAttribute`, `Socket.Begin{Connect,Accept,Send,Receive}`, `GC.GetTotalMemory`, `ThreadPool.SetMaxThreads` | No BCL math. Use the 3-argument `GetString`. Binary proof runs from outside the exe |
| Throwaway CF exe (socket, AsyncProxy, `DllImport`, `Stopwatch`), default SDK config | **Printed nothing, exit 0.** The SDK writes `supportedRuntime v2.0.50727` | Silent false success. Section 6 fixes the config, and the Host requires a ready line |
| Same exe, `App.config` with `v4.0`, `GenerateSupportedRuntime=false` | `ok hello pool=True/25/25 ptr=8 clr=4.0.30319.42000` | This closes the S0 spike in the PRD. Pointers are 64-bit |
| Same source, net10.0, `LangVersion 3`, AsyncProxy `netstandard2.0` | `ok hello pool=True/25/25 clr=10.0.14` | C# 3 iterators and sockets work on both builds |
| `openssl ciphers -v 'ALL:@SECLEVEL=0'` | `AES128-SHA` (Kx=RSA), `ECDHE-RSA-AES128-SHA` listed | A7 suite names |
| PATH | `openssl` also resolves to FireDaemon. Git Bash `ssh` is `/usr/bin/ssh`. `cl` is off PATH | Referees use pinned paths (section 9) |

Consultation. Gems used: `server-replaces-never-merges`, `fail-soft-must-count`, `paths-plain-at-the-boundary`, `decide-at-authoritative-boundary`, `plain-sentence-error-surface`. No gem covers a sans-IO table engine, so it is a candidate after S4. Catalog: closest shape is a multi-step process with independent failure per step. Taken: name each step's failure. Rejected: queues and caches. "Sans-IO" as a pattern name (`rustls`, `h11`) is recollection, unverified this session.
## 1. Module layout
| Path | TFM, language | Owns |
|---|---|---|
| `src/NetSec.Core` | net10.0, C# 3 | All shared source. Assembly `NetSec.Core` |
| `src/NetSec.Core.NetCF` | net35 on CF refs, C# 3, `NETCF` | No source: `Compile Include="..\NetSec.Core\**\*.cs"`. Assembly `NetSec.Core` |
| `src/NetSec.CeDevice` | net35 on CF refs, C# 3, Exe | The CE process (section 6) |
| `src/NetSec.Node` | net10.0, C# 14, Exe | Thin main: `--role pinpad, gateway, server, bankhsm`. Logic lives in `Core/Bridge` (D13) |
| `src/NetSec.Host` | net10.0, C# 14 | Minimal API, WebSocket, sessions, process control, `OsTransportFactory` |
| `native/` | C-compatible C++ | `netsec_ct.dll` (section 7) |
| `app/` | Electron, Vue 3, Vuetify | UI per `ux-design.md`. Tours in `app/src/tours/` |
| `acceptance/referees/bcl` | net10.0, C# 14 | Line oracle on stdin and stdout, so net48 tests reach `MLKem` and `AesGcm` with no skip |
| `acceptance/referees/go` | Go 1.26, `x/crypto` v0.58.0 | `tlspeer`, `sshpeer`, `gogateway`, `tap`, `tokenverify` |
| `tests/NetSec.Tests` | net10.0, net48, C# latest | Builder unit suite. net48 uses `HintPath` to CF binaries, as in MMP.AsyncProxy |
| `acceptance/` | net10.0, net48, pwsh | D11. Separate author. **Builders never write here.** `run.ps1`, `clauses.json`, pinned skip list |
| `tools/` | pwsh, python | `gate.ps1`, `layer_check.py`, `tour_lint.py`, `lessons_status.py` |

Root `Directory.Build.props`: `ShouldUnsetParentConfigurationAndPlatform=false`, `Nullable=disable`, `ImplicitUsings=disable`, `TreatWarningsAsErrors=true`, `AsyncProxyRoot` (default `..\MMP.AsyncProxy`). `LangVersion` stays per project. `.gitignore` keeps `bin/`, `obj/`, and CF binaries out (A9). MMP.AsyncProxy stays unchanged.

Folders inside `NetSec.Core`. Dependencies point down the table. `tools/layer_check.py` reads `using` lines and fails on an upward edge, or on `#if NETCF` outside `Platform`.
| Folder | Public surface | May use |
|---|---|---|
| `Bytes`, `Errors` | `ByteReader`, `ByteWriter`, `Hex`, `MiniJson`, `NetSecError`, `ErrorCodes` | nothing |
| `Crypto` | Section 2.3 and section 4 | `Bytes` |
| `Platform` | `OsRandom`, `SeededRandom`, `MonotonicClock`, `FixedClock` | `Crypto` |
| `Trace` | `TraceEvent`, `TraceStream`, `ITraceSink`, `TraceJson` | `Bytes` |
| `Keys`, `Pki` | `ITrainingKey`, `IKeyHandle`, `TrainingKeySource`, `Der`, `Certificate`, `TrainingCa`, `ChainCheck` | `Crypto` |
| `Machine` | `StepTable`, `StepDecision`, `IProtocolEngine`, `ITamperHook` | `Trace`, `Errors` |
| `Tls13`, `Tls11`, `Ssh` | `CreateClient(options)`, `CreateServer(options)` returning `IProtocolEngine` | `Machine`, `Crypto`, `Pki`, `Keys` |
| `Dukpt` | `DukptPinPad`, `DukptBank`, `PinBlock` | `Crypto` |
| `Auth` | `Token`, `DpopProof`, `Challenge`, `AccessRules` | `Crypto`, `Keys` |
| `Io` | `IByteLink`, `SocketLink`, `MemoryLink`, `EnginePump`, `IStepGate`, `ITransportFactory`, `GlassTransportFactory`, `TransportPolicy`. The only AsyncProxy and socket use | all above |
| `Bridge` | `PinEnvelope`, `IDeviceLink`, `PinPadCore`, `CeDeviceFlow`, `GatewayCore`, `ServerCore`, `BankHsmCore`, `DeviceProfile`, `BudgetJudge` | all above |
| `Native` | `NativeCompare`, `ManagedCompare`, `TimingLab`, `TimingJudge` | `Errors`, `Trace` |
| `Labs` | `ILab`, `LabCatalog`, `AttackCatalog`. One file per lesson | all above |
## 2. Key types and signatures
All C# 3. These public signatures are the contract `acceptance/` compiles against. A parse failure throws `ParseFailure` inside an engine and leaves `Feed` as an `EngineOutput` error.
### 2.1 Trace event (D4)
```csharp
public sealed class TraceEvent {            // Immutable. Byte arrays are copied at construction.
  public readonly int Schema;               // 1
  public readonly string EventId;           // StreamId + "#" + StreamSeq. Stable.
  public readonly string StreamId;          // "<sessionId>/<actor>/<protocol>", one per engine
  public readonly long StreamSeq;           // Per stream, from 1. Same across a same-seed rerun.
  public readonly string SessionId, TraceId, Hop;   // TraceId spans both bridge hops
  public readonly string Actor, From, To;
  public readonly string Type, Message, Step;       // "tls.handshake.sent", "ServerHello", table row id
  public readonly byte[] Wire, Plain;
  public readonly TraceField[] Fields;      // { Name, Offset, Length, Kind, VisibleToWire, Gloss }
  public readonly TraceSecret[] Secrets;    // { Holder, Name, Bytes, DerivedFrom[] }
  public readonly TraceCheck Check;         // { Id, Name, Passed, Code, Detail }
  public readonly string WaitingFor;
  public readonly long AtMicros;
}
public interface ITraceSink { void Write(TraceEvent e); }   // NullSink, ListSink, NdjsonLinkSink
public static class TraceJson { public static string ToLine(TraceEvent e); }   // One writer for both builds
```
The Host adds the session-wide `seq` at ingest (UX section 0). `Fields` come from `ByteReader` calls that record name, offset, and length, so the decoder and the parser cannot drift. `Gloss` is a key into `app/src/field-gloss.json`, so English stays out of the CF binary and A15 scans one place.
### 2.2 Keys and transports (D5, D6, D7)
```csharp
public interface ITrainingKey { string KeyId {get;} KeyAlgorithm Algorithm {get;} byte[] CopyMaterial(); byte[] CopyPublic(); }
public interface IKeyHandle   { string KeyId {get;} KeyAlgorithm Algorithm {get;} byte[] Public(); byte[] Sign(byte[] message); }  // No export
public interface ITrainingKeySource { ITrainingKey Find(string keyId); }   // TrainingKeySource
public interface IKeyHandleSource   { IKeyHandle Find(string keyId); }     // Host only, wraps an OS certificate store
public static class KeyIds { CaRoot, ServerTlsEd25519, ServerTls11Rsa, SshHostEd25519, SshHostRsa, SshClient, DukptBdk128, DukptBdk256, TokenIssuer, AttackerEd25519 }

public enum WireProtocol { Tls13, Tls11, Ssh }
public sealed class TransportRequest { WireProtocol Protocol; EngineRole Role; KexGroup Group; SshSuite Suite; IByteLink Link;
    IRandomSource Random; ITraceSink Sink; IStepGate Gate; ITamperHook Tamper; string TraceId, Hop, PeerName; DeviceProfile Profile; }
public interface ITransportFactory { string Kind {get;}  IFuture<ISecureChannel> Open(TransportRequest request); }
public sealed class GlassTransportFactory : ITransportFactory { public GlassTransportFactory(ITrainingKeySource keys); }
public interface ISecureChannel { ChannelInfo Info {get;} IFuture<AppChunk> Receive(); IFuture Send(int channel, byte[] bytes); IFuture Close(); }
public static class TransportPolicy { public static TransportDecision Decide(DeviceProfile profile, string factoryKind, WireProtocol protocol); }

public interface IDeviceLink { string Kind {get;} IFuture Open(); IFuture Send(byte[] frame); IFuture<byte[]> Receive(); IFuture Close(); }
// GlassSshLink, ExternalForwardLink (plain socket into a port that ssh.exe -L forwards), GlassTls11Link
```
The factory takes its key source at construction and `TransportRequest` carries no key. So `IKeyHandle` has no route into glass (D5). `Core` holds no `IKeyHandle` implementation. Real mode is `OsTransportFactory` in the Host: `SslStream`, TLS only, emitting metadata fields (protocol, suite, group name) and no secret bytes (D6, A16). Real-key routes for CE, SSH, and DUKPT do not exist. `TransportPolicy` refuses TLS 1.3 under `CeProfile` with `CE_TRANSPORT_UNAVAILABLE`. `TrainingKeySource` derives each key as SHAKE256(`"MMP.NetworkSecurity training"` + keyId). The RSA keys are literal hex made once by OpenSSL. All of it reads in source.
### 2.3 Crypto primitives
```csharp
public interface IHash { int DigestSize {get;} int BlockSize {get;} void Update(byte[] b,int off,int n); byte[] Finish(); IHash Clone(); }
public static class Hashes { IHash Md5(); Sha1(); Sha256(); Sha384(); Sha512(); Sha3_256(); Sha3_512(); }
public sealed class Shake { static Shake New128(); New256(); void Absorb(byte[],int,int); void Squeeze(byte[],int,int); }
public static class Hmac  { static byte[] Compute(Func<IHash> h, byte[] key, byte[] data); }
public static class Hkdf  { static byte[] Extract(Func<IHash> h, byte[] salt, byte[] ikm); Expand(Func<IHash> h, byte[] prk, byte[] info, int n); }
public sealed class AesKey  { AesKey(byte[] key); void EncryptBlock(byte[] i,int io,byte[] o,int oo); void DecryptBlock(...); }
public sealed class TdesKey { TdesKey(byte[] key); void EncryptBlock(...); void DecryptBlock(...); }
public static class Modes { byte[] EcbEncrypt(AesKey,byte[]); CbcEncrypt(AesKey,byte[] iv,byte[]); CbcDecrypt(...); Ctr(AesKey,byte[] counter,byte[]); }
public static class Cmac { static byte[] Compute(AesKey k, byte[] message); }
public static class Gcm  { static byte[] Seal(AesKey k, byte[] nonce, byte[] aad, byte[] plain);   // cipher + 16-byte tag
                           static bool TryOpen(AesKey k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain); }
public static class X25519  { static byte[] Mult(byte[] scalar, byte[] point); MultBase(byte[] scalar); }
public static class Ed25519 { static byte[] PublicFrom(byte[] seed); Sign(byte[] seed, byte[] msg); static bool Verify(byte[] pub, byte[] msg, byte[] sig); }
public static class MlKem768 { static MlKemPair KeyGen(byte[] d, byte[] z); static MlKemSealed Encaps(byte[] ek, byte[] m); static byte[] Decaps(byte[] dk, byte[] c); }
public sealed class RsaPublic { RsaPublic(BigUInt n, BigUInt e); byte[] Raw(byte[] m); }   // RsaPrivate(n, d) mirrors it
public static class Pkcs1 { byte[] EncryptV15(RsaPublic,IRandomSource,byte[]); bool TryDecryptV15(RsaPrivate,byte[],out byte[]); bool VerifySha1(...); VerifySha256(...); byte[] SignSha1(...); }
public static class DhGroup14 { static byte[] Public(byte[] x); Shared(byte[] x, byte[] peer); }
public interface IRandomSource { void Fill(byte[] b, int off, int n); }
```
### 2.4 Engine, table, decision
```csharp
public interface IProtocolEngine { EngineStatus Status {get;} EngineOutput Start(); EngineOutput Feed(byte[] b,int off,int n); EngineOutput Command(EngineCommand c); }
public sealed class EngineOutput { byte[] Wire; AppChunk[] App; TraceEvent[] Events; EngineStatus Status; NetSecError Error; }
public delegate StepDecision StepRule<TSession>(TSession session, InboundMessage message);
public sealed class StepRow<TSession> { string Step; string From; int MessageType; StepRule<TSession> Rule; string To; }
public sealed class StepTable<TSession> { StepTable(params StepRow<TSession>[] rows); StepRow<TSession> Find(string state, int type); string[] Steps {get;} }
public sealed class StepDecision {          // A value. A rule runs no side effect.
  public readonly StepOutcome Outcome;      // Advance, Stay, Fail
  public readonly StepEffect[] Effects;     // Applied in order by the interpreter
  public readonly NetSecError Error;
  public static StepDecision Advance(params StepEffect[] e); Stay(params StepEffect[] e); Fail(string code, string checkName, string detail);
}
public static class Effect {                // Each maps to one trace event type
  StepEffect Absorb(byte[] message); Send(string message, byte[] body, TraceField[] fields);   // Plain tamper point runs in Send
  StepEffect Secret(string holder, string name, byte[] value, params string[] from);
  StepEffect InstallKeys(Direction d, string suite, byte[] key, byte[] iv);
  StepEffect Check(string name, string code); Deliver(int channel, byte[] plain); Note(string type, string message);
}
```
A rule reads the session, clones the transcript to compute, and returns effects. A test calls a rule with no engine. `Machine/Interpreter.cs` holds the one switch over effect kinds. An inbound message with no row gives `UNEXPECTED_MESSAGE`, naming state and type.
### 2.5 Tamper hook and errors
```csharp
public enum TamperPoint { Plain, Wire }     // Before protection, or the bytes on the socket
public interface ITamperHook { TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes); }
public sealed class TamperPlan : ITamperHook { /* data: kind, stream, streamSeq or message, offset, xor, replacement */ }
public sealed class NetSecError { string Code; string Message; string CheckName; string Step; bool Retryable; string TraceId; }
public sealed class AttackDefinition { string AttackId; int Lesson; string Kind; TamperPlan Plan; LabOption[] Options; AttackOutcome Expect; string ExpectCode, ExpectCheck; }
```
The hook addresses a message by `(streamId, streamSeq)`. The UI sends `atSeq`, and the Host translates it through the session list. Two engines can interleave differently between reruns, but each stream's own order stays fixed, so a fork hits the same message. `AttackCatalog` is the one list of attacks. A test runs every row beside a passing control and compares `ExpectCode` and `ExpectCheck`. `NoCheck` rows (ECB, CBC flip) assert the absence of a failed check.
### 2.6 State machines
Each row is one `StepRow`. Each code is a stable string in `ErrorCodes`. Server tables mirror the client in their own files and are cut in the PRD's order.

**TLS 1.3 client.** One group per run in `supported_groups` and `key_share`: `x25519` or `X25519MLKEM768` (0x11EC). Suites: `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`. Signature: `ed25519` only, because the training CA issues Ed25519 certificates and both referees accept them. Rows `tls13.c.*`:
| Step | From | Message | Check, failure code | To |
|---|---|---|---|---|
| `hello` | Start | (Start) | none. Key shares, Absorb, Send | WaitServerHello |
| `sh` | WaitServerHello | ServerHello | `TLS13_DOWNGRADE_SENTINEL`, `TLS13_VERSION_REFUSED`, `TLS13_HRR_UNSUPPORTED`. Secrets, InstallKeys | WaitEE |
| `ee` | WaitEE | EncryptedExtensions | group unchanged | WaitCertOrReq |
| `creq` | WaitCertOrReq | CertificateRequest | none. Mark client auth | WaitCert |
| `cert` | WaitCertOrReq, WaitCert | Certificate | `CHAIN_NO_ANCHOR`, `CERT_VALIDITY`, `CERT_NAME`, `CERT_SIGNATURE` | WaitCertVerify |
| `cv` | WaitCertVerify | CertificateVerify | `TLS13_CERTVERIFY_BAD` | WaitFinished |
| `fin` | WaitFinished | Finished | `TLS13_FINISHED_MISMATCH`. App secrets, Send Finished, InstallKeys | Open |
| `ticket` | Open | NewSessionTicket | none. Note (ignored) | Open |
| `keyupdate` | Open | KeyUpdate | `TLS13_KEYUPDATE_UNSUPPORTED` | Failed |

Record failure: `TLS13_AEAD_TAG`. Dummy `change_cipher_spec` gives a Note. `Tls13KeySchedule` is pure, so A4 runs on it alone. `KeyLog.Line(label, clientRandom, secret)` writes NSS format for A6.

**TLS 1.1 client.** Named suites: `TLS_RSA_WITH_AES_128_CBC_SHA` (record now, decrypt after key theft), `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` on X25519. The lab forces the weak suite per accuracy rule 3. Explicit IV, MD5 and SHA-1 PRF, MAC then encrypt. Rows `tls11.c.*`:
| Step | From | Message | Check, failure code | To |
|---|---|---|---|---|
| `hello` | Start | (Start) | none | WaitServerHello |
| `sh` | WaitServerHello | ServerHello or alert 70 | `TLS11_ALERT_PROTOCOL_VERSION` | WaitCert |
| `cert` | WaitCert | Certificate | chain codes above | WaitSkeOrDone |
| `ske` | WaitSkeOrDone | ServerKeyExchange | `TLS11_SKE_SIGNATURE` | WaitDone |
| `done` | WaitSkeOrDone, WaitDone | ServerHelloDone | none. Sends ClientKeyExchange, CCS, Finished | WaitCcs |
| `ccs` | WaitCcs | ChangeCipherSpec | none | WaitFinished |
| `fin` | WaitFinished | Finished | `TLS11_FINISHED_MISMATCH` | Open |

Record failure: `TLS11_RECORD_MAC`, same code for bad padding. `GlassTls11Link` uses this client. The gateway needs the server table for that link.

**SSH-2.** Version line, then packets. `Modern`: `curve25519-sha256`, `aes128-ctr`, `hmac-sha2-256`, `ssh-ed25519` host key. `Legacy`: `diffie-hellman-group14-sha1`, `aes128-cbc`, `hmac-sha1`, `ssh-rsa` host key (A8). Rows `ssh.c.*`:
| Step | From | Message | Check, failure code | To |
|---|---|---|---|---|
| `version` | Start | Version line | `SSH_VERSION` | WaitKexInit |
| `kexinit` | WaitKexInit | KEXINIT | `SSH_NO_COMMON_ALG` | WaitKexReply |
| `kexreply` | WaitKexReply | KEX_ECDH_REPLY, KEXDH_REPLY | `SSH_HOST_KEY_CHANGED`, `SSH_EXCHANGE_SIGNATURE` | WaitNewKeys |
| `newkeys` | WaitNewKeys | NEWKEYS | none. InstallKeys | WaitServiceAccept |
| `service` | WaitServiceAccept | SERVICE_ACCEPT | none | WaitAuth |
| `auth` | WaitAuth | USERAUTH_SUCCESS, FAILURE, PK_OK | `SSH_AUTH_REFUSED` | Authenticated |
| `chan.*` | Authenticated | CHANNEL_* | `SSH_CHANNEL_UNKNOWN`, `SSH_TUNNEL_REFUSED` | Authenticated |

Packet failure: `SSH_PACKET_MAC`. Rekey gives `SSH_REKEY_UNSUPPORTED`. **Our SSH server starts no process.** Exec dispatches to a fixed table (`echo`, `whoami`). `direct-tcpip` opens only allow-listed loopback targets.
## 3. Socket IO and sans-IO testing
```csharp
public interface IByteLink { IFuture<int> Read(byte[] b,int off,int n); IFuture Write(byte[] b,int off,int n); void Close(); }
public interface IStepGate { IFuture Pass(TraceEvent e); }   // FreeRunGate returns Futures.Completed
public sealed class EnginePump {
  public EnginePump(IProtocolEngine engine, IByteLink link, ITraceSink sink, IStepGate gate, ITamperHook tamper, int deadlineMs);
  public IFuture<PumpResult> Run(); public IFuture Enqueue(EngineCommand command);
}
```
`SocketLink` wraps the four Begin/End pairs with `Futures.FromAsync`. `Write` loops on a partial send. The pump runs two iterators through `AsyncProxy.Run`:
1. **Read loop.** `Read`, then `Feed` under a short `lock`, then append output to the outbox, then yield until the outbox drains. The engine cannot run ahead of the gate.
2. **Outbox loop.** The only code that touches the gate, the Wire tamper point, the sink, and `Write`. For each event: `yield return gate.Pass(e)`, then the sink. Then the wire bytes.

Wake-up uses a fresh `Promise` per wait, because CF has no `Monitor.Wait`. A nested iterator publishes with `foreach (IFuture f in Publish(o)) yield return f;`. C# forbids `yield` inside a `try` with `catch`, so failure handling is `yield return Futures.Observe(read); if (read.IsFaulted) ...`. Free run adds a deadline with `Futures.WhenAny(read, Futures.Delay(ms))`. A timeout closes the link and reports `LINK_DEADLINE`, because a Begin read has no cancel. Step mode has no deadline, since a learner can read for an hour.

**Tests need no socket.** `EngineDuel.Run(client, server)` passes `Wire` between two engines in a plain loop on one thread. `MemoryLink.Pair()` tests the pump with no port. RFC 8448 runs on `Tls13KeySchedule` alone. Referee tests use sockets because the referee does.

**Step gating (UX 3.2).** `StepGate` holds one pending `Promise` per waiter, and `session.step` releases one. A node process uses `RemoteStepGate`: it sends the event on the trace link and waits for one go byte back.

**Cross-build equality.** Run a lab with a fixed seed and `FixedClock` on each build. Sort NDJSON by `(StreamId, StreamSeq)` and compare bytes. A difference is a fault in shared code.
## 4. Big integer, field arithmetic, ML-KEM in C# 3
The CF references have no `BigInteger` and no `Span` (verified above). The net10 build uses the same code. Methods take `(byte[], offset, count)`, the `Stream` idiom.
| Need | Type | Representation | Method | Check |
|---|---|---|---|---|
| X25519, Ed25519 field | `Fe25519` | `long[16]`, 16-bit limbs | Carry, schoolbook multiply, invert by exponent | RFC 7748, RFC 8032 |
| Ed25519 group, scalars | `Ge25519`, `Sc25519` | Extended coordinates. `long[64]` for mod L | Double and add, reduce mod L | RFC 8032, Go |
| RSA, DH group 14 | `BigUInt` | Immutable `uint[]`, little-endian, `ulong` carries | Schoolbook multiply, Knuth D, Montgomery CIOS, 4-bit window | Vectors, OpenSSL, Go |
| ML-KEM polynomials | `Poly` | `int[256]`, q = 3329 | NTT per FIPS 203 Alg 9 to 12 | Vectors, .NET `MLKem` |
| GHASH | `Gf128` | Two `ulong` | Shift and xor per block | SP 800-38D |
| SHA-3, SHAKE | `Keccak` | `ulong[25]` | Keccak-f[1600] | NIST vectors |

1. **Names follow the standard.** `MlKem768` internals carry FIPS 203 names: `KPke.Encrypt`, `SamplePolyCbd`, `SampleNtt`, `ByteEncode`, `Compress`. Parameters are one data row, so 512 and 1024 stay cheap to add.
2. **Arithmetic is the one mutation exception.** `Fe25519`, `Ge25519`, `Poly` write into caller-owned arrays, private to `Crypto`. Everything public returns new arrays. DUKPT registers mutate by design, because erasure is the point. The tour states a managed heap can keep copies (A3).
3. **Nothing claims constant time** outside `native/` and `ManagedCompare`, and accuracy rule 5 limits that claim.
4. **DH exponent.** `x` is 512 random bits, which cuts a device's work about 4 times. The peer value must be in `[2, p-2]`.
5. **PRD addition.** Ed25519 needs SHA-512, and ML-KEM needs SHA-3 and SHAKE. A1 omits them. Builder tests carry them. The acceptance author should add clauses.

Complexity hotspots: `BigUInt.DivRem`, `ByteEncode`, the SSH channel window, record reassembly. Each gets a small type and a comment on how the logic works.
## 5. Host contract
Bind `127.0.0.1:5180` only (`NETSEC_PORT` overrides). D14: allow-listed `Origin` (`file://`, `http://localhost:4180`, `http://localhost:5173`) and a session token on every request. Electron generates `NETSEC_TOKEN`, passes it to the Host by env and to the renderer by preload. HTTP uses `Authorization: Bearer`. WebSocket uses `/ws?token=`. Failures: `HOST_ORIGIN_REFUSED`, `HOST_TOKEN_REFUSED`.
| REST | Returns |
|---|---|
| `GET /api/health` | `{ schema, build, referees }` |
| `GET /api/lessons` | `{ lesson, title, labId, lanes[], attacks[], built, lastRun }`. `built` and `lastRun` come from `docs/_runs/lessons.json` (D12) |
| `GET /api/sessions/{id}/events?after=N` | Stored events after `seq` N. The UI replaces its copy from this on reconnect |
| `GET /api/sessions/{id}/keylog` | NSS key log. Refused in real mode |
| `GET /api/ce`, `POST /api/ce/start`, `POST /api/ce/stop` | Section 6 |

WebSocket `/ws`, JSON text frames, UX command names. One change to the UX text: `session.attack` also accepts `{attackId}`.
| Client to Host | Host to client |
|---|---|
| `session.start {requestId, lesson, seed, mode, transport: glass or real}` | `session.started {requestId, sessionId, seed, transportKind, trainingOnly}` |
| `session.step`, `session.run`, `session.pause` | `trace {sessionId, seq, event}` |
| `session.attack {requestId, sessionId, attackId}` or `{atSeq, kind, offset, xor}` | `session.forked {sessionId, parentId, attackId}` |
| `session.load {file}`, `session.save {sessionId}` | `session.finished {sessionId, outcome, code, check}` |
| | `error {requestId, code, message, retryable}` |

| UX concept | Host source |
|---|---|
| Lesson rail, home page | `LabCatalog` row plus `built`. Unbuilt lessons show and say so (D12) |
| Tour step, `bind.kind: event` | First `trace` whose `event.type` and `match` fit. `match` tests `actor`, `message`, `step` |
| Tour step, `concept` | No event. A test caps these at 30% per lesson (A14) |
| Attack button | `AttackCatalog` row. Starts a forked session with the same seed |
| TRAINING ONLY chip | `session.started.trainingOnly`, true when `factory.Kind == "glass"` |
| Secrets panel | `event.secrets[]`. Empty in real mode |
| CE label | The A16 wording: "CF-compiled, run on the desktop CLR, never run on CE" |

Additions to UX section 0: `eventId`, `streamId`, `streamSeq`, `message`, `step`, `schema`. `check` gains `id`. `fields[].gloss` is a key. `SessionManager` keeps the last 20 sessions in memory, capped at 20,000 events each, and appends NDJSON to `%LOCALAPPDATA%\MMP.NetworkSecurity\sessions\`. Per-client outbound is a bounded channel with drop-oldest and a visible `droppedEvents` counter.
```csharp
public interface ILab { string LabId {get;} IFuture<LabResult> Run(LabContext context); }
public sealed class LabContext { int Seed; ITransportFactory Transports; IStepGate Gate; ITraceSink Sink; IClock Clock; IRandomSource Random; AttackDefinition Attack; }
```
## 6. The CE-side process and the bridge
`NetSec.CeDevice.exe`: same flags as `MMP.AsyncProxy.NetCF.csproj`, plus `OutputType=Exe`, `GenerateSupportedRuntime=false`, and this `App.config`:
```xml
<configuration><startup><supportedRuntime version="v4.0" sku=".NETFramework,Version=v4.8"/></startup></configuration>
```
Command line: `--pinpad P --gateway G --trace T --trace-id ID --link glass-ssh|external-forward|glass-tls11 --suite modern|legacy [--step] [--seed N] [--pool 25]`.
| Rule | Detail |
|---|---|
| Startup | `ThreadPool.SetMaxThreads(25, 25)`, then stdout `CE-READY pool=<w>/<c> ptr=<n> clr=<v>`. No line within 10 s gives `CE_DEVICE_SILENT`. That closes the false success from the spike |
| Keys | Holds SSH client keys only. No DUKPT type is reachable from `CeDeviceFlow` (D13) |
| Trace | NDJSON over TCP to the Host trace port. A real board has a socket and may have no stdout, so a later device uses the same ports |
| Result | Final stdout line `CE-RESULT {json}`, exit code 0 or 1 |
| Threads | Main thread parked on an event. Links run as iterators |
```csharp
public sealed class DeviceProfile {         // Immutable data
  public static readonly DeviceProfile Ce = new DeviceProfile("CeProfile", 25, 64 * 1024 * 1024, new WireProtocol[] { WireProtocol.Ssh, WireProtocol.Tls11 }, 2);
  public static readonly DeviceProfile Modern = ...;
}
public static class BudgetJudge { public static BudgetVerdict Judge(DeviceProfile p, BudgetSample s); }
```
**Budget.** The Host samples the CE process from outside every 250 ms, per `ce-budget.md`: threads, private bytes, working set. `CE-RESULT` reports `GC.GetTotalMemory`. `BudgetJudge` gates what transfers to a board: pool cap accepted, dedicated threads at most 2, managed heap under 64 MB. The rest is a number labelled `desktop CLR, 64-bit, does not transfer`.

**Binary proof, from outside.** A test reads the exe and DLLs with `System.Reflection.Metadata` and asserts `mscorlib` token `969db8053d3322ac`. `GET /api/ce` returns `{ running, pid, exePath, mscorlibToken, clr, ptr, label, profile, budget, link, ports }`. `--ce external` makes the Host skip the spawn and wait on the ports, which is the seam for a real board.

**Bridge processes (D13, A10).** `BridgeSupervisor` in the Host starts all five, or attaches with `--external`.
| Process | Build | Holds | Does |
|---|---|---|---|
| PIN-pad | `Node --role pinpad` | DUKPT initial key, registers | Makes the PIN block (ISO 9564 format 4), locks it, CMACs a `PinEnvelope {traceId, KSN, cipher, mac}`. Sends to CE over TCP |
| CE | `CeDevice`, CF binaries | SSH client key | Relays ciphertext through an `IDeviceLink` |
| Gateway | `Node --role gateway`, or Go `gogateway` | Hop keys | Ends SSH or TLS 1.1. Opens glass TLS 1.3 `X25519MLKEM768` to server. Forwards the envelope unopened |
| Server | `Node --role server`, or Go `tlspeer -relay` | TLS key | Ends TLS. Sends the envelope to bank-HSM over TCP |
| Bank-HSM | `Node --role bankhsm` | BDK | Derives, checks `DUKPT_MAC_MISMATCH`, `DUKPT_KSN_REPLAY`, recovers the PIN block |

`ExternalForwardLink` gives the `ssh.exe -L` run: CE opens a plain socket to a local port, and `ssh.exe` carries it, so our code does no SSH on that path. Gateway events carry `PIN block: gateway cannot open this`, and the tour lists what the gateway still sees (accuracy rule 1).
## 7. Native library (D8)
Files: `native/netsec_ct.h`, `native/netsec_ct.c`, compiled as C++ for the DLL and as C for the portability check. No exceptions, so nothing can unwind across the boundary.
```c
NSCT_API unsigned int NSCT_CALL nsct_abi_version(void);     /* NSCT_CALL: __stdcall on x86, ignored on x64 and ARM. Matches DllImport default */
NSCT_API int NSCT_CALL nsct_compare_leaky(const unsigned char *a, const unsigned char *b, unsigned int n);
NSCT_API int NSCT_CALL nsct_compare_ct(const unsigned char *a, const unsigned char *b, unsigned int n);
NSCT_API int NSCT_CALL nsct_sample(int which, const unsigned char *a, const unsigned char *b, unsigned int n,
                                   unsigned int *out_ticks, unsigned int samples, unsigned int *out_freq);
```
`nsct_sample` times each compare inside native code with `QueryPerformanceCounter`, so P/Invoke cost stays out of each sample. `nsct_compare_ct` accumulates through a `volatile`, and accuracy rule 5 says the result depends on the optimizer.
```csharp
internal static class NetSecCtNative {      // One file, both builds. Default calling convention, blittable arguments.
  [DllImport("netsec_ct.dll")] internal static extern uint nsct_abi_version();
  [DllImport("netsec_ct.dll")] internal static extern int nsct_compare_leaky(byte[] a, byte[] b, uint n);
  [DllImport("netsec_ct.dll")] internal static extern int nsct_compare_ct(byte[] a, byte[] b, uint n);
  [DllImport("netsec_ct.dll")] internal static extern int nsct_sample(int which, byte[] a, byte[] b, uint n, uint[] ticks, uint samples, out uint freq);
}
public static class TimingLab { public static TimingCase Sample(CompareKind kind, int bufferSize, int samples, int diffPosition); }
public static class TimingJudge { public static TimingVerdict Judge(TimingCase firstByteDiff, TimingCase lastByteDiff); }   // Pure Welch t
```
A12 run: 100,000 samples per case on a 4,096-byte buffer, first-byte difference against last-byte difference. Stated threshold: leaky passes at `|t| > 4.5` and `|t|` above 3 times the constant-time `|t|`. A missing library maps to `NATIVE_LIB_MISSING`. Build (x86 uses `vcvars32.bat` and `bin\x86`):
```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" && ^
cl /nologo /W4 /WX /O2 /TP /LD /DNSCT_BUILD native\netsec_ct.c /Fenative\bin\x64\netsec_ct.dll /Fonative\bin\x64\ && ^
cl /nologo /W4 /WX /O2 /TC /c native\netsec_ct.c /Fonative\bin\x64\c_check.obj
```
## 8. Build order
Each slice ships its lesson, tour, attacks, and e2e (D12), merges to a running `main`, reads `docs/learnings.md`, and closes on its gate. Only the acceptance author writes `acceptance/`. All slices also keep A9, A13, A14, A15, A15a green for the lessons built so far.
| Slice | Delivers, lessons | Closes | Owner | Parallel, no file overlap |
|---|---|---|---|---|
| Pre | `acceptance/`, `clauses.json`, signatures from section 2 | none | Echo | None. Comes first (D11) |
| S0 | Both builds of `Bytes`, `Errors`, `Trace`, `Machine`, `Io`. `EchoEngine` through `EnginePump`. Host with D14. Shell, tour engine, one live toy lesson. CF exe in the build | Partial A9, A13 | Richard | Nancy: `app/`. Heather: toy tour. Echo: `tests/` harness, `layer_check.py` |
| S1 | `Crypto` to ML-KEM and BigUInt, `Platform`. Lessons 1, 2, 3 (key agreement half) | A1, A2 | Richard A: hashes, AES, TDES, modes, GCM, HMAC, CMAC, HKDF, Keccak. Richard B: 25519, BigUInt, RSA, DH, ML-KEM | Echo: vector fetch, `referees/bcl`. Jared: crypto review. Heather, Nancy: lessons 1 to 3 |
| S2 | `Keys`, `Dukpt`. Lesson 6 | A3, A16 type half | Richard | Heather, Nancy: lesson 6 |
| S3 | `Pki`, `Tls13`. Lessons 3, 4, 5. `tap` | A4, A5, A6, A10a | Richard | Jared: `tlspeer`, `tap`. Heather, Nancy: lessons 4, 5 |
| S4 | `Tls11`, `Ssh` client, then server roles. Lessons 7, 8 | A7, A8, A1 remainder | Richard A: `Tls11`. Richard B: `Ssh` | Jared: `sshpeer`. Heather, Nancy: lessons 7, 8 |
| S5 | `Bridge`, `CeDevice`, `Node`. Lesson 9 | A10, A10a | Richard | Jared: `gogateway`, `tlspeer -relay`. Nancy: onion, CE panel. Heather: lesson 9 |
| S6 | `Auth`, mTLS rows. Lesson 10 | A11 | Richard | Jared: `tokenverify`. Heather, Nancy: lesson 10 |
| S7 | `native/`, `Native`. Lesson 11 | A12 | Richard. Jared reviews the C | Can start after S0. Touches only `LabCatalog` in shared files |
| S8 | Real-mode switch, polish, final red team | A16 | Nancy, Richard (`OsTransportFactory`) | Iolo: red team of the closing report. Echo: third-agent fresh-clone run |

Order under time pressure: S0, S1, S2, S3, S7, S4, S5, S6, S8. Cut order is the PRD's. A cut role makes the matching clause NOT RUN, by name.
## 9. Gate commands
Run from `E:\dev\MMP.NetworkSecurity`. `$cf = -p:NetCFRefDir=E:\dev\tools\netcf35-ref`. Referee pins, asserted by version string:
```
NETSEC_OPENSSL = C:\Program Files\Git\mingw64\bin\openssl.exe    # "OpenSSL 3.5.7"
NETSEC_SSH     = C:\Windows\System32\OpenSSH\ssh.exe             # "OpenSSH_for_Windows_9.5p2"
```
Base gate, in every slice. `pwsh tools/gate.ps1 -Slice Sn -Clauses A1,A2` runs this and the extras, and writes `docs/_runs/<date>-Sn.md`:
```
python tools/layer_check.py src/NetSec.Core
dotnet build src/NetSec.Core -c Release
dotnet build src/NetSec.Core.NetCF -c Release $cf
dotnet test tests/NetSec.Tests -c Release -f net10.0 $cf --logger trx --results-directory docs/_runs/trx/Sn-net10
dotnet test tests/NetSec.Tests -c Release -f net48   $cf --logger trx --results-directory docs/_runs/trx/Sn-cf
pwsh acceptance/run.ps1 -Clauses <list>
python tools/tour_lint.py app/src/tours --max-grade 8.9 --max-concept 0.30
python ~/.claude/hooks/tic-gate.py <each changed tour file>
cd app; npx playwright test e2e/lesson-<n>.spec.ts
python tools/lessons_status.py docs/_runs
```
| Slice | Clauses | Extras before the base gate |
|---|---|---|
| S0 | A9 | `dotnet build src/NetSec.Host -c Release`; `dotnet build src/NetSec.CeDevice -c Release $cf`; `cd app; npm ci; npm run build` |
| S1 | A1, A2 | `dotnet build acceptance/referees/bcl -c Release` |
| S2 | A3, A16 | none. If x9.org is unreachable, A3 records NOT RUN |
| S3 | A4, A5, A6, A10a | `cd acceptance/referees/go; go build -o bin/ ./...` |
| S4 | A1, A7, A8 | Go build. `ssh.exe` key: `icacls <key> /inheritance:r /grant:r "%USERNAME%:R"` |
| S5 | A10, A10a | Go build. `dotnet build src/NetSec.Node -c Release` |
| S6 | A11 | Go build |
| S7 | A12 | Section 7 build |
| S8 | All | `dotnet build src/NetSec.Host -c Release`. Then a third agent runs `acceptance/run.ps1` from a fresh clone and diffs `acceptance/` against the pinned commit |

Referee commands the suites spawn:
```
openssl s_server -accept 0 -tls1_3 -groups X25519MLKEM768 -cert srv.pem -key srv.key -keylogfile k.log -naccept 1        # A5, A6
openssl s_server -accept 0 -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -cert rsa.pem -key rsa.key -naccept 1                 # A7 RSA suite
openssl s_server -accept 0 -tls1_1 -cipher ECDHE-RSA-AES128-SHA:@SECLEVEL=0 -cert rsa.pem -key rsa.key -naccept 1       # A7 ECDHE suite
openssl s_server -accept 0 -tls1_3 -cert srv.pem -key srv.key -naccept 1                                                # A7 alert 70
openssl s_server -accept 0 -cipher ALL:@SECLEVEL=0 -cert rsa.pem -key rsa.key -naccept 1                                # A7 sentinel: 1.3-capable server, client hello rewritten to 1.1
tlspeer -mode server -groups x25519mlkem768 -cert srv.pem -key srv.key                                                  # A5, prints ConnectionState group
sshpeer -host-key host.key -authorized user.pub -kex curve25519-sha256 -allow-tunnel 127.0.0.1:Q                        # A8 modern
sshpeer -host-key rsa-host.key -authorized user.pub -kex diffie-hellman-group14-sha1 -cipher aes128-cbc -mac hmac-sha1  # A8 legacy
ssh.exe -F NUL -o BatchMode=yes -o UserKnownHostsFile=<file> -i <key> -L P:127.0.0.1:Q -N training@127.0.0.1 -p <port>  # A10 forward run
tap -listen 127.0.0.1:A -to 127.0.0.1:B -log hop.hex [-flip-at N]                                                       # A10, A10a
tokenverify -pub issuer.pub -token <jws>                                                                                # A11
```
A10 runs from outside the app: start nodes behind two `tap` relays, start the CE exe, require `CE-READY`, and check `hop1.hex` starts `SSH-2.0-`, `hop2.hex` holds group 0x11EC, the clear PIN block is in neither hop, tap bytes equal trace bytes (A10a), the bank value equals the input, and both hops share one `traceId`. Then repeat with `-flip-at` per hop and an envelope flip at the gateway, expecting `SSH_PACKET_MAC`, `TLS13_AEAD_TAG`, `DUKPT_MAC_MISMATCH` beside a passing control.

Electron spawns the Host detached, handles `EPIPE` as in the MMP.GasPumpSimulator `main.cjs`, and ends the tree with `taskkill /T`. `e2e/start.spec.ts` launches real Electron with `_electron.launch`. Lesson walks run against `vite preview` on 4180 and a live Host on 5180, one worker.
## 10. Open questions, with the default taken
| # | Question | Default |
|---|---|---|
| 1 | A10 says "CE and gateway memory traces hold no key". Glass SSH shows its session keys by design | "No key" means no DUKPT key and no BDK. Hop keys stay visible. The acceptance author must write the clause this way |
| 2 | CE exe as x86 for 32-bit pointers | x64 now. `PlatformTarget` is a property, and `native/` can build x86 |
| 3 | HelloRetryRequest | Named failure. One added row later |
| 4 | Hybrid share order (RFC 10024) | ML-KEM first, then X25519. OpenSSL and Go decide (D10) |
| 5 | Vector source for ISO 9564 format 4 | None known to be free. Anchor is the A10 round trip. The report says so |
