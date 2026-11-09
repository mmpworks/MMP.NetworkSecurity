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
| Same exe, `App.config` with `v4.0`, `GenerateSupportedRuntime=false` | `ok hello pool=True/25/25 ptr=8 clr=4.0.30319.42000` | The S0 spike passes for `BeginReceive` through AsyncProxy. Connect and Accept in the spike were blocking calls, and `BeginSend`, `BeginConnect`, `BeginAccept` are only compile-checked. S0 commits a test that runs all four. Pointers are 64-bit |
| Same source, net10.0, `LangVersion 3`, AsyncProxy `netstandard2.0` | `ok hello pool=True/25/25 clr=10.0.14` | C# 3 iterators and sockets work on both builds |
| PATH | `openssl` also resolves to FireDaemon. Git Bash `ssh` is `/usr/bin/ssh`. `cl` is off PATH | Referees use pinned paths (section 9) |

Consultation. Gems used: `server-replaces-never-merges`, `fail-soft-must-count`, `paths-plain-at-the-boundary`, `decide-at-authoritative-boundary`, `plain-sentence-error-surface`. No gem covers a sans-IO table engine, so it is a candidate after S4. Catalog: closest shape is a multi-step process with independent failure per step. Taken: name each step's failure. Rejected: queues and caches. "Sans-IO" as a pattern name (`rustls`, `h11`) is recollection, unverified this session.
## 1. Module layout
| Path | TFM, language | Owns |
|---|---|---|
| `src/NetSec.Core` | net10.0, C# 3 | All shared source. Assembly `NetSec.Core` |
| `src/NetSec.Core.NetCF` | net35 on CF refs, C# 3, `NETCF` | No source: `Compile Include="..\NetSec.Core\**\*.cs"`. Assembly `NetSec.Core` |
| `src/AsyncProxy.Local`, `src/AsyncProxy.Local.NetCF` | netstandard2.0, and net35 on CF refs, C# 3 | No source: they compile the sibling's `src/MMP.AsyncProxy`. Assembly `MMP.AsyncProxy`, in this worktree's own output. The sibling is only read |
| `src/NetSec.CeDevice` | net35 on CF refs, C# 3, Exe | The CE process (section 6) |
| `src/NetSec.Node` | net10.0, C# 14, Exe | Thin main: `--role pinpad, gateway, server, bankhsm`. Logic lives in `Core/Bridge` (D13) |
| `src/NetSec.Host` | net10.0, C# 14 | Minimal API, WebSocket, sessions, process control, `OsTransportFactory` |
| `native/` | C-compatible C++ | `netsec_ct.dll` (section 7) |
| `app/` | Electron, Vue 3, Vuetify | UI per `ux-design.md`. Tours in `app/src/tours/` |
| `tests/NetSec.Tests` | net10.0, net48, C# latest | Builder unit suite. net48 uses `HintPath` to CF binaries, as in MMP.AsyncProxy |
| `acceptance/` | net10.0, net48, pwsh | D11. Separate authors. **Builders never write here.** `run.ps1`, `clauses.json`, pinned skip list, `referees/bcl` (oracle, so net48 reaches `MLKem` with no skip), `referees/go` (`tlspeer`, `sshpeer`, `gogateway`, `tap`, `tokenverify`) |
| `tools/` | pwsh, python | `gate.ps1`, `layer_check.py`, `tour_lint.py`, `lessons_status.py`, `run_status.py` (section 9.1) |

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
| `Dukpt`, `Auth` | `DukptPinPad`, `DukptBank`, `PinBlock`, `Token`, `DpopProof`, `Challenge`, `AccessRules` | `Crypto`, `Keys` |
| `Io` | `Probe`, `IByteLink`, `SocketLink`, `MemoryLink`, `EnginePump`, `IStepGate`, `ITransportFactory`, `GlassTransportFactory`, `TransportPolicy`. The only AsyncProxy and socket use | all above |
| `Bridge` | `PinEnvelope`, `IDeviceLink`, `PinPadCore`, `CeDeviceFlow`, `GatewayCore`, `ServerCore`, `BankHsmCore`, `DeviceProfile`, `BudgetJudge` | all above |
| `Native` | `NativeCompare`, `ManagedCompare`, `TimingLab`, `TimingJudge` | `Errors`, `Trace` |
| `Labs` | `ILab`, `LabCatalog`, `AttackCatalog`. One file per lesson | all above |
## 2. Key types and signatures
All C# 3. Section 11 lists what `acceptance/` calls. A parse failure throws `ParseFailure` inside an engine and leaves `Feed` as an `EngineOutput` error.
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

**UX section 0 is confirmed, including `visibleToWire`.** An engine sets `visibleToWire` per field: true for clear headers and clear handshake fields, false for anything inside protected bytes. `TraceJson` writes the UX names: `secrets[].hex`, `check {id, name, result, code, detail}` with `result` as `pass` or `fail`, and `waiting {actor}`. The Host stamps `seq` and `seed`. Actor names stay as in the UX: the PIN-pad is `reader`, and the bank-HSM is `bank`. Amendments: added `eventId`, `streamId`, `streamSeq`, `message`, `step`, `schema`; `check.id` is new; `fields[].gloss` is a key rather than English. In real mode `plain` and `secrets` are always empty. The pump also emits type `wire.sent` with the bytes it wrote to the socket after tampering. It skips the gate, and A10a compares it to the tap.
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
A name in a list after `;` has the modifiers and return type of the first name. `MlKemPair {Ek, Dk}`, `MlKemSealed {Ciphertext, SharedSecret}`, `BigUInt.FromBytes(byte[])` (big-endian).
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
| `sh` | WaitServerHello | ServerHello | `TLS13_DOWNGRADE_SENTINEL`, `TLS13_VERSION_REFUSED`, `TLS13_HRR_UNSUPPORTED`. Secrets, InstallKeys | WaitEE |
| `ee` | WaitEE | EncryptedExtensions | group unchanged | WaitCertOrReq |
| `creq` | WaitCertOrReq | CertificateRequest | none. Mark client auth | WaitCert |
| `cert` | WaitCertOrReq, WaitCert | Certificate | `CHAIN_NO_ANCHOR`, `CERT_VALIDITY`, `CERT_NAME`, `CERT_SIGNATURE` | WaitCertVerify |
| `cv` | WaitCertVerify | CertificateVerify | `TLS13_CERTVERIFY_BAD` | WaitFinished |
| `fin` | WaitFinished | Finished | `TLS13_FINISHED_MISMATCH`. App secrets, Send Finished, InstallKeys | Open |

Record failure: `TLS13_AEAD_TAG`. Dummy `change_cipher_spec` and `NewSessionTicket` give a Note. `KeyUpdate` gives `TLS13_KEYUPDATE_UNSUPPORTED`. `Tls13KeySchedule` is pure, so A4 runs on it alone. `KeyLog.Line(label, clientRandom, secret)` writes NSS format for A6.

**TLS 1.1 client.** Named suites: `TLS_RSA_WITH_AES_128_CBC_SHA` (record now, decrypt after key theft), `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` on X25519. The lab forces the weak suite per accuracy rule 3. Explicit IV, MD5 and SHA-1 PRF, MAC then encrypt. Rows `tls11.c.*`:
| Step | From | Message | Check, failure code | To |
|---|---|---|---|---|
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
| `newkeys` | WaitNewKeys | NEWKEYS, then SERVICE_ACCEPT | none. InstallKeys | WaitAuth |
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
3. **DH exponent.** `x` is 512 random bits, which cuts a device's work about 4 times. The peer value must be in `[2, p-2]`.
4. **PRD addition.** Ed25519 needs SHA-512, and ML-KEM needs SHA-3 and SHAKE. A1 omits them. Builder tests carry them. The acceptance author should add clauses.

Complexity hotspots: `BigUInt.DivRem`, `ByteEncode`, the SSH channel window, record reassembly. Each gets a small type and a comment on how the logic works.
## 5. Host contract
Bind `127.0.0.1:5180` only (`NETSEC_PORT` overrides). D14: allow-listed `Origin` (`file://`, `http://localhost:4180`, `http://localhost:5173`) and a session token on every request. Electron generates `NETSEC_TOKEN`, passes it to the Host by env and to the renderer by preload. HTTP uses `Authorization: Bearer`. WebSocket uses `/ws?token=`. Failures: `HOST_ORIGIN_REFUSED`, `HOST_TOKEN_REFUSED`.
D14 amendment (test runs only). The Host also reads `NETSEC_ORIGINS`, a comma list that adds origins to the built-in list and never replaces it. An entry is the full string `http://localhost:PORT` or `http://127.0.0.1:PORT`, with PORT 1024-65535, no leading zero, no path, no trailing slash, and no wildcard. `localhost` and `127.0.0.1` are separate entries, because a browser sends whichever the page used. The Host drops any other entry and keeps the rest. At start, when `NETSEC_ORIGINS` has entries, the Host prints one `HOST-ORIGINS accepted=[...] dropped=[...]` line that names each accepted entry and each dropped entry with its reason. The token check still runs on every request from an added origin. Electron blanks `NETSEC_ORIGINS` in the environment of the Host it spawns (an empty value, which the Host reads as unset), so a value in a learner's shell never widens the shipped Host (`e2e/origins-electron.spec.ts` pins this).
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
| `session.start {requestId, lesson, seed, mode, transport: glass or real}` | `session.started {requestId, sessionId, seed, transportKind, trainingOnly, sessionFile}` |
| `session.step`, `session.run`, `session.pause` | `trace {sessionId, seq, event}` |
| `session.attack {requestId, sessionId, attackId}` or `{atSeq, kind, offset, xor}` | `session.forked {sessionId, parentId, attackId}` |
| `session.load {file}`, `session.save {sessionId}` | `session.finished {sessionId, outcome, code, check}` |
| | `error {requestId, code, message, retryable}` |

| UX concept | Host source |
|---|---|
| Lesson rail, home page | `LabCatalog` row plus `built`. Unbuilt lessons show and say so (D12) |
| Tour step, `bind.kind: event` | First `trace` whose `event.type` and `match` fit. `match` tests `actor`, `message`, `step` |
| Attack button | `AttackCatalog` row. Starts a forked session with the same seed |
| TRAINING ONLY chip | `session.started.trainingOnly`, true when `factory.Kind == "glass"` |

`SessionManager` keeps the last 20 sessions in memory, capped at 20,000 events each, and appends NDJSON to `%LOCALAPPDATA%\MMP.NetworkSecurity\sessions\`. Per-client outbound is a bounded channel with drop-oldest and a visible `droppedEvents` counter.
`ILab { string LabId; IFuture<LabResult> Run(LabContext c); }`. `LabContext` carries seed, transports, gate, sink, clock, random, attack.
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
`DeviceProfile.Ce` is immutable data: name `CeProfile`, pool 25, 64 MB, SSH and TLS 1.1, 2 dedicated threads. `BudgetJudge.Judge(profile, sample)` is pure.
**Budget.** The Host samples the CE process from outside every 250 ms, per `ce-budget.md`: threads, private bytes, working set. `CE-RESULT` reports `GC.GetTotalMemory`. `BudgetJudge` gates what transfers to a board: pool cap accepted, dedicated threads at most 2, managed heap under 64 MB. The rest is a number labelled `desktop CLR, 64-bit, does not transfer`.

**Binary proof, from outside.** A test reads the exe and DLLs with `System.Reflection.Metadata` and asserts `mscorlib` token `969db8053d3322ac`. `GET /api/ce` returns `{ running, pid, exePath, mscorlibToken, clr, ptr, label, profile, budget, link, ports }`. `--ce external` makes the Host skip the spawn and wait on the ports, which is the seam for a real board.

**Bridge processes (D13, A10).** Five processes. Decision, 2026-11-05: `BridgeSupervisor` is not built. This design was the only place that named it. The PRD, `ux-design.md` and `acceptance/CONTRACT.md` ask for no such thing. A10 starts the processes from outside. Lesson 9 runs the same code in one process, so a learner can step it. `/api/ce` runs the CE alone, through `CeProcess`. A later UI that starts all five from the app would need it.
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
`NetSecCtNative` holds one `[DllImport("netsec_ct.dll")]` per export: one file, both builds, default calling convention, blittable arguments. `TimingLab.Sample(kind, bufferSize, samples, diffPosition)` and the pure `TimingJudge.Judge(first, last)` (Welch t) sit above it.
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
| Pre | `acceptance/`, `clauses.json`, against section 11 | none | Echo | Jared: `acceptance/referees/` (D11) |
| S0 | Both builds of `Bytes`, `Errors`, `Trace`, `Machine`, `Io`. `EchoEngine` through `EnginePump`. Host with D14. Shell, tour engine, one live toy lesson. CF exe socket-loop test (all four Begin pairs) | Partial A9, A13 | Richard | Nancy: `app/`. Heather: toy tour. Echo: `tests/` harness, `layer_check.py` |
| S1 | `Crypto` to ML-KEM and BigUInt, `Platform`. Lessons 1, 2, 3 (key agreement half) | A1, A2 | Richard A: hashes, AES, TDES, modes, GCM, HMAC, CMAC, HKDF, Keccak. Richard B: 25519, BigUInt, RSA, DH, ML-KEM | Jared: crypto review. Heather, Nancy: lessons 1 to 3 |
| S2 | `Keys`, `Dukpt`. Lesson 6 | A3, A16 type half | Richard | Heather, Nancy: lesson 6 |
| S3 | `Pki`, `Tls13`. Lessons 3, 4, 5. `tap` | A4, A5, A6, A10a | Richard | Heather, Nancy: lessons 4, 5 |
| S4 | `Tls11`, `Ssh` client, then server roles. Lessons 7, 8 | A7, A8, A1 remainder | Richard A: `Tls11`. Richard B: `Ssh` | Heather, Nancy: lessons 7, 8 |
| S5 | `Bridge`, `CeDevice`, `Node`. Lesson 9 | A10, A10a | Richard | Nancy: onion, CE panel. Heather: lesson 9 |
| S6 | `Auth`, mTLS rows. Lesson 10 | A11 | Richard | Heather, Nancy: lesson 10 |
| S7 | `native/`, `Native`. Lesson 11 | A12 | Richard. Jared reviews the C | Can start after S0. Touches only `LabCatalog` in shared files |
| S8 | Real-mode switch, polish, final red team | A16 | Nancy, Richard (`OsTransportFactory`) | Iolo: red team of the closing report. Echo: third-agent fresh-clone run |

Order under time pressure: S0, S1, S2, S3, S7, S4, S5, S6, S8. Cut order is the PRD's. A cut role makes the matching clause NOT RUN, by name.
## 9. Gate commands
Run from `E:\dev\MMP.NetworkSecurity`. `$cf = -p:NetCFRefDir=E:\dev\tools\netcf35-ref`. Referee pins, asserted by version string: `NETSEC_OPENSSL` = `C:/Program Files/Git/mingw64/bin/openssl.exe` (`OpenSSL 3.5.7`), `NETSEC_SSH` = `C:/Windows/System32/OpenSSH/ssh.exe` (`OpenSSH_for_Windows_9.5p2`).
Base gate, in every slice. `pwsh tools/gate.ps1 -Slice Sn -Clauses A1,A2` runs this and the extras, adds A9 to the clause list on every run, and writes `docs/_runs/<date>-Sn.md`:
```
python tools/layer_check.py src/NetSec.Core
dotnet build src/NetSec.Core -c Release
dotnet build src/NetSec.Core.NetCF -c Release $cf
dotnet test tests/NetSec.Tests -c Release -f net10.0 $cf --logger trx --results-directory docs/_runs/trx/Sn-net10
dotnet test tests/NetSec.Tests -c Release -f net48   $cf --logger trx --results-directory docs/_runs/trx/Sn-cf
pwsh acceptance/run.ps1 -Clauses <list>
python tools/tour_lint.py app/src/tours --max-grade 8.9 --max-concept 0.30
python ~/.claude/hooks/tic-gate.py <each changed tour file>
cd app; node node_modules/@playwright/test/cli.js test e2e/lesson-<n>.spec.ts
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
openssl s_server -accept 0 -tls1_1 -cipher <AES128-SHA or ECDHE-RSA-AES128-SHA>:@SECLEVEL=0 -cert rsa.pem -key rsa.key   # A7 named suites
openssl s_server -accept 0 -tls1_3 -cert srv.pem -key srv.key -naccept 1                                                # A7 alert 70
openssl s_server -accept 0 -cipher ALL:@SECLEVEL=0 -cert rsa.pem -key rsa.key -naccept 1                                # A7 sentinel: 1.3-capable server, client hello rewritten to 1.1
tlspeer -mode server -groups x25519mlkem768 -cert srv.pem -key srv.key                                                  # A5, prints ConnectionState group
sshpeer -host-key host.key -authorized user.pub -kex curve25519-sha256 -allow-tunnel 127.0.0.1:Q                        # A8 modern
sshpeer -host-key rsa-host.key -authorized user.pub -kex diffie-hellman-group14-sha1 -cipher aes128-cbc -mac hmac-sha1  # A8 legacy
ssh.exe -F NUL -o BatchMode=yes -o UserKnownHostsFile=<file> -i <key> -L P:127.0.0.1:Q -N training@127.0.0.1 -p <port>  # A10 forward run
tap -listen 127.0.0.1:A -to 127.0.0.1:B -log hop.hex [-flip-at N]                                                       # A10, A10a
tokenverify -pub issuer.pub -token <jws>                                                                                # A11
```
Under-load runs, outside the gate. The shared suite runs the #309 side tests 6 times with no burner. `pwsh tools/load_runs.ps1` runs them 20 times each, the second half beside a CPU burner on every core (`NETSEC_LOAD_RUNS=1`). It takes the heavy lock and writes `docs/_runs/<date>-load-runs.md`. Run it after a change to the pump, the deadline rule or the side tests, and before a claim of "20 of 20 under load".

A10 runs from outside the app, with the steps in section 11. Expected tamper codes: `SSH_PACKET_MAC`, `TLS13_AEAD_TAG`, `DUKPT_MAC_MISMATCH`, each beside a passing control.

Electron spawns the Host detached, handles `EPIPE` as in the MMP.GasPumpSimulator `main.cjs`, and ends the tree with `taskkill /T`. `e2e/start.spec.ts` launches real Electron with `_electron.launch`. Lesson walks run against `vite preview` on 4180 and a live Host on 5180, one worker (or the `NETSEC_PORT_BASE` block, which gives each worktree its own ports).
### 9.1 Long runs: read the log at the expected end

Read the run's log at its expected end. Do not wait for the finish notice. Finish notices for background runs arrived late or never four times in one day (a gate, a Host test run, an app suite), and each time an agent lost about an hour.

1. When you start a run in the background, write down the log path and the expected end. Typical times on this machine: full `-SkipApp` gate 17 to 25 minutes, full Playwright suite 22 to 25 minutes, full Host test run 40 to 90 seconds, one guard test file about 1 minute.
2. At the expected end, run `python -I tools/run_status.py <log>`. It prints one line and sets an exit code: `PASSED` (0), `FAILED` (1), `RUNNING` (2, names the current step or the Playwright count), `STUCK` (3, names the step and the quiet time), `NO_LOG` (4).
3. `RUNNING` past the expected end: check again at half the expected time. `STUCK`: stop only your own processes, keep the log, and report the step it stopped at.
4. A machine that other agents also load makes runs slower. A slow run that still writes output is `RUNNING`, not stuck. Raise the limit with `--stuck-after <minutes>` (default 10).
5. Report the result from the log line, with its counts.

## 10. Open questions, with the default taken
| # | Question | Default |
|---|---|---|
| 1 | A10 says "CE and gateway memory traces hold no key". Glass SSH shows its session keys by design | "No key" means no DUKPT key and no BDK. Hop keys stay visible. The acceptance author must write the clause this way |
| 2 | Hybrid share order (RFC 10024) | ML-KEM first, then X25519. OpenSSL and Go decide (D10) |
| 3 | Vector source for ISO 9564 format 4 | None known to be free. Anchor is the A10 round trip. The report says so |
## 11. Acceptance seams (D11)
`acceptance/` calls only what this section and the sections it names list. The names hold from S0. A builder who needs a change asks the acceptance author and never edits `acceptance/`. `pwsh tools/bootstrap.ps1` builds everything from a fresh clone, with `-p:AsyncProxyRoot` as an override. Outputs: `src/NetSec.Core/bin/Release/net10.0/`, `src/NetSec.Core.NetCF/bin/Release/net35/`, `src/NetSec.CeDevice/bin/Release/net35/NetSec.CeDevice.exe`, `src/NetSec.Node/bin/Release/net10.0/NetSec.Node.exe`, `src/NetSec.Host/bin/Release/net10.0/NetSec.Host.exe`, `native/bin/x64/netsec_ct.dll`. The net48 suite references both CF DLLs by `HintPath`. Option classes use public fields, for object initializers.
```csharp
public static class Probe {                  // Namespace NetSec.Io. One socket, one engine, both builds.
  public static IFuture<ProbeResult> Connect(ProbeRequest r);
  public static ProbeListener Listen(ProbeRequest r);   // ProbeListener { int Port; IFuture<ProbeResult> Result; }. Binds now, port 0 allowed
}
public sealed class ProbeRequest { WireProtocol Protocol; string Host; int Port; KexGroup Group; string Suite; SshSuite SshSuite; string PeerName; string KnownHostsFile;
  bool OfferOnlyTls11; string ClientKeyId; string ExecCommand; string TunnelTo; byte[] Send; TamperPlan Tamper; int Seed; }   // Seed 0 means OsRandom
public sealed class ProbeResult { bool Completed; string Code, CheckName, Version, Suite, Group; int AlertReceived; string[] KeyLog; byte[] Received; TraceEvent[] Events; }
public static class TrainingPki { public static void Export(string directory); }   // PEM and OpenSSH files named in section 9
public static class Tls13KeySchedule { public static Tls13Secrets Derive(Func<IHash> h, byte[] shared, byte[] helloHash, byte[] serverFinishedHash); }   // Fields named per RFC 8446
public sealed class DukptPinPad { DukptPinPad(byte[] initialKey, byte[] initialKeyId); DukptUse Next(DukptKeyUsage u, DukptKeyType t); byte[][] HeldKeys(); }   // DukptUse { Ksn, Key }
public static class DukptBank { byte[] DeriveInitialKey(byte[] bdk, byte[] initialKeyId); DeriveWorkingKey(byte[] bdk, byte[] ksn, DukptKeyUsage u, DukptKeyType t); }
public static class Token { string Issue(ITrainingKey k, string claimsJson); AuthDecision Verify(byte[] pub, string jws, DateTime now); }   // DpopProof, Challenge, AccessRules return AuthDecision too
public sealed class AuthDecision { bool Allowed; string Code, CheckName; }
public sealed class TimingVerdict { double LeakyT, ConstantT, Threshold; bool Separated; }
```
| Clause | Seam |
|---|---|
| A1, A2 | Section 2.3. TDES vectors use `TdesKey` blocks. `MlKem768` is deterministic from `d`, `z`, `m` |
| A3 | `DukptPinPad`, `DukptBank`. `HeldKeys` returns copies, for the absence check. The tour line is in `app/src/tours/lesson-06.json` |
| A4 | `Tls13KeySchedule.Derive` |
| A5, A6 | `TrainingPki.Export`, then `Probe.Connect` or `Probe.Listen` against the section 9 referees. `ProbeResult.Group`, `KeyLog` |
| A7 | `Probe`, `Suite` by IANA name. `AlertReceived == 70`. `OfferOnlyTls11` with a TLS 1.3 client gives `TLS13_DOWNGRADE_SENTINEL` |
| A8 | `Probe`, `SshSuite`, `ExecCommand`, `TunnelTo`, `KnownHostsFile`. `Received` holds the exec output. `Code` gives `SSH_HOST_KEY_CHANGED` |
| A9 | Build outputs above. `System.Reflection.Metadata` on each CF binary. `git ls-files`. `BuildId.Target` is `net10` or `netcf35` |
| A10, A10a | Processes below. Compare each direction's `wire.sent` bytes, joined, to the tap log for that direction. Run twice with no seed, and compare randoms |
| A11 | `Token`, `DpopProof`, `Challenge`, `AccessRules`. mTLS through `Probe` with `ClientKeyId`. `tokenverify` reads `Token.Issue` output |
| A12 | `native/build.cmd`. `NativeCompare.AbiVersion()`, `TimingLab`, `TimingJudge` |
| A13 | Host CLI below, `data-testid` names in UX section 6, `GET /api/lessons` `built` |
| A14, A15, A15a | `app/src/tours/lesson-NN.json`, UX section 3.1, plus `claims [{text, source}]`. A14 runs each lesson over the WebSocket with `session.run` and matches each `bind` |
| A16 | Reflection: no public member of `GlassTransportFactory` accepts `IKeyHandle`, and its only constructor takes `ITrainingKeySource`. `session.start {transport: real}`, then scan events and `sessionFile` for key bytes. `training-only-label` testid |

Processes. Each prints `READY port=<p>` first and a final `RESULT {json}` line, and takes `--trace-file <path>`, so a suite needs no Host. Frames on every plain link: 4-byte big-endian length, then bytes.
1. `NetSec.Node.exe --role bankhsm --listen 0`; `--role server --listen 0 --bank P`; `--role gateway --listen 0 --server P --link ssh|tls11`; `--role pinpad --listen 0 --pin 1234 --pan <digits>`. Bank `RESULT` holds `pinBlockHex`, `code`, `check`.
2. `NetSec.CeDevice.exe` per section 6, with `--trace-file`. It prints `CE-READY` and `CE-RESULT`.
3. `NetSec.Host.exe --port P --token T [--ce external]`. Origin and token rules are in section 5.
