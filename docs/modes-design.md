# MMP.NetworkSecurity: security modes design

Author: Richard. Date: 2026-11-05. Status: design for review, no product code. Branch `docs/security-modes`, off `dfe9510`. Inputs: `docs/prd.md`, `docs/program-design.md`, `docs/learnings.md`, `acceptance/CONTRACT.md`, the code, and one spike.

## Conclusion

1. **The course holds 34 security items. They collapse to 15 switches that can go Real and 11 items that stay as they are.** 23 items sit behind the 15 switches. Section 1 lists all 34.
2. **Each of the 15 security types is Mock or Real on its own.** A lab reads a snapshot of the types at `session.start`. A Real type that is not ready refuses the lab by name. It never falls back to Mock.
3. **Engines get operations, never private bytes.** `IKeyHandle` widens and enters the glass engines. The engine then cannot show what it never held. This reverses the last sentence of D5, so it needs Steve's yes (decision O1).
4. **SQLite works as the vault.** The spike created, stored, and read keys through `Microsoft.Data.Sqlite.Core` on .NET 10, signed inside the box, and OpenSSL verified the signature. Use the `.Core` package with `SQLitePCLRaw.bundle_e_sqlite3` 3.0.3. The plain `Microsoft.Data.Sqlite` 10.0.9 package pulls a bundle with a high-severity advisory, and `TreatWarningsAsErrors` turns that warning into a build failure.
5. **"Real mode" and "real keys" are two separate axes.** Transport asks whose code speaks the protocol. Keys ask whose key signs.
6. **The spike found three limits that shape the wizards.**
   - The glass chain check accepts Ed25519 signatures only (`Certificate.cs:216`), so a certificate from a public CA fails today.
   - Windows `SslStream` fails against an Ed25519 server certificate. **So `A16.real-mode.os-transport-writes-no-secret-bytes` cannot pass as written**, because `HostClauses.cs:175` makes its peer key Ed25519. The clause needs an RSA peer. Echo owns that edit.
   - The .NET BCL has no Ed25519 type, `X509Certificate2` rejects an Ed25519 PEM, and an Ed25519 PKCS#12 file fails to load. So an Ed25519 key can use only PEM, OpenSSH, or the vault, through our own readers. The OS store route is RSA only (inferred from those results; the store itself was not touched).
7. **A separate bug waits behind real mode.** The clause wants `transportKind == "os"` (`HostClauses.cs:199`). The app tests for `'real'` (`app/src/store.ts:100`, `:206`). A working OS transport would still show the TRAINING ONLY chip.

Two things for Steve: decide O1, and confirm O3 (the keys live in a gitignored `.security/` folder inside the project).

## 1. Inventory

Enumerated from `git grep` on `dfe9510`. 11 `KeyIds` constants (`Keys.cs:35-45`, one more than design section 2.2 lists: `ClientTlsEd25519`) plus 23 items outside `KeyIds`. Total 34.

`new TrainingKeySource()` appears at 24 sites: Labs 12, `Probe` 5, `SshProbe` 3, `TrainingPki` 1, `Node` 2, `CeDevice` 1. `LabContext` carries no keys, and `SessionManager.cs:159` sets no `Transports`, so each lab makes its own key source today.

Format notes: "seed" is 32 bytes, "PKCS#8" is DER, as in `CONTRACT.md` rule 5.

### 1.1 Long-term keys (`KeyIds`)

| # | Item | Lessons | Made today | Holder | Format | A real one is | Switch |
|---|---|---|---|---|---|---|---|
| 1 | `ca-root` | 4, 5, 7, 9, 10 | SHAKE256 of label and id, `TrainingKeySource.cs:28` | `TrainingCa._seed`, `TrainingCa.cs:41` | Ed25519 seed | An offline root or issuing CA key in an HSM | `pki.root-ca` |
| 2 | `server-tls-ed25519` | 4, 5, 7, 9, 10 | Same | `Tls13Options.SigningSeed`, `Tls13Session.cs:24` | Ed25519 seed | A web server key, on disk or in an HSM | `tls13.server` |
| 3 | `client-tls-ed25519` | 10 | Same | `SigningSeed`, `Lesson10Auth.cs:176` | Ed25519 seed | A device key for mutual TLS | `tls13.client` |
| 4 | `server-tls11-rsa` | 7 | Literal hex, `TrainingRsaKeys.cs` | `Tls11Options.ServerKey`, `Tls11Session.cs:26` | RSA 2048 PKCS#8 | A legacy server RSA key | `tls11.server` |
| 5 | `ssh-host-ed25519` | 8, 9 | SHAKE256 | `SshServerOptions.HostKey`, `SshSession.cs:42` | Ed25519 seed | `ssh_host_ed25519_key` | `ssh.host-ed25519` |
| 6 | `ssh-host-rsa` | 8 (legacy round), 9 with `--suite legacy` | Literal hex | Same | RSA 2048 PKCS#8 | `ssh_host_rsa_key` | `ssh.host-rsa` |
| 7 | `ssh-client` | 8, 9 | SHAKE256 | `SshClientOptions.UserKey`, `SshSession.cs:29` | Ed25519 seed | `id_ed25519` on the device | `ssh.client` |
| 8 | `dukpt-bdk-128` | 6, 9 | SHAKE256 | Bank: `Lesson06Dukpt.cs:103`, `Node/Program.cs:114` | 16 bytes | A BDK held in an HSM, loaded from components | `dukpt.bdk` |
| 9 | `dukpt-bdk-256` | None. Only `KeysTests.cs:24,67` reads it | SHAKE256 | Nobody in a lesson | 32 bytes | An AES-256 BDK | `dukpt.bdk`, as a size choice |
| 10 | `token-issuer` | 10 | SHAKE256 | `Session.Issuer`, `Lesson10Auth.cs:83` | Ed25519 seed | A JWT signing key in a KMS | `token.issuer` |
| 11 | `attacker-ed25519` | 4, 8, 10 attack rows | SHAKE256 | The attack rows | Ed25519 seed | **Nothing. An attacker's key has no real owner** | None |

### 1.2 Certificates, trust, and pins

| # | Item | Lessons | Made today | Holder | Format | A real one is | Switch |
|---|---|---|---|---|---|---|---|
| 12 | Root certificate | 4, 5, 7, 9, 10 | `TrainingCa.BuildRoot`, `TrainingCa.cs:82` | CA, clients | X.509 DER, Ed25519 signature | A CA certificate | `pki.root-ca` |
| 13 | Server leaf, `localhost` | 4, 5, 7, 9, 10 | `TrainingPki.ServerCertificate`, `TrainingPki.cs:47` | Server | X.509 DER | A server certificate with a real name | `tls13.server` |
| 14 | Client leaf, `pump-reader-4` | 10 | `TrainingPki.ClientCertificate`, `TrainingPki.cs:53` | Client | X.509 DER | A device certificate | `tls13.client` |
| 15 | TLS 1.1 RSA leaf | 7 | `Tls11Training.cs:20` | Server | X.509 DER, RSA key, Ed25519 signature | An RSA certificate signed by RSA | `tls11.server` |
| 16 | Attack certificates (expired, wrong name, unknown CA, wrong client name, server usage) | 4, 10 | `Tls13Lab.cs:115-119`, `Lesson10Auth.cs:159-171` | Attack rows | X.509 DER | None. Each needs a CA that will sign a bad certificate | None, follows #1 |
| 17 | Trust anchors | 4, 5, 7, 9, 10 | `Tls13Lab.cs:156`, `GlassTlsChannel.cs:176`, `Tls11Training.cs:12` | Clients, and the server for mutual TLS | DER list | A CA bundle | `tls.trust` |
| 18 | `known_hosts` pin | 8, 9 | `Lesson08Ssh.cs:105`, `BridgeHops.cs:458` | SSH client | One `known_hosts` line | A learned or provisioned pin | `ssh.known-hosts` |
| 19 | `authorized_keys` list | 8, 9 | `SshProbe.cs:63` | SSH server | 32-byte public keys | `authorized_keys` | `ssh.client` |

### 1.3 Tokens and devices

| # | Item | Lessons | Made today | Holder | Format | A real one is | Switch |
|---|---|---|---|---|---|---|---|
| 20 | Token verify key | 10 | `Lesson10Auth.cs:228` | Server | 32-byte public key | A JWKS entry | `token.issuer` |
| 21 | Enrolled device key and its enrolment row. The same key signs DPoP proofs | 10 | Drawn per run, `Lesson10Auth.cs:193`; row at `:209`; proof at `:371` | Client holds the seed. Issuer holds the public key | Ed25519 seed | A passkey-shaped device key | `device.enrolment` |

### 1.4 DUKPT state and test data

| # | Item | Lessons | Made today | Holder | Format | A real one is | Switch |
|---|---|---|---|---|---|---|---|
| 22 | Lesson 6 initial key and key id `MMPTRAIN` | 6 | `Lesson06Dukpt.cs:52,105` | PIN pad | 16 bytes, 8-byte id | An initial key injected by a key loader | `dukpt.pad` |
| 23 | Lesson 9 injected key and key id | 9 | Constants, `PinEnvelope.cs:83` | PIN pad | 16 bytes, 8-byte id | Same | `dukpt.pad` |
| 24 | KSN ledger and pad counter | 6, 9 | `DukptBank.cs:70`, `DukptPinPad` | Bank, pad | Memory only | HSM and device state | None, follows #8 |
| 25 | PIN `1234`, PAN `4111111111111111` | 6, 9 | Constants, `Lesson06Dukpt.cs:38`, `Lesson09Bridge.cs:27`, `--pin`, `--pan` | PIN pad | Text | **Refused. See below** | None |

### 1.5 Session and per-run secrets

| # | Item | Lessons | Made today | Holder | Format | Real? | Switch |
|---|---|---|---|---|---|---|---|
| 26 | `aes.key` | 1 | Drawn, `Lesson01Aes.cs:64` | Both sides | 16 bytes | A data key from a KMS | `lab.aes-key` |
| 27 | `seal.key` | 2 | Drawn, `Lesson02Seals.cs:58` | Both sides | Bytes | A data key from a KMS | `lab.seal-key` |
| 28 | X25519 and ML-KEM ephemerals | 3 | Drawn, `Lesson03Kex.cs:88,97` | Each side, per round | Scalars, keypairs | Ephemeral by definition | None |
| 29 | TLS 1.3 session secrets | 4, 5, 7, 9, 10 | `Tls13Rules.cs:41-57` | Each side | 32 to 48 bytes | Ephemeral by definition | None |
| 30 | TLS 1.1 premaster, master, write keys, ECDHE scalar | 7 | `Tls11Rules.cs:120-125,222,302` | Each side | Bytes | Ephemeral by definition | None |
| 31 | SSH ephemeral, K, H, session keys | 8, 9 | `SshKex.cs:94-107`, `SshClientRules.cs:72` | Each side | Bytes | Ephemeral by definition | None |
| 32 | Per-sale DUKPT working keys | 6, 9 | `Lesson06Dukpt.cs:183,226`, `PinEnvelope.cs:165` | Pad, bank | 16 bytes | Derived per sale | None, follows #8 |
| 33 | Challenge and token values | 10 | `Lesson10Auth.cs:259,265,296` | Client, issuer | Bytes | Per login | None |
| 34 | `lab-secret` | 11 | `Lesson11Timing.cs:96`, 4 bytes | Target | 4 bytes | **Nothing. See below** | None |

### 1.6 What cannot go Real, and why

| Item | Why |
|---|---|
| #11 attacker key | An attacker's key has no real owner. Attack rows stay the same in both modes |
| #16 attack certificates | They need a CA that signs a bad certificate. They run only when `pki.root-ca` can sign. With a trust-only CA, rows `L4-expired-cert`, `L4-wrong-name`, and `L10-wrong-client-name` show as unavailable, with code `ATTACK_NEEDS_CA_KEY` |
| #28 to #33 | They exist for one run. A provisioned one would be wrong |
| #34 `lab-secret` | The timing lab needs a chosen 4-byte secret so the guess loop can finish (`Lesson11Timing.cs:31`). A real secret has no such size |
| #25 PIN and PAN | **Pushback.** Steve said "real data", and these two stay test values. Glass traces show the clear PIN field, and a real PAN or PIN there is cardholder data. PRD line 179 records a public data class. The wizard offers no field for them, and `--pan` refuses a number outside a short list of test numbers, with code `TEST_DATA_ONLY`. I would change this only if Steve asks for it and Dave has read it |

### 1.7 Labs and protocols against the switches

| Lab | Protocol | Switches it reads |
|---|---|---|
| 0 Toy | Echo | None |
| 1 AES | AES modes | `lab.aes-key` |
| 2 Seals | Hash, HMAC, CMAC | `lab.seal-key` |
| 3 Key agreement | X25519, ML-KEM, hybrid | None |
| 4, 5 TLS 1.3 | TLS 1.3, X25519 and `X25519MLKEM768` | `pki.root-ca`, `tls13.server`, `tls.trust` |
| 6 DUKPT | AES DUKPT, ISO 9564 format 4 | `dukpt.bdk`, `dukpt.pad` |
| 7 TLS 1.1 | TLS 1.1 with RSA key transport, beside TLS 1.3 | `pki.root-ca`, `tls11.server`, `tls13.server`, `tls.trust` |
| 8 SSH | SSH-2, modern and legacy | `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.known-hosts`, `ssh.client` |
| 9 Bridge | SSH or TLS 1.1, TLS 1.3 hybrid, DUKPT | `ssh.host-ed25519` or `ssh.host-rsa`, `ssh.known-hosts`, `ssh.client`, `pki.root-ca`, `tls13.server`, `tls.trust`, `dukpt.bdk`, `dukpt.pad` |
| 10 Auth | Mutual TLS, JWS, DPoP, challenge | `pki.root-ca`, `tls13.server`, `tls13.client`, `tls.trust`, `token.issuer`, `device.enrolment` |
| 11 Timing | Native compare | None |

`Probe` and `TrainingPki` stay on training keys in every mode, because `acceptance/` grades with them. Those 9 of the 24 sites do not change.

### 1.8 What the engines accept today

These limits decide which real items a wizard can accept.

| Engine | Accepts | Evidence |
|---|---|---|
| Chain check, all TLS | A certificate signed by Ed25519 only | `Certificate.cs:216` |
| TLS 1.3 signature | `ed25519` only | `Tls13Rules.cs:32` |
| TLS 1.1 server key | RSA only | `Tls11Rules.cs:179` |
| SSH user key | Ed25519 only | `SshServerRules.cs:138`, `SshClientRules.cs:166` |
| SSH host key | Ed25519 or RSA | `SshHostKey.cs:37-38`, RSA signs with SHA-1 |
| Token, challenge, DPoP | Ed25519 only | `Auth.cs:101` |

Result: no certificate from a public CA runs in a glass engine today, and no ECDSA certificate can run there at any slice of this plan (decision O2).

## 2. Per-type mode

### 2.1 Resolution rules

| Question | Answer |
|---|---|
| Which option wins | One row per type in `modes.json`: `mode` and `binding`. There is no global switch |
| When is it chosen | At `session.start`. The Host builds an immutable `CredentialSet`, and a fork reuses its parent's set |
| Both exist | A type has one active binding. Older versions stay stored and unused |
| None exists | Mock always exists. Real with no binding is `Unconfigured` |
| Where is it visible | The security page, `session.started.security[]`, the session file's first line, and a chip beside TRAINING ONLY |
| Many accounts or projects | One learner, one machine: an explicit non-goal. Each worktree has its own `.security/` folder |

### 2.2 States

A type in Mock has no state to manage. A type in Real has one of the four states. `Broken` is computed at read time and is never stored.

| State | Means | Moves to |
|---|---|---|
| `Unconfigured` | Mode is Real and no binding exists | `Configured`, when a wizard writes the binding |
| `Configured` | A binding exists, and the proof has not passed for this version | `Verified`, when the proof passes |
| `Verified` | The referee passed for this version | `Broken`, or `Configured` when the version changes |
| `Broken` | Was verified, and now the file hash changed, the certificate expired, or the key is gone | `Configured` after a fix. The wizard names the cause |

```csharp
public enum CredentialMode { Mock, Real }
public enum Readiness { Ready, Unconfigured, Configured, Broken }
public sealed class LabDecision { public readonly bool MayRun; public readonly TypeProblem[] Problems; }   // TypeProblem { TypeId, Code, Detail }
public static class SecurityReadiness {
    // Pure. Same input, same answer. A test calls it with no Host, no file, and no clock of its own.
    public static LabDecision Decide(string[] typesTheLabReads, SecurityTypeState[] states, DateTime now);
}
public static class LabCatalog { public static string[] Needs(int lesson); }   // Added beside Find. The table in 1.7 as data
```

### 2.3 What a lab does

| Case | Lab behaviour |
|---|---|
| All its types are Mock | Runs as today. Byte-equal to today, by the slice M0 check |
| A Real type is `Verified` | Runs with the Real item |
| A Real type is `Configured` | **Refuses** with `SECURITY_TYPE_NOT_PROVEN`, because an unproved key can fail for an unnamed reason inside a lesson |
| A Real type is `Unconfigured` or `Broken` | **Refuses** with `SECURITY_TYPE_NOT_READY`, naming each type and its wizard route |
| Types disagree | **Refuses** with `SECURITY_TYPES_DISAGREE`. Example: `tls13.server` is Real and `tls.trust` is Mock, so the chain cannot reach an anchor. The rule runs before the lab starts |
| An attack row needs what the item lacks | The row shows `available: false` with its code, and the lab itself runs |

A lab never falls back to Mock in silence. A silent fallback is the green-light drift the house rules name: the run would report success on the wrong key. To run with Mock, the learner flips the type to Mock.

Decision point: `session.start` (gem `decide-at-authoritative-boundary`).

### 2.4 Derived bindings

Three types default to following another type, so a new user meets one wizard, and the types disagree only on purpose.

| Type | Default binding |
|---|---|
| `tls.trust` | The root of `pki.root-ca` |
| `ssh.known-hosts` | The public key of the matching host key type |
| `dukpt.pad` | Derived inside the box from `dukpt.bdk`, with a new key id for each lab run |

A new key id per run means each sale gets an unused KSN, with no register state to store. The cost: a same-seed fork of a Real DUKPT run differs in its key id. Mock keeps today's fixed id.

## 3. Plugin seam

### 3.1 Signatures

All in `src/NetSec.Core/Keys`, C# 3, on both builds. This is additive except for `IKeyHandle`, which has no implementer today. Keys sits below Io in `tools/layer_check.py`, so nothing here names a Dukpt or Io type.

```csharp
public enum KeyAlgorithm { Ed25519, X25519, Rsa2048, Aes128, Aes256, Raw, Rsa }   // Added Rsa: any modulus of 2048 bits or more
public enum SignScheme { Ed25519, RsaPkcs1Sha1, RsaPkcs1Sha256, RsaPkcs1Md5Sha1 }

public interface IKeyHandle {                 // Widened. No member returns private bytes
    string KeyId {get;}  KeyAlgorithm Algorithm {get;}
    byte[] Public();
    byte[] Sign(SignScheme scheme, byte[] message);
}
public interface IKeyTransportHandle : IKeyHandle { bool TryDecryptPkcs1(byte[] cipher, out byte[] plain); }   // TLS 1.1 key transport
public interface IBaseKey {                   // A BDK. The derivation runs in the box
    string KeyId {get;}  KeyAlgorithm Algorithm {get;}  string CheckValue {get;}
    byte[] DeriveInitialKey(byte[] initialKeyId);
    byte[] DeriveWorkingKey(byte[] ksn, int usage, int keyType);
}
public interface IDataKeySource { byte[] NewDataKey(int size, IRandomSource labRandom); }   // Mock draws from labRandom, so same-seed runs stay equal. Real ignores it

public sealed class Credential {              // One security type, resolved. Immutable
    public readonly string TypeId, ProviderKind, Fingerprint, PeerName;
    public readonly CredentialMode Mode;
    public readonly int Version;
    public readonly IKeyHandle Key;           // Null for a type with no private half
    public readonly IBaseKey BaseKey;         // dukpt.bdk only
    public readonly IDataKeySource DataKeys;  // lab.aes-key and lab.seal-key only
    public readonly byte[][] Chain, Anchors;  // DER. Leaf first
    public readonly string Lines;             // known_hosts or authorized_keys text
}
public sealed class CredentialBinding { public string TypeId, ProviderKind, Locator; public int Version; }
public interface ICredentialProvider {
    string Kind {get;}                        // "mock", "file", "os-store", "vault"
    CredentialCheck Check(CredentialBinding binding);   // Cheap. Uses no private key
    Credential Open(CredentialBinding binding);
}
public sealed class CredentialSet {           // What a lab holds. A snapshot
    public Credential Get(string typeId);     // A missing type throws SECURITY_TYPE_NOT_READY
    public CredentialSummary[] Summary();     // Public facts only. Goes in session.started and the session file
    public static CredentialSet Mock(ITrainingKeySource keys);
}
public static class SecurityTypes { public const string RootCa = "pki.root-ca"; /* and the other 14 */ }
```

The additions outside `Keys`:

```csharp
public sealed class LabContext { /* existing fields */ public CredentialSet Credentials; }   // Null means CredentialSet.Mock(new TrainingKeySource())
public sealed class GlassTransportFactory { public GlassTransportFactory(ITrainingKeySource keys); public GlassTransportFactory(CredentialSet credentials); }
public sealed class TrainingCa { /* existing */ public TrainingCa(IKeyHandle key, string name); }
public static class Token { /* existing */ public static string Issue(IKeyHandle k, string claimsJson); }
```

`ITrainingKeySource` stays the root of Mock: `MockCredentialProvider` wraps `TrainingKeySource`, and its handle calls the same `Ed25519.Sign` on the same seed.

### 3.2 Providers

| Provider | Project, build | Handles | Refuses by name |
|---|---|---|---|
| `mock` | Core, both builds | All 15 types | Nothing |
| `file`: PEM, PKCS#8, OpenSSH | Core, both builds. Reuses `Der`, `RsaPkcs8`. It is the only Real provider the CE process can use | Ed25519, RSA | `KEY_FILE_ENCRYPTED`, `KEY_FILE_FORMAT` |
| `file`: PKCS#12 | Host, net10 only, through `X509CertificateLoader` | RSA only. Spike: Ed25519 PKCS#12 throws | `PKCS12_ED25519_UNSUPPORTED`, `PKCS12_PASSWORD` |
| `os-store` | Host, net10 only, `X509Store` and `RSACng` | RSA only: PKCS#1 decrypt and SHA-1 sign pass in the spike. The raw 36-byte form failed, so the TLS 1.1 ECDHE suite is out. The lab forces RSA key transport (`Lesson07Tls11.cs` `Common`), so lesson 7 still works | `OS_STORE_NOT_FOUND`, `OS_STORE_KEY_NOT_USABLE` |
| `vault` | New `src/NetSec.Vault`, net10 only. Host and Node reference it | All key types | Section 4 |

The CE process and the CF build never see SQLite, PKCS#12, or the OS store. `NetSec.CeDevice` takes `--key-file` and `--known-hosts-file`. `CeDevice/Program.cs:52` keeps the Mock path when the flags are absent. A vault key cannot reach CE, and that is accurate: a device holds its own key.

### 3.3 Engine changes

Each row adds a field or overload, and existing contract signatures stay. A rule then calls one path, and the seed wraps once at the boundary.

| Site | Today | After |
|---|---|---|
| `Tls13ClientTable.cs:129`, `Tls13ServerTable.cs:58` | `Ed25519.Sign(o.SigningSeed, ...)` | `o.Signer.Sign(...)`. `Tls13Engine.cs:39` wraps `SigningSeed` when no signer is set |
| `Tls11Rules.cs:301`, `:334` | `Pkcs1` on `RsaPrivate` | `IKeyTransportHandle` |
| `SshHostKey.cs:106`, `SshClientRules.cs:169` | `CopyMaterial()` | `Sign`. Algorithm name and blob come from `Public()` |
| `Auth.cs:102`, `:186`, `:276` | Seed to `CompactJws`, `DpopProof`, `Challenge` | Overloads that take a handle |
| `TrainingCa.cs:104` | `Ed25519.Sign(_seed, tbs)` | Handle |
| `DukptBank`, `BankHsmCore.Decide`, `Lesson06Dukpt.cs:82`, `Node/Program.cs:114` | `byte[] bdk` | `IBaseKey`. The byte overloads stay for A3 |
| 12 `new TrainingKeySource()` sites in Labs | Per lab | `LabCredentials.Of(c).Get(...)` |

### 3.4 Effect on D5, D6, and A16

| Item | Effect |
|---|---|
| D5 last sentence, "a real key cannot enter it by type" | Replaced. New D15: a real key enters a glass engine only as operations, and its private bytes stay outside the engine |
| D6 last sentence, "Real-key routes... do not exist" | Retired. The rest of D6 stays and governs the transport axis |
| `A16.type.keyhandle-cannot-reach-glass-factory` | **Stays green.** Its 4 attack programs still fail. A probe of the two-constructor shape gave CS1503 on both handle programs and compiled the control |
| `A16.type.core-holds-no-keyhandle-implementation-and-no-io-member-takes-one` | **Must change.** Core gains `IKeyHandle` implementations (mock and file). The Io half stays true: `CredentialSet` is the public type there |
| Design section 11, A16 row, "its only constructor" | Text edit |
| `acceptance/contract/Io.cs` | The stub gains the new shape. Echo owns it |

The replacement anchor is stronger than a type wall. A canary key goes Real in every type, every lesson runs, and a scan looks for its bytes in hex and base64 across frames, session files, and the repo tree. The old clause proved a compile error. The new one proves absence from output.

I chose not to add a same-shape interface that leaves the clause green. That would keep a passing check whose reason had already moved.

## 4. Vault facade

### 4.1 What it is

`src/NetSec.Vault`, net10.0, C# 14. One interface, in the shape a real vault presents. The class boundary stands for the HSM's device boundary, and the tour says so.

```csharp
public interface IVault {
    VaultKeyInfo CreateKey(string name, VaultKeyPolicy policy, string caller);
    int Generate(string name, string caller);                // Adds a version
    int Import(string name, byte[] material, string caller); // Adds a version. provenance = imported
    VaultKeyInfo Describe(string name);
    byte[] PublicKey(string name, int? version);
    byte[] Sign(string name, SignScheme scheme, byte[] message, string caller);
    bool TryDecrypt(string name, byte[] cipher, out byte[] plain, string caller);
    byte[] Derive(string name, VaultDerive purpose, byte[] input, string caller);
    VaultDataKey GenerateDataKey(string name, int size, string caller);   // Clear copy and wrapped copy
    byte[] Export(string name, string caller);               // VAULT_EXPORT_REFUSED for a non-exportable key
    void Retire(string name, int version, string caller);
    AuditRow[] Audit(long afterSeq, int limit);
}
public sealed class VaultKeyPolicy { public string Algorithm; public bool Exportable; public string[] AllowedOps; public string[] AllowedCallers; }
```

Tables, as the spike ran them, plus `provenance`, `allowed_callers`, and `prev_hash`:

```sql
key_names(name PK, algorithm, exportable, allowed_ops, allowed_callers, provenance, created_at)
key_versions(name, version, nonce, wrapped, public_key, fingerprint, state, created_at, PK(name, version))
audit(seq PK AUTOINCREMENT, at, caller, op, name, version, result, detail, prev_hash)
```

Wrapping: AES-256-GCM under a master key, with `name#version` as the additional data. A row moved to another name fails to open. `audit.prev_hash` links each row to the last (`GEM:seeded-hash-linked-custody-chain`), so an edited row shows.

### 4.2 How far it goes for accuracy

| Behaviour | Real HSM or vault | Facade |
|---|---|---|
| Named keys and versions | Yes (Vault transit: "supports versioning of keys") | Yes |
| Policy per key | Yes | Yes: operations and callers |
| Audit log | Yes | Yes, with a refused call logged too. Spike row 7 |
| Wrapped at rest | Yes | Yes. Tampered row refused in the spike |
| Sign inside the box | Yes | **Yes** |
| Refuse export of a non-exportable key | Yes (PKCS#11 `CKA_EXTRACTABLE`, from recollection, not read this session) | **Yes. Spike: `VAULT_EXPORT_REFUSED`** |
| Data key: clear copy and wrapped copy | Yes (AWS KMS `GenerateDataKey`, page read this session) | Yes, for lessons 1 and 2 |
| DUKPT base key stays in | Yes | **Yes** |
| DUKPT per-sale key stays in | Yes, a real HSM translates the PIN inside (from recollection) | **No.** The facade hands it out so lesson 6 can show one key per sale. A line in the UI says "A real HSM would not hand this out" |
| Tamper-resistant hardware, FIPS, a separate process | Yes | **No.** The private bytes sit in the Host's memory during a call. The tour says so |
| Seal and unseal, quorum | Yes | **No,** except BDK components (below) |
| Network API, client certificates, PKCS#11 interface | Yes | **No.** `IVault` is the seam if one is ever wanted |

### 4.3 How it meets the engines

The engines take raw bytes today (section 3.3). After the seam they call operations.

| Operation | Called from | What the trace shows |
|---|---|---|
| Sign, Ed25519 | TLS 1.3 `CertificateVerify`, SSH host and user, token, challenge, DPoP, CA issue | `vault.sign`: key name, version, SHA-256 of the input, signature. Signature bytes are public anyway |
| Decrypt, PKCS#1 | TLS 1.1 key transport | `vault.decrypt`: key name, version. The premaster still shows as a session secret, as the lab teaches |
| Sign, RSA | TLS 1.1 ECDHE, SSH legacy | As above |
| Derive | DUKPT bank | `vault.derive`: key name, version, KSN |
| Data key | Lessons 1, 2 | `vault.datakey`. The key then shows as a session secret, since the lab misuses it on purpose |

These `vault.*` events appear only in Real mode, so tour bindings on Mock stay as they are. Each event pairs with an audit row, so the learner can read both sides of one call.

### 4.4 Package and spike

| Fact | Value |
|---|---|
| Package | `Microsoft.Data.Sqlite.Core` 10.0.9 with `SQLitePCLRaw.bundle_e_sqlite3` 3.0.3 |
| In the NuGet cache | Yes, both, with `SourceGear.sqlite3` 3.50.4.5 |
| Rejected | `Microsoft.Data.Sqlite` 10.0.9. It pulls `SQLitePCLRaw.lib.e_sqlite3` 2.1.11: NU1903, GHSA-2m69-gcr7-jv3q, high, SQLite before 3.50.2. `Directory.Build.props:5` sets `TreatWarningsAsErrors`, so a repo build would fail |
| Native file | `runtimes/win-x64/native/e_sqlite3.dll`, in the build output, never in git. `THIRD-PARTY-NOTICES.md` gains a section. Licences not read yet: the slice M1 builder reads them |

The spike is a throwaway console project outside the repo, in the session scratch folder. It references `NetSec.Core` for `Ed25519`. Final run, package pair above, foreground, under the 2-minute limit:

```
runtime .NET 10.0.14, Microsoft.Data.Sqlite 10.0.9.0
create: tables key_names, key_versions, audit
store: tls13/server versions 1, 2 (non-exportable); lab/aes-data version 1 (exportable)
read: sign inside the box with version 2, signature 64 B, fingerprint SHA256:i3Js/0lEx6Pj1msYyG5OtHY7U4p+CxAhPjT1MNmj+gs
check: NetSec.Core Ed25519.Verify = True
referee: openssl pkeyutl -verify -rawin: Signature Verified Successfully
export non-exportable: refused VAULT_EXPORT_REFUSED: this key was made non-exportable, as an HSM key is
export exportable: 16 B, as a data key
tampered row: refused VAULT_UNWRAP_FAILED: the stored row or the master key changed
1000 sign calls with one audit row each: 2348 ms (2.35 ms per call)
audit, first 8 rows:
  1 wizard create tls13/server v- ok
  2 wizard generate tls13/server v1 ok
  3 wizard generate tls13/server v2 ok
  4 wizard create lab/aes-data v- ok
  5 wizard generate lab/aes-data v1 ok
  6 lesson-5/server sign tls13/server v2 ok
  7 wizard-demo export tls13/server v- refused VAULT_EXPORT_REFUSED
  8 lesson-1/client export lab/aes-data v1 ok
audit rows 1011, file bytes 106496 plus WAL

--- probes the design depends on
BCL types with Ed25519 in the name: none
RSACng raw PKCS#1 over 36 bytes, no prefix (TLS 1.1 ServerKeyExchange): FAILED CryptographicException: Unknown error (0xc1000225)
RSACng PKCS#1 SHA-1 sign (SSH legacy host key): 256 B
RSACng PKCS#1 decrypt (TLS 1.1 key transport): 48 B
X509Certificate2 reads an Ed25519 PEM: FAILED CryptographicException: '1.3.101.112' is not a known key algorithm.
X509Certificate2 reads Ed25519 PEM with key: FAILED CryptographicException: '1.3.101.112' is not a known key algorithm.
PKCS#12 ed25519 through X509CertificateLoader: FAILED CryptographicException: Invalid algorithm specified.
SslStream TLS 1.3 client to s_server with ed25519 cert: FAILED: AuthenticationException: The message received was unexpected or badly formatted.
PKCS#12 rsa through X509CertificateLoader: HasPrivateKey=True, RSA=True, ECDsa=False
SslStream TLS 1.3 client to s_server with rsa cert: ok, Tls13, TLS_AES_256_GCM_SHA384
```

Limits of the probes: the raw 36-byte test tried one hash name, `MD5SHA1`, so another route may exist. The OS store itself was not touched, since that writes machine state; `RSACng` used an ephemeral key. The spike's vault is a single process. Host and Node on one file (WAL mode) is unproved until slice M6.

## 5. Where things live

### 5.1 Folders

One root, inside the project, per Steve's "within the project". `NETSEC_SECURITY_DIR` overrides it, and `acceptance/` sets that to a temp folder. The Host finds the default by the walk up from `AppContext.BaseDirectory` that `Program.cs:114` already uses.

```
<repo>/.security/                  gitignored as a whole
  README.txt                       What this folder is. Written by the Host
  modes.json                       Mode, binding, proof result per type. No secret
  vault/vault.db, -wal, -shm       Section 4
  vault/master.key                 32 random bytes
  files/<typeId>/v<N>/             Copies of imported files, plus chain.pem
  ssh/known_hosts                  Written when the pin is not derived
  ssh/authorized_keys
  pads/<keyId>.key                 Lesson 9 process run only. The pad deletes it on load, as a key loader's job ends
  proof/<wizardId>/                Referee scratch. Deleted when the proof ends
```

Session files stay in `%LOCALAPPDATA%\MMP.NetworkSecurity\sessions\` (`Program.cs:26`), since `A16.real-mode` and the UI read them there.

| Stored by | What |
|---|---|
| Thumbprint in `modes.json`, nothing on disk | OS store items |
| A copy in `files/` | An imported file. A moved original then cannot break a verified type. The stored hash feeds `Broken` |

`.gitignore` gains `.security/`, `*.pfx`, `*.p12`, and `*.db`.

### 5.2 The check that a real key is never committed

**One enforcement: an acceptance clause that runs a script. Proposed id: `A17.repo.no-real-key-tracked`.** A git hook would not travel with a clone and can be skipped. A clause cannot. `tools/gate.ps1` calls the same script on every slice.

`tools/secret_guard.py` runs over `git ls-files` plus the staged set, and fails on:

| Rule | Detail |
|---|---|
| Path | Anything under `.security/`, or any `.pfx`, `.p12`, `.db`, `.key`, `master.key`, `id_rsa`, `id_ed25519`, `known_hosts` |
| PEM header | `PRIVATE KEY` in a file outside the allow-list. Today that is 3 files: `src/NetSec.Core/Pki/TrainingPki.cs`, `tests/NetSec.Tests/Tls13Tests.cs`, `acceptance/lib/Harness/OpenSshKey.cs` |
| Ignore rule | `.gitignore` must hold the `.security/` line, and `git check-ignore .security/x` must agree |

The clause runs beside a control: on a temp clone, a planted PEM file and a planted `.security/` file must each fail the script by name, and the unchanged tree must pass. Current state: `git ls-files` finds no key file today.

The canary scan in section 3.4 covers the other route, a key that leaks through a trace into a committed file.

## 6. Trace and display

### 6.1 Rule

| Class | Mock | Real | Session file and export |
|---|---|---|---|
| Long-term private material | Shown, as today | **Never shown or written.** Shows a fingerprint | Fingerprint |
| Session secrets (#28 to #33) | Shown | **Still shown** on glass | Written |
| Public material, signatures, certificates | Shown | Shown | Written |
| OS transport session | Not applicable | Metadata only. `secrets[]` empty, key log refused (A16) | Metadata only |

Fingerprints: `SHA256:<base64>` for an asymmetric key, the form `SshHostKey` already prints. For a symmetric key, a check value: AES-CMAC over a zero block, first 5 bytes. That KCV form is from recollection, so a builder should mark it in the UI as this course's check value until someone reads the source.

### 6.2 How it holds

Today long-term secrets reach a trace at only 3 sites: `Lesson06Dukpt.cs:205` (`dukpt.bdk`), `:138` and `:206` (`dukpt.initial`), and `Lesson10Auth.cs:250` (`auth.device-key`). In Real the rule has no bytes to give at those sites, so no redaction filter is needed. A new effect carries the public fact:

```csharp
public static StepEffect Fingerprint(string holder, string name, string fingerprint, params string[] from);   // In Effect. TraceSecret gains Class and Fingerprint. Hex stays empty
```

`TraceJson` adds `class` and `fingerprint`, both additive. `SecretsPanel.vue:13,36,38` reads `hex` directly, and its two-sides-match test compares `hex`, so Nancy needs a branch there. The session file gains a first line, `{"type":"session.security", ...}`, from `CredentialSet.Summary()`. `session.load` must skip that line when it feeds trace frames (`Program.cs:275`).

### 6.3 Trade-off

| Choice | Gains | Costs |
|---|---|---|
| Hide long-term private material | The lesson becomes "the key stayed in the box", which is how an HSM works. A shared trace cannot impersonate the server later, and cannot open recorded RSA key transport sessions (lesson 7) | The learner cannot see those bytes in Real. Mock still shows them |
| Keep showing session secrets | Every lesson still works: the key schedule, the traffic keys, "two sides, one key" | Anyone with a session file can read that session's traffic. That risk stops at one session, and the labs run on loopback |

### 6.4 When showing all is the better call

Showing everything wins when **every** Real item meets all three conditions: the wizard generated it in this vault, its policy is exportable, and nothing outside this course trusts it. In that case hiding costs learning and protects nothing. That matches Steve's "we do NOT need to be super-secure".

So: each item with `provenance = generated` and `exportable = true` gets one control, "Show this key in lessons", off by default. It emits `vault.export` and writes an audit row. An imported key refuses with `REVEAL_IMPORTED_REFUSED`, because someone else may trust it. A non-exportable key cannot be shown at all, which is the lesson.

If Steve wants everything shown everywhere, the change is one condition in that rule. It would also retire the canary clause's long-term half.

## 7. Relationship to unbuilt real mode

**Recommendation: two axes.** They answer different questions and fail in different ways. The design's own words already separate them: D6 is about transport, and D5 is about keys.

| | Keys: all Mock | Keys: some Real |
|---|---|---|
| **Transport: glass** | Today. 207 of 208 pass | New. All lessons. Session secrets show, long-term keys show as fingerprints |
| **Transport: OS** (`SslStream`) | Needs a non-Ed25519 peer certificate. Spike: Schannel fails on Ed25519. Metadata only | Lesson 5, with `tls.trust` as the custom trust store. RSA peer certificate. Metadata only |

The axes touch at one place: the wizard's key choice. "Ed25519" runs on glass only. "RSA" runs on OS transport, and on glass after slice M5. The CA wizard states this choice in short, clear words.

The new dropdown from PR #98, `ui.target` (`store.ts:41-48`), is a third axis. It stays independent, and the CE rows stay disabled. Real credentials reach a future CE through the file provider.

### 7.1 What real mode needs

| Item | Detail | Owner |
|---|---|---|
| `OsTransportFactory` | Unbuilt. Design section 2.2 places it in the Host. `Program.cs:203` answers `REAL_MODE_NOT_BUILT` | Builder |
| Lab route | `Tls13Lab.cs:78` builds both engines directly, and no lab reads `LabContext.Transports`. So lesson 5 in real mode needs its own lab path, one client and a peer from `NETSEC_REAL_PEER` | Builder |
| Clause peer key | `HostClauses.cs:175` makes an Ed25519 key. Evidence above: `SslStream` fails on it, and RSA passes on the same probe. Change to `-algorithm rsa -pkeyopt rsa_keygen_bits:2048` | **Echo** |
| Clause trust | `HostClauses.cs:186` sets `SSL_CERT_FILE`. From recollection, Schannel does not read it. The product reads that variable and loads a `CustomTrustStore`. This needs a line in `CONTRACT.md` | Echo, builder |
| Chip bug | `store.ts:100` and `:206` use `'real'`. The clause wants `os`. Change both | Nancy |
| Button text | `App.vue:143` says "Real mode". It must change to "OS transport", or the word "Real" means two things on one screen. `transport-switch` stays as the test id | Nancy |
| Today's button | Per the closing report, it changes the label, and the error shows at the next lesson start | Fixed by the factory |

### 7.2 Open PRs

| PR | Content | Effect here |
|---|---|---|
| #90 | `StepGate` holds one early step, `EnginePump.cs` | No overlap in purpose. Merge first, because slice M0 records golden traces, and those should come from the final gate code |
| #91 | Removes the tour's 3-second resend, `app/src/store.ts`. Depends on #90 | Touches a different block of the file slice M2 edits. Merge first |

## 8. Wizard contract

UI choices belong to Nancy. This section is data only. Words live in `app/src/wizard-copy.json`, keyed by `copyId`, as `field-gloss.json` does for fields. So `tools/tour_lint.py` can hold them to grade 8.9, the tic gate can scan them, and a reader can check claims under A15a. Cussler humanizes that file. **The copy assumes no knowledge:** each step says what this thing is, why it exists, what you do now, and what breaks if it is wrong.

### 8.1 Routes

All routes sit behind `HostGuard`, per D14. Errors carry `code`, `message`, `retryable`, `requestId`, the shape at `Program.cs:51`.

| Route | Returns or does |
|---|---|
| `GET /api/security` | `{ schema, root, types: [{ typeId, titleId, mode, state, providerKind, version, fingerprint, notAfter, usedBy[], followsType, canGoReal, whyNot, problem }] }` |
| `PUT /api/security/types/{typeId}/mode` `{ mode }` | Sets the mode. Going to Mock always works, and the binding stays for later. Going to Real with no binding sets `Unconfigured`, and the UI opens the wizard |
| `POST /api/security/wizards` `{ typeId }` | `{ wizardId, step }` |
| `GET /api/security/wizards/{id}` | `{ step }`. The UI replaces its copy (gem `server-replaces-never-merges`) |
| `POST /api/security/wizards/{id}/events` `{ event, stepSeq, data }` | `{ step }`, with `errors[]` when a check refuses |
| `GET /api/security/readiness?lesson=N` | `{ mayRun, problems[] }`, from `SecurityReadiness.Decide` |
| `GET /api/security/vault/keys` | Name, algorithm, versions, policy, provenance. No private bytes |
| `GET /api/security/vault/audit?after=N` | Audit rows |
| `POST /api/security/vault/keys/{name}/export` | Runs the export. A non-exportable key gives `VAULT_EXPORT_REFUSED`. The UI can show this on purpose |
| `GET /api/lessons` | Existing. `attacks[]` gains `available` and `whyNot` |
| WebSocket `session.started` | Existing. Gains `security[]` |

A key file moves by **path**, chosen in Electron's file dialog. The Host reads it, so private bytes never cross the renderer (gem `paths-plain-at-the-boundary`). DUKPT components are the one secret typed into a field, and `fields[].mask` is true there.

### 8.2 Step payload

```json
{ "wizardId": "w1", "typeId": "tls13.server", "state": "ReadBack", "stepSeq": 4, "stepIndex": 3, "stepCount": 6,
  "kind": "review", "copyId": "wizard.tls13-server.read-back",
  "facts": { "subject": "localhost", "issuer": "my lab root", "notAfter": "2028-01-01", "algorithm": "Ed25519", "fingerprint": "SHA256:..." },
  "fields": [], "choices": [], "allowed": ["next", "back", "cancel"], "errors": [] }
```

`kind` is one of `explain`, `choose`, `file`, `entry`, `generate`, `review`, `prove`, `done`. `allowed` comes from the table, so the UI cannot offer a move the machine refuses.

### 8.3 The machine owns the moves

A table, in the shape of `StepTable`. `WizardMachine.Decide` is pure, and the Host applies the effects (the house decide-then-act rule). An event with no row from the current state gets `WIZARD_EVENT_NOT_ALLOWED`, naming both, as `UNEXPECTED_MESSAGE` does in the engines. A stale `stepSeq` gets `WIZARD_STEP_STALE`.

```csharp
public sealed record WizardRow(string From, string Event, Func<WizardFacts, WizardCheck> Guard, string To, WizardEffect[] Effects);
public static class WizardMachine { public static WizardDecision Decide(WizardTable table, WizardState state, WizardEvent e); }
```

Every family runs this spine: `Intro`, `ChooseSource`, source steps, `ReadBack`, `Place`, `Prove`, `Done`. `back` works up to `Place`. `Place` writes a new version and leaves the old one, so a failed proof loses nothing.

| Family | Types | Sources offered | Source steps |
|---|---|---|---|
| F1 Certificate and key | `pki.root-ca`, `tls13.server`, `tls13.client`, `tls11.server` | Make one for me (vault, default). Import PEM. Import PKCS#12 (RSA). OS store (RSA) | Choose the key kind: Ed25519 or RSA. Name. Or pick the file, then the key and chain |
| F2 Trust list | `tls.trust` | Follow my root (default). Import certificates | Pick files, read each back |
| F3 SSH key | `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.client` | Make one for me (vault, default). Import OpenSSH. `ssh.client` adds "for the CE process": file only | Pick the file. Show the public line |
| F4 Pin | `ssh.known-hosts` | Follow my host key (default). Paste a `known_hosts` line. Learn on first connect | Show the fingerprint, and ask the learner to compare it another way. `Lesson08Ssh.cs` already teaches this moment |
| F5 Key ceremony | `dukpt.bdk`, `dukpt.pad` | Enter components (default). Import a vendor test key. `dukpt.pad` follows | Component 1, its check value. Component 2, its check value. Optional 3. Combine by XOR in the box. Compare the final check value. Choose non-exportable |
| F6 Signer | `token.issuer` | Make one for me (vault, default). Import PEM | Pick issuer name and audience |
| F7 Device | `device.enrolment` | Make one for me (default). Import PEM | Subject name. Show the enrolment row |
| F8 Data key | `lab.aes-key`, `lab.seal-key` | Make a wrapping key for me | One screen |

Generating a key and importing a certificate from an outside CA needs a CSR step. It is left out of the first build, and the `kind` list has room for it (decision O8).

### 8.4 Named errors

| Code | Means | Family |
|---|---|---|
| `KEY_FILE_UNREADABLE`, `KEY_FILE_FORMAT`, `KEY_FILE_ENCRYPTED` | Cannot read it. The copy says how to remove the passphrase on a test key | F1, F3, F6, F7 |
| `KEY_ALGORITHM_NOT_IN_ENGINE` | Example: ECDSA. Names what the engine takes, and names OS transport as the route | F1, F3 |
| `KEY_CERT_MISMATCH` | Certificate and key are not a pair | F1 |
| `CERT_EXPIRED`, `CERT_NOT_YET_VALID` | Dates. Same codes as `ChainCheck` where they exist | F1, F2 |
| `CERT_NAME_MISSING`, `CERT_USAGE_WRONG`, `CERT_NOT_A_CA` | Name, EKU, or basic constraints | F1, F2 |
| `CHAIN_INCOMPLETE`, `CHAIN_SIGNATURE_NOT_IN_ENGINE` | Missing issuer, or an unsupported signature | F1 |
| `PKCS12_PASSWORD`, `PKCS12_ED25519_UNSUPPORTED` | From the spike | F1 |
| `OS_STORE_NOT_FOUND`, `OS_STORE_KEY_NOT_USABLE` | Thumbprint gone, or wrong key kind | F1 |
| `KNOWN_HOSTS_LINE_BAD` | The line does not parse. Wildcards refused, as `SshKnownHosts` does | F4 |
| `DUKPT_COMPONENT_LENGTH`, `DUKPT_KCV_MISMATCH` | Wrong size, or a typing error | F5 |
| `VAULT_KEY_UNKNOWN`, `VAULT_OP_REFUSED`, `VAULT_EXPORT_REFUSED`, `VAULT_UNWRAP_FAILED`, `VAULT_CALLER_REFUSED` | Section 4 | All |
| `REFEREE_MISSING` | Referee not on this machine | Prove |
| `PROOF_FAILED` | The referee said no. The output is attached | Prove |
| `WIZARD_EVENT_NOT_ALLOWED`, `WIZARD_STEP_STALE`, `WIZARD_NOT_FOUND` | Machine | All |

Each branch ends in one sentence on what happened and what to do, with detail to the log (gem `plain-sentence-error-surface`).

### 8.5 Prove it works

`Prove` runs a real tool against the real item, and shows the learner the command and its real output. A pass stores `{ referee, command, outputTail, passed, at, version }` and moves the type to `Verified`.

| Type | Referee command | Fallback when absent |
|---|---|---|
| `pki.root-ca` | `openssl verify -CAfile root.pem root.pem`, then issue a test leaf and verify it | BCL chain check, for RSA only. For Ed25519 none, so `REFEREE_MISSING` |
| `tls13.server` | `openssl s_client -tls1_3 -CAfile <anchors> -verify_return_error` against a glass server on this handle | None |
| `tls13.client` | `openssl s_server -tls1_3 -Verify 1 -CAfile <anchors>` against the glass client | None |
| `tls.trust` | `openssl verify -CAfile <anchors> <active leaf>` | None |
| `tls11.server` | `openssl s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile <anchors>`, as `Tls11Tests` does | None |
| `ssh.host-*` | `ssh.exe -F NUL -o BatchMode=yes -o UserKnownHostsFile=<pin> ...` runs `echo hello` on the glass server | None |
| `ssh.client` | `ssh.exe` with the key file for a file key. For a vault key, the glass client against the glass server, marked as lower tier, because no outside tool can use a vault key | Same |
| `ssh.known-hosts` | Connect to the host key type's server. A pin mismatch names `SSH_HOST_KEY_CHANGED` | None |
| `dukpt.bdk` | Two steps. First, a control: the vault's derive code, on the published X9 test BDK, must give the published vector. Then a round trip under the real key, with the final check value compared | The vector needs its fetch script (PRD licence item 1) |
| `dukpt.pad` | PIN-pad to bank round trip on one sale | None |
| `token.issuer` | `openssl pkeyutl -verify -pubin -rawin` on a fresh token's signing input. The spike ran this form | Core `Token.Verify`, lower tier |
| `device.enrolment` | Same form, on a challenge answer | Same |
| `lab.aes-key`, `lab.seal-key` | Wrap, unwrap, and compare with BCL `AesGcm` | None needed |

Referees: `openssl` and `ssh.exe` at the pinned paths in design section 9, overridable by `NETSEC_OPENSSL` and `NETSEC_SSH`. `/api/health` `referees` returns an empty list today (`Program.cs:45`), and it should report these two. The product does not call `acceptance/referees/go`, because the Host must not depend on the suite's folder (D11).

A proof states its tier. A proof against an outside tool is the higher tier. A glass-to-glass proof is lower, and the UI says so.

## 9. Slices

Each slice is vertical and merges to a running `main`. Builders never write `acceptance/`. Echo writes the clauses first, and the ids below are proposals. Agents use canary keys only (PRD boundary: "use any real key" stays Steve's).

| Slice | Delivers | Closes on | Clauses Echo owes |
|---|---|---|---|
| Pre | Merge #90 and #91. D15 in the PRD after O1. Echo edits the A16 clauses and writes A17 | `run.ps1 -Contract` compiles | `A17.*` |
| **M0 skeleton** | **Golden traces from main, before any change.** `Credential`, `CredentialSet`, mock and file providers, `SecurityReadiness`, `modes.json`, routes, `WizardMachine`, one security page. **`token.issuer` end to end,** F6, file source only | Mock traces byte-equal to golden, on both builds, all 12 labs, fixed seed. Lesson 10 runs on a canary issuer. OpenSSL proof passes. Refusal shows beside a passing control. Playwright walks the wizard | `A17.mock.golden-trace-equal`, `A17.readiness.refuses-by-name`, `A17.canary.absent`, `A17.repo.no-real-key-tracked`, `A17.wizard.token-issuer-walk` |
| **M1 vault** | `NetSec.Vault`, `token.issuer` from the vault, audit page, export refusal, `vault.sign` events | Lesson 10 signs inside the box. Export refused and audited. Tampered row refused. OpenSSL verifies | `A17.vault.*` |
| **M2 OS transport** | `OsTransportFactory`, lesson 5 path, chip fix, button text. Can run beside M1: no shared files but `Program.cs` | **`A16.real-mode` passes: 208 of 208** | Clause edit from section 7.1 |
| **M3 TLS 1.3** | `pki.root-ca`, `tls13.server`, `tls13.client`, `tls.trust`, F1 and F2. `TrainingCa` on a handle. Attack availability. `TamperPlan.Field`, a named field in place of offset 1284, since a real server name moves it (`Tls13Lab.cs:36`, learnings S3 item 7) | Lessons 4, 5, 10 on canary items. OpenSSL and Go pass. Each attack row gets its named code, or `available: false` | `A17.tls13.*` |
| **M4 SSH** | `ssh.host-*`, `ssh.client`, `ssh.known-hosts`, F3 and F4. `CeDevice --key-file` | Lessons 8, 9 on canary keys. `ssh.exe` and Go pass. A9 stays green with the new file reader on net48. RSA row offset 669 moves to a named field (`Labs.cs:215`) | `A17.ssh.*` |
| **M5 RSA reach** | `tls11.server`, `KeyAlgorithm.Rsa`, RSA signatures in `Certificate.VerifySignedBy`, `rsa_pss_rsae_sha256` in TLS 1.3 per O2. PKCS#12 and OS store providers | Lesson 7 on a canary RSA chain. OpenSSL `-tls1_1` passes. A public-shape RSA chain reaches TLS 1.3 on glass and on OS | `A17.tls11.*`, `A17.rsa.*` |
| **M6 DUKPT** | `dukpt.bdk`, `dukpt.pad`, F5, `IBaseKey`. Node `--vault`. Host and Node on one vault file | X9 vector through the vault. Lessons 6, 9 on a canary BDK. A10 process run on it. No trace holds the BDK | `A17.dukpt.*` |
| **M7 the rest** | `device.enrolment`, `lab.aes-key`, `lab.seal-key`, F7, F8. "Show this key" control. Session file header | 15 of 15 types go `Verified` on canaries in one run. Reveal refused on an imported key | `A17.all-types`, `A17.reveal.*` |
| **M8 words and close** | Cussler pass on wizard copy, A15a reader, Real callouts in tours, Iolo red team, fresh-clone run | All clauses from a fresh clone. Grade and tic gates | `A17.copy.*` |

**Kill condition (proposed).** The work ends when 15 of 15 types reach `Verified` on canary items and every clause passes from a fresh clone, or on 2026-11-12, whichever comes first. The report states N of 15 and N of M.

**Complexity hotspots, named now.**

| Where | Why | Plan |
|---|---|---|
| `SecurityReadiness.Decide` | Consistency across types can grow branches | A list of named pure rules, one per pair of types |
| `FileCredentialProvider` | PEM, PKCS#8, OpenSSH, and CF limits | One small reader per format. Tests on real OpenSSL and `ssh-keygen` output |
| `WizardMachine` tables | 8 families | Data rows on one spine. One test per family walks every row |
| SSH signer | Ed25519 and RSA paths share `SshHostSigner` | Keep one class. It reads scheme from the handle's algorithm |

## 10. Open decisions

| # | Decision | Options | Pick | What would change my mind |
|---|---|---|---|---|
| O1 | **How a real key meets a glass engine (changes D5). Needs Steve** | A: operations-only handle in the engine. B: keep the wall, so real keys run only on OS transport. C: load real keys as `ITrainingKey` bytes | **A.** It is what a real server with an HSM does. B cannot show a real key at work in SSH, DUKPT, or tokens, because OS transport covers TLS only. C gives the engine the bytes it could then show | If Steve holds D5 as a hard wall, B stands and the course shows real keys for TLS metadata only |
| O2 | Real-world certificates in glass | A: Ed25519 only. B: add RSA signatures and RSA-PSS. C: also write P-256 ECDSA in C# 3 | **B.** About the size of the `Pkcs1` work, and a public-shape RSA chain works. ECDSA gives `KEY_ALGORITHM_NOT_IN_ENGINE` with OS transport as the route | If Steve wants a Let's Encrypt-style ECDSA certificate on glass, C becomes a slice |
| O3 | **Where items live. Confirm with Steve** | A: `<repo>/.security/`. B: `%LOCALAPPDATA%` | **A,** per his words, with the guard in 5.2. Cost: `git clean -xdf` deletes it, and each worktree has its own | If "within the project" meant the configuration model and not a folder, or if the repo goes public, B is better. The override makes that one line |
| O4 | Facade in or out of process | A: in-process class. B: separate process, as D13 does for DUKPT | **A.** 2.35 ms per call. `IVault` keeps the door open. The tour states the difference | A lesson that attacks a compromised Host would need B |
| O5 | Master key protection | A: plain file. B: DPAPI. C: seal and unseal | **A,** per Steve's "not super-secure". Anyone with both files reads every key, and the wizard says so | Any sign that a real production key will go in. Then B, and the design asks again |
| O6 | Showing long-term keys | A: always hide. B: always show. C: hide, with a per-item control on generated keys | **C.** Section 6.4 | Steve asks to show all |
| O7 | Axes | One or two | **Two.** Section 7 | Nothing I can foresee: OS transport cannot show secrets by design, so one axis would fail for keys either way |
| O8 | CSR flow for an outside CA | Now or later | **Later.** Its only customer is an outside CA, and most users of this course will not have one on hand | Steve has a CA he wants to use |
| O9 | Lessons 1 and 2 going Real | A: data keys from the vault. B: Mock only | **A, last.** Steve said every mode, and `GenerateDataKey` is an accurate pattern. It is also the first thing to cut | A deletion pass finds nobody uses it |
| O10 | PIN and PAN | Test values only, or free entry | **Test values only.** Section 1.6 | Steve asks, and Dave has read it |

## 11. Prior art and arithmetic

| Item | Finding |
|---|---|
| Catalog check | `E:\dev\MMP.Library\docs\system-design-catalog.md`: no vault or HSM entry. Took its "multi-step process with independent failure at each step" for the wizard, so each step names its own failure. Took the arithmetic habit. Rejected queues and caches |
| Style | Modular monolith plus lab node processes, unchanged. One new module, `NetSec.Vault` |
| Closest shape, keys | HashiCorp Vault transit: "encryption as a service", "doesn't store the data", versioned keys, sign and verify (page read this session). The page does not cover `exportable`, so that name is from recollection. AWS KMS `GenerateDataKey`: clear copy and encrypted copy (page read this session) |
| Closest shape, handle | PKCS#11 and a TLS server with an HSM key: the handshake stays in process, and one sign call crosses. From recollection |
| Closest shape, wizard | An XState-style machine that owns its moves (house rule, `1rMgw0Q5MgY`) |
| Where we differ | One learner, one machine, loopback. No network API, no tokens, no HA, no real tamper resistance. We show the audit log and the failure on purpose, since teaching is the job. Reasoning: those are what a learner must see, and the rest is operations |
| When this is wrong | A team sharing a vault, or a production key in the folder. Then use a real vault behind `ICredentialProvider` |

| Arithmetic | Value |
|---|---|
| Assumption | 1 learner, 20 lesson runs a day, 20 audit rows a run |
| Rate | Average well under 1 call per second. Measured ceiling: about 425 sign calls per second, with an audit row each (1000 in 2348 ms) |
| Added time per run | About 47 ms at 20 calls. A handshake's trace is read by a person, so this does not show |
| Key rows | 15 types, 5 versions, about 300 B each: about 22 KB |
| Audit growth | About 100 B per row (1011 rows in 106 KB). 400 rows a day is 40 KB a day, about 44 MB in 3 years. No pruning needed |
| Result | One SQLite file. No cache, no queue, no pool |

| Gems | Use |
|---|---|
| Used | `decide-at-authoritative-boundary` (readiness), `replaceable-seam` (provider), `plain-sentence-error-surface` (wizard errors), `paths-plain-at-the-boundary` (key files), `server-replaces-never-merges` (wizard step), `seeded-hash-linked-custody-chain` (audit) |
| Novel | None needed yet. A per-type mode seam may earn a gem after M3 |

## 12. Disposition

The design is ready for review. Next: Steve decides O1 and confirms O3. Echo takes the A16 edits from sections 3.4 and 7.1 and writes A17. Nancy takes sections 6.2, 7.1, and 8. After that, slice M0 can start.
