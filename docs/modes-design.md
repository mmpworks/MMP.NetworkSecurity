# MMP.NetworkSecurity: security modes design

Author: Richard. Date: 2026-11-05. Status: revised after Steve's decisions and Iolo's red team. No product code. Branch `docs/security-modes`. Companion: `docs/modes-real-world.md` (Jared, accuracy). Where the two differ, section 12 says which one governs.

## Conclusion

1. **The course holds 34 security items. 23 of them sit behind 15 types, and every one of the 15 can take a learner's own test key.** The other 11 items stay as they are. Section 1 lists all 34.
2. **Steve's O1: option C. Keys reach the engines as bytes, through a facade. The engines do not change, and A16's type clauses stay green.** `CredentialSet` implements `ITrainingKeySource`, so `GlassTransportFactory` keeps its one constructor.
3. **Sign-inside and refuse-export are taught in one separate vault exercise:** sign, derive, refuse, audit. A non-exportable key runs only there, and never in a glass engine.
4. **Five "make my set" flows, kept as data, cover the 15 types.** DUKPT and the passkey-shaped login stay available, and the screen says no outside tool can judge them.
5. **One app-wide Show keys toggle, default ON, for built-in and own keys alike.** Test id `show-keys-switch`. OFF puts fingerprints in place of key bytes at the Host's trace boundary.
6. **The UI says "My test key", never "Real".** The `SslStream` path is the "OS transport", and that button changes too.
7. **SQLite works as the vault.** The spike's output is in section 4.4.
8. **`A16.real-mode` cannot pass as written.** Windows `SslStream` fails on an Ed25519 peer, and `HostClauses.cs:175` makes one. Echo changes it to RSA. Slice V2 closes it, in its own PR.
9. **This round cuts** the OS store, PKCS#12, the data-key wizard, and RSA chains on glass. Section 9.3 names each cut and the door left open.

**The M Echo should expect: 259.** That is the 208 counted today plus 51 new clauses (section 9.2). Renames add none.

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

| # | Item | Lessons | Made today | Holder | Format | A learner's own? | Switch |
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

### 1.6 What stays built-in, and why

| Item | Why |
|---|---|
| #11 attacker key | An attacker's key has no real owner. Attack rows stay the same in both modes |
| #16 attack certificates | They need a CA that signs a bad certificate. They run only when `pki.root-ca` can sign. With a trust-only CA, rows `L4-expired-cert`, `L4-wrong-name`, and `L10-wrong-client-name` show as unavailable, with code `ATTACK_NEEDS_CA_KEY` |
| #28 to #33 | They exist for one run. A provisioned one would be wrong |
| #34 `lab-secret` | The timing lab needs a chosen 4-byte secret so the guess loop can finish (`Lesson11Timing.cs:31`). A learner's secret would have no such size |
| #25 PIN and PAN | These two stay test values, and Steve uses test data. Glass traces show the clear PIN field, and a real PAN or PIN there is cardholder data. PRD line 179 records a public data class. The wizard offers no field for them, and `--pan` refuses a number outside a short list of test numbers, with code `TEST_DATA_ONLY`. I would change this only if Steve asks for it and Dave has read it |

### 1.7 Labs and protocols against the types

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

`TrainingPki` stays on training keys in every mode. `Probe` and `SshProbe` stay on them unless a request sets `Credentials` (section 3.3), so `acceptance/` can grade a learner's key from outside.

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

Result: no certificate from a public CA runs in a glass engine today, and no RSA-signed or ECDSA chain runs there this round (decision O2).

Jared ran openssl-made chains through `ChainCheck.Run` on `dfe9510`:

| Chain | Result |
|---|---|
| Ed25519 root, Ed25519 leaf | Pass |
| Ed25519 root, RSA leaf | Pass. This is how `tls11.server` works today |
| Ed25519 root, intermediate, leaf, with the intermediate sent | Pass |
| RSA or P-256 root | `CERT_SIGNATURE: the signature on certificate 0 does not verify` |

The last row misleads: that name tells a learner the certificate was tampered with. So `ChainCheck` gains `CERT_SIGNATURE_ALG_UNSUPPORTED`, in slice V4, before a learner's key can reach it. Wizards generate Ed25519 CAs by default, for this reason.

## 2. Per-type mode

**Words.** The doc and the code say `BuiltIn` and `Mine`. The UI says "Built-in key" and "My test key". The UI never says "Real" (clause `A17.ui.no-word-real`). The inventory's "a real one is" column describes production, which this course never touches.

### 2.1 Resolution rules

| Question | Answer |
|---|---|
| Which option wins | One row per type in `modes.json`: `mode` and `binding`. There is no global switch. A flow sets all its types at once, and each type can then go back on its own |
| When is it chosen | At `session.start`. The Host builds an immutable `CredentialSet`, and a fork reuses its parent's set |
| Both exist | A type has one active binding. Older versions stay stored and unused |
| None exists | `BuiltIn` always exists. `Mine` with no binding is `Unconfigured` |
| Where is it visible | The security page, `session.started.security[]`, the session file's first line, and a chip beside TRAINING ONLY |
| Many accounts or projects | One learner, one machine: an explicit non-goal. Each worktree has its own `.security/` folder |

### 2.2 States

A `BuiltIn` type has no state to manage. `Broken` is computed at read time and is never stored.

| State | Means | Moves to |
|---|---|---|
| `Unconfigured` | `Mine`, with no binding | `Configured`, when a flow writes the binding |
| `Configured` | A binding exists, and its check has not passed for this version | `Verified`, when the check passes |
| `Verified` | The flow's check passed for this version. **This is the product's own word, and it never counts toward the kill condition** | `Broken`, or `Configured` when the version changes |
| `Broken` | Was verified, and now a file hash changed, a certificate expired, or a key is gone | `Configured` after a fix. The flow names the cause |

```csharp
public enum CredentialMode { BuiltIn, Mine }
public enum Readiness { Ready, Unconfigured, Configured, Broken }
public sealed class LabDecision { public readonly bool MayRun; public readonly TypeProblem[] Problems; }   // TypeProblem { TypeId, Code, Detail }
public static class SecurityReadiness {
    // Pure. Same input, same answer. A test calls it with no Host and no file.
    public static LabDecision Decide(string[] typesTheLabReads, SecurityTypeState[] states, DateTime now);
}
public static class LabCatalog { public static string[] Needs(int lesson); }   // Added beside Find. The table in 1.7 as data
```

### 2.3 What a lab does

| Case | Lab behaviour |
|---|---|
| All its types are `BuiltIn` | Runs as today. Byte-equal to the golden trace |
| A `Mine` type is `Verified` | Runs with that key |
| A `Mine` type is `Configured` | **Refuses** with `SECURITY_TYPE_NOT_PROVEN`, because an unchecked key can fail for an unnamed reason inside a lesson |
| A `Mine` type is `Unconfigured` or `Broken` | **Refuses** with `SECURITY_TYPE_NOT_READY`, naming each type and its flow |
| Types disagree | **Refuses** with `SECURITY_TYPES_DISAGREE`. Example: `tls13.server` is `Mine` and `tls.trust` is `BuiltIn`, so the chain cannot reach an anchor |
| An attack row needs what the item lacks | The row shows `available: false` with its code, and the lab itself runs |
| Show keys is OFF | Runs. The toggle does not change what the lab does |
| A binding names a non-exportable vault key | **Refuses** with `VAULT_EXPORT_REFUSED`. No flow makes such a binding, so this is a guard |

A lab never falls back to built-in keys in silence. The run would report success on the wrong key. Decision point: `session.start` (gem `decide-at-authoritative-boundary`).

### 2.4 Derived bindings

| Type | Default binding |
|---|---|
| `tls.trust` | The root of `pki.root-ca` |
| `ssh.known-hosts` | A prepared line from the matching host key. The flow offers no learn-on-first-connect, because lesson 9 step 3 says the pin was put on the device ahead of time (`modes-real-world.md` section 6) |
| `dukpt.pad` | Derived from `dukpt.bdk` with the lab's fixed key id. In lesson 9, this replaces the constant at `PinEnvelope.cs:83` |

The KSN ledger is per run today, so a fixed key id repeats a KSN across runs under one key. That is a lab shortcut, and the lesson 6 tour text says so. Same-seed forks stay comparable as a result.

### 2.5 Names are read-only

**Pick: the flows' names are read-only this round. `Credential` carries no name field.** This also removes Iolo's M0 failure: `Lesson10Auth.cs:57-59` holds constant subject, audience, and issuer, `:415` compares the audience, and a learner-chosen name would fail there.

| Name | Value | Source |
|---|---|---|
| Server name | `localhost` | `TrainingPki.cs:13` |
| Client name | `pump-reader-4` | `TrainingPki.cs:14` |
| Root name | `MMP.NetworkSecurity training root` | `TrainingCa.cs:14` |
| Token issuer, audience | `https://pump.training/issuer`, `https://pump.training/api` | `Lesson10Auth.cs:58-59` |
| SSH host | The lab's constant | `Lesson08Ssh.cs`, `HostName` |

The flow shows these names and says why they are fixed. An imported certificate must carry them, or it gets `CERT_NAME_MISSING`. This also stops a name from moving attack offsets (section 3.4). The door left open: add the fields to `Credential` when a lesson needs them.

## 3. Plugin seam

### 3.1 Signatures

All in `src/NetSec.Core/Keys`, C# 3, on both builds. Additive.

```csharp
public sealed class Credential {              // One security type, resolved. Immutable
    public readonly string TypeId, ProviderKind, Fingerprint;
    public readonly CredentialMode Mode;
    public readonly int Version;
    public readonly bool CanIssue;            // The CA key is here, so bad-certificate attack rows can run
    public readonly bool Imported;            // Drives the lab clock, section 3.4
    public readonly ITrainingKey Key;         // Null for a type with no private half
    public readonly byte[][] Chain, Anchors;  // DER, leaf first, intermediates included. Null means the lab issues as today
    public readonly string Lines;             // known_hosts or authorized_keys text
}
public sealed class CredentialBinding { public string TypeId, ProviderKind, Locator; public int Version; }
public interface ICredentialProvider {
    string Kind {get;}                        // "builtin", "file", "vault". A string, so a later provider adds no enum value
    CredentialCheck Check(CredentialBinding binding);   // Cheap. Reads no private key
    Credential Open(CredentialBinding binding);
}
public sealed class CredentialSet : ITrainingKeySource {   // What a lab holds. A snapshot
    public Credential Get(string typeId);     // A missing type throws SECURITY_TYPE_NOT_READY
    public ITrainingKey Find(string keyId);   // Routes each KeyIds value to its type. attacker-ed25519 always gives the built-in key
    public CredentialSummary[] Summary();     // Public facts only. Goes in session.started and the session file
    public static CredentialSet BuiltIn(ITrainingKeySource keys);
}
public static class SecurityTypes { public const string RootCa = "pki.root-ca"; /* and the other 14 */ }
public sealed class LabContext { /* existing fields */ public CredentialSet Credentials; }   // Null means CredentialSet.BuiltIn(new TrainingKeySource())
```

`ITrainingKey` now means "a test key this course may read". That is the same contract as D5's, on a key the learner made. `IKeyHandle` and `IKeyHandleSource` stay in `Keys.cs` as they are, with no implementer: they name a production key, and it still has no route into glass.

### 3.2 Providers

| Provider | Project, build | Handles | Refuses by name |
|---|---|---|---|
| `builtin` | Core, both builds. Wraps `TrainingKeySource` | All 15 types | Nothing |
| `file`: PEM, PKCS#8, OpenSSH, hex text | Core, `Pki/KeyFileReader`, C# 3, beside `OpenSshFile`. Reuses `Der` and `RsaPkcs8` | Ed25519, RSA 2048, a 16-byte test BDK | `KEY_FILE_ENCRYPTED`, `KEY_FILE_FORMAT`, `KEY_SIZE_NOT_2048` |
| `vault` | New `src/NetSec.Vault`, net10 only, Host references it | All key types | Section 4 |

Which code is net10 only: the vault, the flows, RSA key generation (BCL `RSA.Create(2048).ExportPkcs8PrivateKey()`), and the Host routes. Ed25519 generation uses `OsRandom` and Core's `Ed25519`.

### 3.3 What changes in the labs

| Site | Today | After |
|---|---|---|
| 12 `new TrainingKeySource()` sites in Labs | Per lab | `LabCredentials.Of(c)`, which returns the set |
| `Lesson01Aes.cs:64`, `Lesson02Seals.cs:58` | Drawn from `c.Random` | `BuiltIn` draws as today, so the golden holds. `Mine` takes the type's bytes |
| `Lesson10Auth.cs:193`, `:209` | Device seed drawn per run | `BuiltIn` as today. `Mine` takes the enrolled seed. The issuer row uses its public half |
| `Lesson09Bridge.cs:50` | Constants | `Mine` derives the pad key from the BDK, section 2.4 |
| `Tls13Lab.cs:149`, `Lesson07Tls11.cs:92`, `Lesson10Auth.cs:114` | Fixed lab date | `LabClock.For(credentials)`, section 3.4 |
| `SessionManager.cs:159` | No credentials | Sets `Credentials` |
| Engines, `Tls13Options.SigningSeed`, `SshHostSigner`, `Token.Issue`, `DukptBank`, `BankHsmCore`, `GlassTransportFactory` | | **No change** |
| `Probe.cs:169,176,197,200,210`, `SshProbe.cs:150,151,185` | `new TrainingKeySource()` | `r.Credentials`, when set. Null keeps training keys, so every existing clause runs as today |
| `TrainingPki`, `Node`, `CeDevice` | Training keys | No change. Node and CE on own keys are cut (section 9.3) |

**The suite's route to a glass server on a learner's key.** Without it, OpenSSL, Go, and `ssh.exe` have nothing to judge from `acceptance/`. The suite makes its own keys with OpenSSL or `ssh-keygen`, and tests the product as a black box:

```csharp
public sealed class ProbeRequest { /* existing fields */ public CredentialSet Credentials; }   // NetSec.Io. Null keeps training keys
public sealed class CredentialSet { /* section 3.1 */ public static CredentialSet FromFiles(string directory); }
```

`FromFiles` runs over the file provider, on both builds. A missing file leaves that one type built-in, so a clause can change one type and hold the rest. Labs never use this call: they get their set from `modes.json`, and section 2.3 still refuses there. A file it cannot read throws `NetSecException` with the section 8.5 code.

| File in the folder | Type | Note |
|---|---|---|
| `root.pem`, optional `root.key` | `pki.root-ca` | With the key, `CanIssue` is true |
| `anchors.pem`, else `root.pem` | `tls.trust` | |
| `srv.pem`, `srv.key` | `tls13.server` | `srv.pem` is leaf first, with any intermediates |
| `client.pem`, `client.key` | `tls13.client` | Same |
| `rsa.pem`, `rsa.key` | `tls11.server` | |
| `host.key` | `ssh.host-ed25519` | OpenSSH format |
| `rsa-host.key` | `ssh.host-rsa` | OpenSSH format |
| `known_hosts` | `ssh.known-hosts` | Else derived from the host key |
| `user.key`, `user.pub` | `ssh.client` | |
| `issuer.key` | `token.issuer` | |
| `device.key` | `device.enrolment` | |
| `bdk.hex` | `dukpt.bdk` | `dukpt.pad` follows it |
| `aes.hex`, `seal.hex` | `lab.aes-key`, `lab.seal-key` | |

The names match `TrainingPki.Export` wherever that method writes the same item.

Under option C, no engine needs an operations interface. `IKeyHandle` needs no RSA decrypt or derive call, because TLS 1.1 key transport and DUKPT run on bytes as they do today. The exercise calls `IVault` directly.

For a generated key, `new TrainingCa(credentials)` then issues as it does today, from the learner's CA key, with the same names and dates. So its layout matches the built-in one in every byte count.

### 3.4 Jared's traps

**The lab clock.** `Tls13Lab.cs:40` and `Lesson07Tls11.cs:29` fix 2030-01-01. `Lesson10Auth.cs:47` fixes 2026-11-05. A new 30-day certificate reads as expired at the first date, and as not yet valid at the second.

| Key origin | Rule |
|---|---|
| Generated by a flow | Valid 2025 to 2049, as `TrainingCa.cs:15-16`. Passes on the fixed clocks, so nothing changes |
| Imported certificate | `LabClock.For` returns the wall clock, read once at `session.start`, for certificate checks only. Attack certificates dated 2020 stay expired. Token times stay on `LabNow`, which is consistent inside lesson 10 |

**Fixed attack offsets.** A flip can land on the wrong field and still get the expected code, because the AEAD tag and the chain signature catch almost anything. So a row can pass for the wrong reason.

| Constant | Value | With a generated key | With an imported key |
|---|---|---|---|
| `Labs.cs:209` `SshEd25519SignatureOffset` | 130 | Holds: an Ed25519 blob is always 51 bytes | Holds |
| `Labs.cs:212` `SshProtectedBodyOffset` | 20 | Holds: no key in it | Holds |
| `Labs.cs:215` `SshRsaSignatureOffset` | 669 | Holds at RSA 2048 only | Holds, because other sizes are refused (`KEY_SIZE_NOT_2048`) |
| `Tls13Lab.cs:29` `CertSerialOffset` | 28 | Holds: same layout | **Moves** with DER length forms and issuer |
| `Tls13Lab.cs:31` `CertVerifySignatureOffset` | 8 | Holds | Holds: Ed25519 only |
| `Tls13Lab.cs:32` `VerifyDataOffset` | 4 | Holds | Holds |
| `Tls13Lab.cs:34` `RecordCipherOffset` | 8 | Holds | Holds |
| `Tls13Lab.cs:36` `ClientX25519ShareOffset` | 1284 | Holds, because the server name is read-only (section 2.5) | Holds, same reason |
| `Tls13Lab.cs:38` `ServerMlKemCiphertextOffset` | 68 | Holds | Holds |

Action: row `L4-flip-cert-byte` takes a named field (`TamperPlan.Field`, additive, read from `Fields`). All rows get `A17.attacks.hit-named-field`: the tamper records which field it hit, and the clause compares that as well as the code. Echo writes this clause so a wrong-reason pass fails.

**Same-seed pins.** A new key changes the signature bytes and the pinned digest. No clause compares a `Mine` run with a `BuiltIn` golden. Two `Mine` runs compare only under one key version, and the session file's first line names that version. A fork reuses the parent's set, so `atSeq` still holds.

### 3.5 Effect on D5, D6, and A16

| Item | Effect |
|---|---|
| D5 | **Stands.** New D15 beside it: "A learner's test key is an `ITrainingKey`, fetched as bytes through a provider." `IKeyHandle` still cannot reach glass |
| D6 | **Rewritten.** "The OS transport runs `SslStream`. It shows metadata only, because Schannel holds the secrets. A learner's key is a separate setting." The sentence "Real-key routes... do not exist" is retired |
| `A16.type.*`, both clauses | **Stay green, no edit.** No implementer in Core, no new constructor, nothing new on `TransportRequest` |
| `A16.real-mode.*` | Substance stays, wording changes. Section 7.1 |
| PRD A16 text, UX chip | Echo and Heather replace "Real mode" with "OS transport". "Never use it with real secrets" stays true |
| `acceptance/contract/` | Gains `CredentialSet` and `LabContext.Credentials` |

## 4. Vault facade

### 4.1 What it is

`src/NetSec.Vault`, net10.0, C# 14. It copies the behaviour of a vault. Its file and its process give no protection an HSM gives, and it says so on screen.

```csharp
public interface IVault {
    VaultKeyInfo CreateKey(string name, VaultKeyPolicy policy, string caller);   // Exportable and usage are set here, and are one-way
    int Generate(string name, string caller);                // Adds a version
    int Import(string name, byte[] material, string caller); // Adds a version. provenance = imported
    VaultKeyInfo Describe(string name);
    byte[] PublicKey(string name, int? version);
    byte[] Sign(string name, byte[] message, string caller);          // The exercise only
    byte[] Derive(string name, byte[] input, string caller);          // The exercise only
    byte[] Export(string name, string caller);               // How a lab gets an exportable key's bytes. VAULT_EXPORT_REFUSED for a non-exportable key. Audited with the caller
    AuditRow[] Audit(long afterSeq, int limit);
}
public sealed class VaultKeyPolicy { public string Algorithm; public bool Exportable; public string[] AllowedOps; }
```

Tables, as the spike ran them, plus `provenance` and `prev_hash`:

```sql
key_names(name PK, algorithm, exportable, allowed_ops, provenance, created_at)
key_versions(name, version, nonce, wrapped, public_key, fingerprint, state, created_at, PK(name, version))
audit(seq PK AUTOINCREMENT, at, caller, op, name, version, result, detail, prev_hash)
```

Wrapping: AES-256-GCM under a master key, with `name#version` as the additional data. `audit.prev_hash` links each row to the last (`GEM:seeded-hash-linked-custody-chain`), so an edited row shows. The UI does not call it tamper-proof. Each call writes its audit row before it returns, and a failed audit write refuses the call (Jared, from Vault's audit docs). A symmetric key shows a check value, by CMAC for AES, as AWS describes (`modes-real-world.md` section 4).

**The on-screen statement,** on the vault page: "Practice vault. Not an HSM. Not FIPS validated. Non-export here is a rule in our code. Anyone can open the SQLite file and read the wrapped key."

### 4.2 How far it goes for accuracy

| Behaviour | Real vault or HSM | Facade |
|---|---|---|
| Named keys and versions | Yes | Yes |
| Exportable set once, one way | Yes | Yes |
| Fixed usage | Yes | Yes. A signing key refuses `Derive` with `VAULT_OP_REFUSED` |
| Audit, including refusals | Yes | Yes |
| Wrapped at rest | Yes | Yes |
| Sign and derive inside | Yes | **In the exercise only** |
| Export | An exportable key can leave. A non-exportable one cannot | **The same.** Flows make exportable keys, and labs read them by `Export`. Only the exercise's keys are non-exportable |
| Sealing, roles, wrapped-only import, scheduled deletion | Yes | **Cut this round.** Jared's table lists them, and section 9.3 leaves the door open |
| Tamper-resistant hardware, FIPS, a separate process | Yes | No |

### 4.3 The vault exercise, the one place operations are taught

Three screens, opened from the vault page, on narrow Host routes. It is not a lab: a lab cannot take typed input (`ILab.Run` has only its context), and the learner types here. So it needs no tour file and no trace stream. It changes no mode and no key a lesson uses.

| Step | Route | What the learner sees |
|---|---|---|
| 1 Sign | `POST /api/security/vault/exercise/sign` `{ text }` | A key that never left the box signs the typed text. The Host runs `openssl pkeyutl -verify` against the public key, and the command and its output show |
| 2 Derive | `POST /api/security/vault/exercise/derive` `{ label }` | A new key comes from a key that stays in the box: HKDF-SHA256 over the typed label. This is the idea behind a DUKPT base key. It is not DUKPT, because a typed label stands in for a KSN, and the screen says so |
| 3 Refuse | `POST /api/security/vault/exercise/export` | Asks for the key, and the box says `VAULT_EXPORT_REFUSED` |
| 4 Audit | `GET /api/security/vault/audit`, `POST /api/security/vault/exercise/audit-check` | All the calls, with the refusal. The check walks the `prev_hash` chain and says whether a row changed |

Responses are data, so a clause can judge them from outside. Sign returns `{ keyName, version, inputHex, signatureHex, publicKeyHex, command, output, code }`. Derive returns `{ keyName, version, label, outputHex, code }`. Export returns HTTP 409 with `code: VAULT_EXPORT_REFUSED`. Audit-check returns `{ rows, firstBadSeq, code }`. `GET /api/security/vault/keys` lists both exercise keys with `fingerprint` and `hidden: "non-exportable"`. `session.start` with lesson 20 gives `LESSON_NOT_BUILT`, because no such lab exists.

It makes its own keys, `exercise/signing` and `exercise/derive`, non-exportable, so it needs no flow first. A signing key refuses `Derive`, so there are two. `Export` refuses both, so nothing has a route to their bytes. **These are the only non-exportable keys in the course, and no glass engine runs on them.**

### 4.4 Package and spike

| Fact | Value |
|---|---|
| Package | `Microsoft.Data.Sqlite.Core` 10.0.9 with `SQLitePCLRaw.bundle_e_sqlite3` 3.0.3 |
| In the NuGet cache | Yes, both, with `SourceGear.sqlite3` 3.50.4.5 |
| Rejected | `Microsoft.Data.Sqlite` 10.0.9. It pulls `SQLitePCLRaw.lib.e_sqlite3` 2.1.11: NU1903, GHSA-2m69-gcr7-jv3q, high, SQLite before 3.50.2. `Directory.Build.props:5` sets `TreatWarningsAsErrors`, so a repo build would fail |
| Native file | `runtimes/win-x64/native/e_sqlite3.dll`, in the build output, never in git. `THIRD-PARTY-NOTICES.md` gains a section. Licences not read yet: slice V1 reads them |

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

Limits of the spike: its vault is one process. The raw 36-byte test tried one hash name. The OS store was not touched. Those two matter only for the cut provider.

## 5. Where things live

### 5.1 Folders

**O3 stands as the default: a gitignored `.security/` inside the project.** `NETSEC_SECURITY_DIR` overrides it, and `acceptance/` sets that to a temp folder. The Host finds the default by the walk up from `AppContext.BaseDirectory` that `Program.cs:114` already uses.

```
<repo>/.security/                  gitignored as a whole
  README.txt                       What this folder is. Written by the Host
  modes.json                       Mode, binding, check result per type, showKeys. No secret
  vault/vault.db, -wal, -shm       Section 4
  vault/master.key                 32 random bytes
  files/<typeId>/v<N>/             Copies of imported files, plus chain.pem
  ssh/known_hosts                  Written when the pin is not derived
  ssh/authorized_keys
  runs/<runId>.json                A flow's state, for resume. No secret
  proof/<flowId>/                  Check scratch. Deleted when the check ends. ssh.exe needs its key file locked to one reader, so the flow sets that
```

Session files stay in `%LOCALAPPDATA%\MMP.NetworkSecurity\sessions\` (`Program.cs:26`). A flow copies an imported file into `files/`, so a moved original cannot break a verified type. The stored hash feeds `Broken`. A flow writes generated keys only under `.security/`, and never to a default such as `~/.ssh`, where it could overwrite a daily key.

**The `~/.ssh` warning.** An import path under `%USERPROFILE%\.ssh` gets a warning step, `KEY_PATH_PERSONAL`: "This looks like a key you use every day. This course shows every key. Use a test key." The learner can go on, because Steve's rule is a stated rule and not a hard stop.

`.gitignore` gains `.security/`, `*.pfx`, `*.p12`, and `*.db`.

### 5.2 The check that a key is never committed

**One enforcement: an acceptance clause that runs a script, `A17.repo.no-key-tracked`.** A git hook would not travel with a clone and can be skipped. A clause cannot. `tools/gate.ps1` calls the same script on every slice.

`tools/secret_guard.py` runs over `git ls-files` plus the staged set, and fails on:

| Rule | Detail |
|---|---|
| Path | Anything under `.security/`, or any `.pfx`, `.p12`, `.db`, `.key`, `.ndjson`, `master.key`, `id_rsa`, `id_ed25519`, `known_hosts`. A session file can hold keys. `git ls-files` finds none of these today |
| PEM block | A private key block, meaning the header line, a base64 body, and the footer, in a file outside the allow-list (`acceptance/CONTRACT.md` 5.5). A sentence that only names the header is no key, and these docs do that. The allow-list today is 3 files: `src/NetSec.Core/Pki/TrainingPki.cs`, `tests/NetSec.Tests/Tls13Tests.cs`, `acceptance/lib/Harness/OpenSshKey.cs` |
| Ignore rule | `.gitignore` must hold the `.security/` line, and `git check-ignore .security/x` must agree |

The clause runs beside a control: on a temp clone, a planted PEM file and a planted `.security/` file must each fail by name, and the unchanged tree must pass.

## 6. Trace and display

**Decision: one app-wide "Show keys" toggle, default ON.** It works the same for built-in keys and own keys. ON shows every key the provider can export, long-term and session, on screen and in session files. OFF replaces key bytes with a fingerprint on screen, in saved files, and in exports. The Host applies it at its trace boundary. Test id: `show-keys-switch`.

### 6.1 Steve's rulings

| Ruling | Effect |
|---|---|
| "I only ever use test keys... This is training." | Own keys show as built-in keys do. The gitignore and the no-commit check stay |
| "We should make the showing of keys optional. a toggle switch." | One toggle, independent of mode, default ON because the course teaches by showing keys |

### 6.2 What the toggle does

| Surface | ON (default) | OFF |
|---|---|---|
| Live frames, `/api/sessions/{id}/events` | `secrets[].hex` present | No `hex`. `fingerprint`, `length`, and `hidden` instead |
| New session file | Bytes written | Fingerprints written |
| `session.save` | Returns the session file | If the file holds any shown line, writes a redacted copy and returns that path |
| `session.load` replay | As the file holds it | Any bytes in the file become fingerprints before they reach a frame |
| `/api/sessions/{id}/keylog` | As today | Refused with `KEYS_HIDDEN` |
| OS transport session | No secrets, by A16 | No secrets, by A16 |
| Security page, `GET /api/security/types/{typeId}/key` | Key hex, for a key that can show | Fingerprint. No bytes |

Limits, stated:

1. Files written while ON stay on disk with their bytes. OFF does not rewrite them. The file itself is still readable in `%LOCALAPPDATA%`.
2. OFF hides `secrets[]`. It does not touch `wire` or `plain`. The bearer token in lesson 10 still shows, because that lab sends it in the clear on purpose. The secret `auth.last-call` carries that token with the DPoP proof of each call. The challenge nonce and its signature are public protocol values, so lesson 10 does not list them as secrets. `keys.installed` carries no bytes (`Interpreter.cs:204-208`).
3. Lesson 11 stores the guessed bytes in `plain` (`TimingReport.cs:71`), since the attack result is the lesson. A 4-byte `lab-secret` also falls to a brute-force search of its fingerprint.
4. OFF is a setting for a shared screen or a shared trace. It is not a security boundary. The Host still holds the bytes in memory.

### 6.3 Showing every key

Today's traces show few long-term keys, built-in ones too. Only `Lesson06Dukpt.cs:138,205,206` and `Lesson10Auth.cs:250` emit one. No TLS, SSH, CA, or token private key is ever in a trace. So "every key" needs one addition.

**Event `key.in-use`.** At `session.start`, for each type the lab reads (`LabCatalog.Needs`), the Host writes one event on its own stream, `<sessionId>/keys`, in both modes: holder, type, version, provider, and the key's bytes as a normal `secrets[]` entry.

| Property | Why |
|---|---|
| Written by the Host | It adds nothing to an engine stream, so `streamSeq`, tamper addresses, `atSeq` forks, and the golden traces stay as they are |
| Skips the step gate | A tour gains no step |
| Bytes come from `Credential.Key.CopyMaterial()` | The Host holds the same set the lab holds. For a vault key, opening the set called `Export(name, "host/lab-<n>")` |
| Audit rows on every session start | Each lab start writes one export row per vault key it reads, with the toggle ON or OFF. That is accurate: an exportable key left the box. The audit list shows the caller name, so the row does not read as an attack |

**One exception, on accuracy: a non-exportable key shows only its fingerprint, even with the toggle ON.** Such a key runs only in the vault exercise (section 4.3), so no lab holds its bytes, and the Host has none to hide. The exercise's routes and the vault page carry the public fingerprint with `hidden: "non-exportable"`, and `GET /api/security/types/{typeId}/key` has no bytes to give. Beside it the UI shows this line, word for word:

> The course refuses to show it. A real HSM would refuse too. These files could still open it here.

**Flows generate exportable keys, with no other choice this round,** so every key a lab uses can show. The refusal is taught once, in the exercise.

### 6.4 The boundary

One pure function in Core and one line at each exit in the Host. Rules, engines, and labs never read the toggle. A fork still runs on the real bytes.

```csharp
public sealed class TraceSecret { /* existing */ public string Fingerprint; public int Length; public string Hidden; }   // Hidden: null, "toggle", "non-exportable"
public static class TraceRedaction {            // NetSec.Trace, C# 3. Same input, same output
    public static string Fingerprint(byte[] secret);      // "fp:" and the first 8 bytes of SHA-256, as hex
    public static TraceEvent Hide(TraceEvent e);          // A new event. Each secret loses Bytes and gains the three fields. All else is the same
}
```

| Exit | Today | Change |
|---|---|---|
| `SessionManager.cs:43` `LabSession.Write` | One line to store, file, and broadcast | Makes two lines, shown and hidden. `StoredEvent` holds both. File and broadcast take the one the toggle names at that moment |
| `SessionManager.cs:55` `After` | Stored line | Picks by the toggle now |
| `Program.cs:275` `session.load` | File line to frame | `HideLine(string)` in the Host, on the JSON, when OFF |
| `Program.cs:259` `session.save` | Returns the path | Section 6.2 |
| `Program.cs:57` key log | Empty text | `KEYS_HIDDEN` when OFF |

**Flipping it during a session.** The Host stores the value, broadcasts `security.show-keys {on}`, and the UI replaces its copy of each open session from `/events` (gem `server-replaces-never-merges`). So OFF clears bytes from the screen at once, and ON brings them back for the 20 sessions held in memory. A session file holds each line as the toggle stood when the line was written.

**Stored:** `showKeys` in `.security/modes.json`. A missing file or field means ON.

**Outside the Host:** `NetSec.Node` and `NetSec.CeDevice` write `--trace-file` directly, and the Host starts neither one with a trace file today. Those files are a test tool, and they always hold bytes.

### 6.5 Lessons that need the bytes

Every lesson runs with the toggle OFF. Each one loses the bytes and keeps the comparison. A fingerprint has one job: same fingerprint, same key.

| Lesson | On screen when OFF | Still teaches |
|---|---|---|
| 1 AES | `aes.key` as a fingerprint. The picture lab uses `wire` and `plain` | ECB leak, nonce reuse, tag failure |
| 2 Seals | `seal.key` as a fingerprint. Tags are on the wire | All tamper rows |
| 3 Key agreement, **"two sides, one key"** | **The grids show fingerprint cells.** Lines tie the two sides when the fingerprints match. The swap attack shows them differ | The two sides reach one secret |
| 4, 5 TLS 1.3 | The key ladder shows a fingerprint per rung. `derivedFrom` chips stay | What derives from what |
| 6 DUKPT | One fingerprint per sale. Held counts come from `HeldCount` | A new key per sale, and erased keys |
| 7, 8, 9 | Session keys as fingerprints | All checks |
| 10 Auth | Device key as a fingerprint. The token stays visible on the wire | All rows |
| 11 Timing | `lab-secret` as a fingerprint | Whole lesson |

**Nancy, a trap.** `SecretsPanel.vue:36` decides a match with `v.every(r => r.hex === v[0].hex)`. With `hex` empty that is always true, so two different keys would show as a match. The compare must use the fingerprint when `hidden` is set. `:70` counts bytes from `hex`, and must read `length`. `:73` copy has nothing to copy. `:81` and `lab.ts:107` draw from `hex`. `host.ts:48` must carry the three new fields.

**Tours and the toggle.** No tour branches on it. Tour bindings match `type`, `actor`, `message`, and `step` (design section 5), so A14 holds. While OFF, one banner under the top bar (`show-keys-off-banner`) shows in tour mode and in free play: "Show keys is off, so you see a short fingerprint of each key. Two keys with the same fingerprint are the same key."

### 6.6 Replay and the suite

**The suite runs with the toggle ON.** The clauses named `A17.show-keys.*` turn it OFF on purpose, each in its own Host.

| Case | Result |
|---|---|
| Saved ON, replayed OFF | Fingerprints |
| Saved OFF, replayed ON | Fingerprints. The bytes are gone from that file, and the banner says so |
| `A6.keylog.*` | **Not affected, and the suite runs it ON anyway.** It reads `ProbeResult.KeyLog` in process (`Tls13LiveClauses.cs:72-77`), and that never crosses the Host. The Host's own key log route is the one OFF refuses |
| A4, A10, A10a | Not affected. A4 calls `Tls13KeySchedule`. A10 and A10a read `--trace-file` from Node and CE (`TraceLine.cs:43`) |
| `tests/NetSec.Tests` | Not affected. They run a lab into a `ListSink`, with no Host |
| `A16.real-mode` | **Needs ON.** Its key log check at `HostClauses.cs:195` wants success. Note for Echo: the control at `:193` counts `secrets[]` entries, so it would pass on hidden entries too. It should require `hex` |
| A13 walks, `tests/NetSec.Host.Tests` | **Run with ON,** because they were written against shown values |

**How a test run gets ON.** `run.ps1` sets `NETSEC_SECURITY_DIR` to a temp folder, so `modes.json` is absent and the toggle is ON. `/api/health` gains `showKeys`, and the suite fails a run early with `SUITE_NEEDS_SHOW_KEYS_ON` if it reads false. There is no env flag for the toggle, since a second control for one decision would let a run differ from the app.

## 7. Relationship to the unbuilt OS transport

**Two axes, and "Real" names neither.** Transport asks whose code speaks the protocol. Keys ask whose key is in use.

| | All built-in keys | Some "My test key" |
|---|---|---|
| **Transport: glass** | Today. 207 of 208 pass | New. Keys show or hide by the toggle |
| **Transport: OS** (`SslStream`) | Needs a non-Ed25519 peer certificate. The spike: Schannel fails on Ed25519. Metadata only | Lesson 5, with `tls.trust` as the custom trust store. RSA peer certificate. Metadata only |

The dropdown from PR #98, `ui.target` (`store.ts:41-48`), is a third axis. It stays independent, and the CE rows stay disabled.

### 7.1 What the OS transport needs

**This is slice V2, in its own PR.** It closes the one failed clause with no dependence on the key work.

| Item | Detail | Owner |
|---|---|---|
| `OsTransportFactory` | Unbuilt. `Program.cs:203` answers `REAL_MODE_NOT_BUILT`, which becomes `OS_TRANSPORT_NOT_BUILT` | Builder |
| Lab route | `Tls13Lab.cs:78` builds both engines directly, and no lab reads `LabContext.Transports`. So lesson 5 on the OS transport needs its own lab path, one client and a peer from the env | Builder |
| Clause peer key | `HostClauses.cs:175` makes an Ed25519 key. `SslStream` fails on it, and RSA passes on the same probe. Change to `-algorithm rsa -pkeyopt rsa_keygen_bits:2048` | **Echo** |
| Clause trust | `HostClauses.cs:186` sets `SSL_CERT_FILE`. From recollection, Schannel does not read it. The product reads that variable and loads a `CustomTrustStore`. This needs a line in `CONTRACT.md` | Echo, builder |
| Clause wording | `A16.real-mode.*` becomes `A16.os-transport.*`, `transport: real` becomes `transport: os` (`store.ts:288`, `HostClauses.cs:197`), `NETSEC_REAL_PEER` becomes `NETSEC_OS_PEER`. The count stays the same | **Echo** |
| Chip bug | `store.ts:100` and `:206` test `'real'`. The clause wants `os`. Change both | Nancy |
| **Button text** | **The rename from "Real" touches this button.** `App.vue:143` says "Real mode", and it becomes "OS transport". `transport-switch` stays as the test id | Nancy |
| D6, PRD A16 text | Section 3.5 | Lead, Heather |

### 7.2 Open PRs

**#90 and #91 merge before V0.** Echo records golden traces from the final gate code, and #90 changes `StepGate`. #91 depends on #90 and touches `app/src/store.ts`.

## 8. Wizard contract

UI choices belong to Nancy. This section is data only. Words live in `app/src/wizard-copy.json`, keyed by `copyId`, as `field-gloss.json` does for fields. So `tools/tour_lint.py` can hold them to grade 8.9, the tic gate can scan them, and a reader can check claims under A15a. Cussler humanizes that file. **The copy assumes no knowledge:** each step says what this thing is, why it exists, what you do now, and what breaks if it is wrong.

### 8.1 Five flows, as data

`src/NetSec.Host/wizard-flows.json` holds the flows. `WizardMachine` reads rows. Adding or moving a type is a data edit.

| Flow id | UI name | Types | Count | Who judges |
|---|---|---|---|---|
| `my-certificates` | My certificates | `pki.root-ca`, `tls.trust`, `tls13.server`, `tls13.client`, `tls11.server` | 5 | OpenSSL. **Checked against the root you gave it** |
| `my-ssh` | My SSH keys | `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.known-hosts`, `ssh.client` | 4 | `ssh.exe` |
| `my-payment` | My payment keys | `dukpt.bdk`, `dukpt.pad` | 2 | **No outside tool.** Our code matches the published X9 vectors |
| `my-login` | My login keys | `token.issuer`, `device.enrolment` | 2 | OpenSSL, for the token's signature only. **No outside tool for the passkey-shaped login** |
| `my-lesson-keys` | Keys for lessons 1 and 2 | `lab.aes-key`, `lab.seal-key` | 2 | OpenSSL |

Total: 15 of 15. No type is dropped.

`my-lesson-keys` is one screen that makes or takes bytes. It is not the cut data-key wizard: it has no `GenerateDataKey` and no wrapping key.

### 8.2 The spine

Every flow runs these states. The default path is five screens, and "Use my own files" adds one branch screen. `my-lesson-keys` has no branch.

| State | Kind | Content |
|---|---|---|
| `Intro` | `explain` | What this set is. The test-keys line |
| `Make` | `choose` | Lists each part. "Make it for me" (default) generates all parts and places them. A link opens `PickFiles` |
| `PickFiles` | `file` | One row per type. Checks each file, then places them. A path under `~/.ssh` gets the `KEY_PATH_PERSONAL` warning first |
| `Review` | `review` | Every type: names (read-only), dates (fixed), algorithm, fingerprint. `back` goes to `Make` and makes a new version |
| `Check` | `prove` | Section 8.6 |
| `Done` | `done` | Each part's result, and which lessons now use these keys |

Placing writes a new version of each type and keeps the old one, so a failed check loses nothing. A flow has one decision on its default path. It offers no choice of name, key kind, or dates: sections 2.5 and 3.4 say why, and `Review` says "A real system uses about 90 days. This lab's clock is fixed, so these dates stay."

**Resume.** A run's state stays in `.security/runs/<runId>.json`, with no secret in it, so a learner who quits comes back to the same step.
**The test-keys line,** copy id `wizard.common.test-keys-only`, on every `Intro` and on the security page:

> Use test keys only. This course shows your keys on screen and in saved files.

Nothing can detect a production key, and imports stay open for vendor test keys. So this line is the control, with the `~/.ssh` warning beside it.

### 8.3 Routes

All routes sit behind `HostGuard`, per D14. Errors carry `code`, `message`, `retryable`, `requestId`, the shape at `Program.cs:51`.

| Route | Returns or does |
|---|---|
| `GET /api/security` | `{ schema, root, showKeys, flows: [{ flowId, openRunId }], types: [{ typeId, flowId, titleId, mode, state, providerKind, version, fingerprint, notAfter, usedBy[], followsType, problem }] }` |
| `PUT /api/security/types/{typeId}/mode` `{ mode }` | Sets the mode. Going to `BuiltIn` always works, and the binding stays for later |
| `POST /api/security/flows/{flowId}/runs` | `{ runId, step }` |
| `GET /api/security/runs/{id}` | `{ step }`. The UI replaces its copy (gem `server-replaces-never-merges`) |
| `POST /api/security/runs/{id}/events` `{ event, stepSeq, data }` | `{ step }`, with `errors[]` when a check refuses |
| `GET /api/security/readiness?lesson=N` | `{ mayRun, problems[] }`, from `SecurityReadiness.Decide` |
| `GET /api/security/types/{typeId}/key` | Section 6.2. A vault read writes an audit row |
| `GET /api/security/vault/keys`, `GET /api/security/vault/audit?after=N` | Names, versions, policy, provenance. Audit rows |
| `POST /api/security/vault/exercise/{sign,derive,export,audit-check}` | Section 4.3. The exercise's keys only |
| `GET`, `PUT /api/security/show-keys` `{ on }` | The toggle. A set broadcasts `security.show-keys {on}`. `/api/health` also reports it. UI test id `show-keys-switch` |
| `GET /api/lessons` | Existing. `attacks[]` gains `available` and `whyNot` |
| WebSocket `session.started` | Existing. Gains `security[]` and `showKeys` |

A key file moves by **path**, chosen in Electron's file dialog, and the Host reads it (gem `paths-plain-at-the-boundary`). No flow has a field for typing a secret. The `my-payment` branch is a file row like every other flow's: a text file holding one test BDK as 32 hex characters. Beside it is one optional field for the vendor's check value, which is not a secret. If the learner fills it and it differs, the step gives `DUKPT_KCV_MISMATCH`.

### 8.4 Step payload and the machine

```json
{ "runId": "r1", "flowId": "my-certificates", "state": "ReadBack", "stepSeq": 4, "stepIndex": 3, "stepCount": 6,
  "kind": "review", "copyId": "wizard.my-certificates.read-back",
  "facts": [{ "typeId": "tls13.server", "name": "localhost", "notAfter": "2049-12-31", "algorithm": "Ed25519", "fingerprint": "SHA256:..." }],
  "fields": [], "choices": [], "allowed": ["next", "back", "cancel"], "errors": [], "warnings": [] }
```

`allowed` comes from the table, so the UI cannot offer a move the machine refuses. `errors[]` stop the step. `warnings[]` let the learner go on, and the Host decides both. `WizardMachine.Decide` is pure, and the Host applies its effects. An event with no row from the current state gets `WIZARD_EVENT_NOT_ALLOWED`, naming both, as `UNEXPECTED_MESSAGE` does in the engines. A stale `stepSeq` gets `WIZARD_STEP_STALE`.

```csharp
public sealed record WizardRow(string From, string Event, string Guard, string To, string[] Effects);   // Loaded from wizard-flows.json. Guard and effects are named, and a test fails on an unknown name
public static class WizardMachine { public static WizardDecision Decide(WizardTable table, WizardState state, WizardEvent e, WizardFacts facts); }
```

### 8.5 Named errors

| Code | Means |
|---|---|
| `KEY_FILE_UNREADABLE`, `KEY_FILE_FORMAT`, `KEY_FILE_ENCRYPTED` | Cannot read it. The copy says how to remove the passphrase on a test key |
| `KEY_PATH_PERSONAL` | A warning, not a refusal. Section 5.1 |
| `KEY_ALGORITHM_NOT_IN_ENGINE`, `KEY_SIZE_NOT_2048` | Example: ECDSA, or RSA 4096. Names what the engine takes |
| `KEY_CERT_MISMATCH` | Certificate and key are not a pair |
| `CERT_EXPIRED`, `CERT_NOT_YET_VALID` | Dates, on the wall clock |
| `CERT_NAME_MISSING`, `CERT_USAGE_WRONG`, `CERT_NOT_A_CA` | Names the fixed name, EKU, or basic constraints |
| `CHAIN_INCOMPLETE` | A leaf under an issuing CA must come with its intermediate, for a client too. Jared ran it: Go refused a leaf-only mutual TLS client, and passed with `-cert_chain` |
| `CERT_SIGNATURE_ALG_UNSUPPORTED` | **Engine and flow code.** An RSA or P-256 root. Today it reads `CERT_SIGNATURE`, which says tampering. Names the OS transport as the route |
| `KNOWN_HOSTS_LINE_BAD` | The line does not parse. Wildcards refused, as `SshKnownHosts` does |
| `DUKPT_KEY_SIZE`, `DUKPT_KCV_MISMATCH` | A test BDK must be 16 bytes this round, since lessons use AES-128. The file's key does not match the check value the learner gave |
| `VAULT_KEY_UNKNOWN`, `VAULT_OP_REFUSED`, `VAULT_EXPORT_REFUSED`, `VAULT_UNWRAP_FAILED`, `VAULT_AUDIT_FAILED` | Section 4. The last one is the refusal when an audit row cannot be written. Jared's doc calls the refusal `KEY_NOT_EXPORTABLE`. The spike printed `VAULT_EXPORT_REFUSED`, and that name stands |
| `KEYS_HIDDEN` | The key log was asked for with Show keys OFF |
| `REFEREE_MISSING`, `CHECK_FAILED` | Tool absent, or it said no, with its output attached |
| `WIZARD_EVENT_NOT_ALLOWED`, `WIZARD_STEP_STALE`, `WIZARD_RUN_NOT_FOUND` | Machine |

Each branch ends in one sentence on what happened and what to do, with detail to the log (gem `plain-sentence-error-surface`).

### 8.6 The check

`Check` runs a tool against the item, and shows the command, its output, and who judged it. **A pass says "Checked against the root you gave it", never "trusted".** A local root is trusted only by what was told to trust it.

**No self-verify.** `openssl verify -CAfile root.pem root.pem` cannot fail, so it is no check. Each row below has a way to fail, and the root row runs a negative control.

**On a `Check` step, each row of `facts[]` carries** `typeId`, `judge`, `says`, `command`, `output`, `passed`. `judge` is `openssl`, `ssh.exe`, or `none`, and it belongs to the type. `says` is a stable id, and the copy file holds its words: `checked-against-root`, `checked-with-openssl`, `checked-signature-only`, `checked-with-ssh-exe`, `no-outside-judge`. A lab may run on a type with `judge: none`: the state is `Verified`, and the UI chip reads `Saved, no outside check`, in the flow and in the lab. Refusing would mean the payment and passkey keys could never run, and Steve said they stay available.

A vault-made `ssh.client` keeps `ssh.exe` as its judge. Under option C every flow key is exportable, so `Check` exports a copy to `proof/`, locks it to one reader, and deletes it after.

| Type | Command | Judge | Screen says |
|---|---|---|---|
| `pki.root-ca` | Issue a test leaf. `openssl verify -x509_strict -CAfile root.pem leaf.pem` passes. **Then the same leaf against a different throwaway root must fail** | OpenSSL | Checked against the root you gave it |
| `tls.trust` | `openssl verify -CAfile <anchors> -verify_hostname localhost <active leaf>` | OpenSSL | Same |
| `tls13.server` | `openssl s_client -tls1_3 -CAfile <anchors> -verify_return_error -verify_hostname localhost` against a glass server with this key | OpenSSL | Same |
| `tls13.client` | `openssl s_server -tls1_3 -Verify 1 -verify_return_error -CAfile <anchors>` against the glass client, with intermediates sent | OpenSSL | Same |
| `tls11.server` | `openssl s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile <anchors>` against the glass server. SECLEVEL=0 is not a normal setting, and the screen says so | OpenSSL | Same |
| `ssh.host-*`, `ssh.known-hosts` | `ssh.exe -F NUL -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=<pin>` runs `echo hello` on the glass server | `ssh.exe` | Checked with `ssh.exe` |
| `ssh.client` | Same run, `-i <key>` | `ssh.exe` | Checked with `ssh.exe` |
| `token.issuer` | `openssl pkeyutl -verify -pubin -rawin -inkey <issuer.pub> -in <signing input> -sigfile <signature>` on a fresh token. Then the same input with one changed byte must fail. The spike ran this form | OpenSSL | **"Checked with OpenSSL. This checks the signature only."** Clauses A11 and `A17.referee.token-issuer-go` judge the rest from `acceptance/` |
| `device.enrolment` | Our own check of a challenge answer | **None** | **"No outside tool can judge this. Our own check passed."** |
| `dukpt.bdk`, `dukpt.pad` | Our derive code on the published X9 test BDK gives the published vector, then a PIN-pad to bank round trip under this key | **None live** | **"No outside tool can judge this. Our code matches the published vectors."** |
| `lab.aes-key`, `lab.seal-key` | `openssl mac -digest SHA256 -macopt hexkey:<hex> HMAC`, and `openssl mac -cipher AES-128-CBC ... CMAC`, against Core's tags. `lab.aes-key` also: `openssl enc -aes-128-ecb -nopad -K` on one block against `Modes` | OpenSSL | Checked with OpenSSL |

Not run yet: `-x509_strict` against a chain from `TrainingCa`, since Jared ran it on openssl-made chains. If `TrainingCa`'s leaf lacks a field that mode wants, V4 drops the flag and says so.

Tools: `openssl` and `ssh.exe` at the pinned paths in design section 9, overridable by `NETSEC_OPENSSL` and `NETSEC_SSH`. `/api/health` `referees` is empty today (`Program.cs:45`), and it should report these two. The product does not call `acceptance/referees/go`, because the Host must not depend on the suite's folder (D11). **The clauses judge from `acceptance/`, on their own. A product check is a help to the learner, and it is no evidence for the plan.**

### 8.7 Tour text bound to the key

Some tour sentences go false on a learner's key (`modes-real-world.md` section 6). A step gains an optional `textMine`, chosen by `session.started.security[]`, and A15 and A15a cover it.

| Step | Today says | Fix |
|---|---|---|
| Lesson 4 step 1 | "a training CA made for this course" | `textMine` |
| Lesson 4 step 4 | "the chain has two cards" | Read the length from the trace |
| Lesson 6 step 12 | "anyone can read the base key in the source" | `textMine` |
| Lesson 9 steps 1, 2, 11 | Training keys public on purpose | `textMine` |
| Lesson 10 step 6 | "issued under the same training root" | `textMine` |

Lesson 6 also gains a line for all modes: a real HSM shows only a key id and a check value.

## 9. Slices and clauses

### 9.1 Slices

Each slice is vertical and merges to a running `main`. Builders never write `acceptance/`. Agents use canary test keys only.

| Slice | Delivers | Closes on |
|---|---|---|
| **Pre** | #90 and #91 merged. **Echo records golden traces in `acceptance/`, first, from that main. No builder records them.** Echo writes A17 and the A16 wording edits. D15 and D6 in the PRD | `run.ps1 -Contract` compiles. A rerun of Echo's recorder matches, twice |
| **V0 skeleton, one type** | `Credential`, `CredentialSet`, `builtin` and `file` providers, `SecurityReadiness`, `modes.json`, routes, `WizardMachine`, `wizard-flows.json`, one security page, `secret_guard.py`. **`token.issuer` end to end**, `my-login` with one type | Golden equal. Lesson 10 runs on a canary issuer with the fixed names. Go `tokenverify` in `acceptance/` accepts its token. Refusal shows beside a passing control |
| **V1 vault** | `NetSec.Vault`, audit page, the vault exercise (routes), `device.enrolment`, `my-login` whole | Export refused and audited. A lab's export shows its caller. OpenSSL judges the exercise's signature |
| **V2 OS transport, own PR** | `OsTransportFactory`, lesson 5 path, chip fix, button text | **`A16.os-transport.*` passes** |
| **V3 Show keys** | `TraceRedaction`, `LabSession.Write`, `key.in-use`, `show-keys-switch`, `SecretsPanel` compare | ON and OFF, same seed, all 12 labs: no ON secret in an OFF frame or file |
| **V4 certificates** | `my-certificates`, 5 types. `LabClock`. `CERT_SIGNATURE_ALG_UNSUPPORTED`. `TamperPlan.Field`, attack availability | Lessons 4, 5, 7, 10 on canary keys. Mutual TLS under an issuing CA with its intermediate, beside a leaf-only control. **Lesson 10 is now whole on own keys** |
| **V5 SSH** | `my-ssh`, 4 types | Lessons 8, 9 hop 1. `ssh.exe` and Go judge from `acceptance/` |
| **V6 payment** | `my-payment`, 2 types. Lesson 9 pad key derived | X9 vectors through the flow's code. Lessons 6, 9 on a canary BDK |
| **V7 lesson keys** | `my-lesson-keys`, 2 types | Lessons 1, 2. OpenSSL on tags. **15 of 15 types take own keys** |
| **V8 words, cold reader** | Cussler pass on wizard copy, `textMine`, A15a reader, Iolo red team. **A cold reader runs lesson 10 on their own test keys from a fresh clone** | The kill condition |

**Golden, by name.** Echo records every lab's engine streams, sorted by `(StreamId, StreamSeq)`, with `FixedClock` and a fixed seed, on both builds. Three exclusions, each by name:

1. `<streamId>/wire` streams, since TCP chunking changes between runs (learnings S0 item 3).
2. Lesson 11's six event types: `timing.lab.started`, `timing.samples`, `timing.managed`, `timing.verdict`, `timing.guess.finished`, and `timing.failed`. They hold `Stopwatch` samples (`Timing.cs:94`), native tick counts, and results that follow them. That leaves lesson 11 nothing to compare, so **the golden covers 11 labs, and lesson 11 is out by these names.** Clause A12 still judges it.
3. The Host's `<sessionId>/keys` stream, which does not exist in the golden.

**Kill condition.** The work ends when a cold reader runs lesson 10 on their own test keys from a fresh clone, an `acceptance/` referee confirms it, and the count is N of 259, or at **2026-11-12 17:00 local**, whichever comes first. The product's `Verified` never counts. The report states N of 259, and names each clause not met. **The reader's run happens at V8, after all 15 types land, because Steve wants every mode (lead, 2026-11-05).** Lesson 10 is whole at V4, and that does not end the work. If the date comes first, the reader runs on what exists.

**Complexity hotspots, named now.**

| Where | Why | Plan |
|---|---|---|
| `SecurityReadiness.Decide` | Consistency across types can grow branches | A list of named pure rules, one per pair of types |
| `KeyFileReader` | PEM, PKCS#8, OpenSSH | One small reader per format. Tests on real OpenSSL and `ssh-keygen` output |
| `wizard-flows.json` | Guards named as strings | A test walks every row of all 5 flows, and fails on an unknown name |
| `LabSession.Write` | Two lines per event | One call to `TraceRedaction`. No branch on mode |

### 9.2 What Echo should expect: M = 259

208 counted today, plus 51. The A16 renames add none. Echo owns the final ids.

| Slice | New clauses | Count |
|---|---|---|
| V0 | `A17.mock.golden-trace-equal` on net10 and on net48 (2), `A17.readiness.refuses-by-name`, `A17.readiness.types-disagree`, `A17.repo.no-key-tracked`, `A17.import.warns-on-personal-ssh-path`, `A17.flow.login.walk`, `A17.referee.token-issuer-go` | 8 |
| V1 | `A17.vault.export-refused-and-audited`, `.export-audited-with-caller`, `.tampered-row-refused`, `.audit-failure-refuses`, `.exportable-is-one-way`, `.exercise-sign-judged-by-openssl`, `.exercise-walk` (Playwright, and the routes) | 7 |
| V2 | None. It closes the renamed A16 clause | 0 |
| V3 | `A17.show-keys.default-on`, `.off-holds-no-secret`, `.mine-shows-exportable`, `.non-exportable-hidden-when-on`, `.fingerprint-compare`, `A17.ui.show-keys-switch` | 6 |
| V4 | `A17.flow.certificates.walk`, `A17.referee.tls13-server-openssl`, `.tls13-client-go-with-intermediate`, `.tls11-server-openssl`, `A17.proof.root-negative-control`, `A17.chain.alg-unsupported-named`, `A17.clock.new-certificate-not-expired`, `A17.attacks.hit-named-field`, `A17.attacks.unavailable-names-code` | 9 |
| V5 | `A17.flow.ssh.walk`, `A17.referee.ssh-host-ssh-exe`, `.ssh-client-go` | 3 |
| V6 | `A17.flow.payment.walk`, `A17.payment.vectors-through-flow-code` | 2 |
| V7 | `A17.flow.lesson-keys.walk`, `A17.referee.lesson-keys-openssl-mac` | 2 |
| V8 | `A17.lesson-N.my-keys` for lessons 1, 2, 4, 5, 6, 7, 8, 9, 10 (9), `A17.ui.no-word-real`, `A17.ui.test-keys-line`, `A17.ui.no-outside-judge-line`, `A17.copy.grade-and-tics`, `A17.cold.lesson-10-fresh-clone` | 14 |
| **Total** | | **51** |

Note for Echo: if a clause uses `PerBuild`, M grows. Only the golden pair is counted as two here, because the rest run in the Host, on net10.

### 9.3 Cut this round, with the door left open

| Cut | Why | Door left open |
|---|---|---|
| OS store provider | RSA only (spike), and writes machine state | `ProviderKind` is a string. Add a provider |
| PKCS#12 | RSA only through the BCL (spike) | Same |
| F8, the data-key wizard, `GenerateDataKey` | `my-lesson-keys` is enough | `IVault` can gain the call |
| Old M5: RSA signatures and RSA-PSS on glass | A learner's chain is Ed25519-signed. An RSA leaf under an Ed25519 root already works (Jared's run) | `CERT_SIGNATURE_ALG_UNSUPPORTED` names the gap, and the OS transport is the route today |
| RSA other than 2048, AES-256 BDK | Offset 669, and lessons use AES-128 | `KEY_SIZE_NOT_2048` and `DUKPT_KEY_SIZE` are the two places to change |
| Sign-inside in the engines | Steve's O1 | `IKeyHandle` still stands in `Keys.cs` |
| Node and CE on own keys | Lesson 9 runs in the Host. A10 stays on training keys | `KeyFileReader` is C# 3, so the CE process can take a `--key-file` later |
| Learner-chosen names | Section 2.5 | Fields on `Credential` |
| Learn-on-first-connect pin, key component ceremony | Each teaches something false here (`modes-real-world.md` sections 3.5, 3.7) | A flow row each |
| Choosing dates or key kind in a flow | Fixed dates pass every lab clock. Each type's key kind is fixed by its engine | A branch step in `wizard-flows.json`, and `LabClock.For` already reads the wall clock |
| `KEY_FILE_PERMISSIONS` warning | Test keys only, so it protects nothing, and `Check` locks its own copy for `ssh.exe` | A row in `warnings[]` |
| Sealing, roles, wrapped-only import, scheduled deletion | Steve's "not super-secure" | Jared's section 4 table is the list |
| CSR for an outside CA | A public CA will not sign `localhost` | A `kind` for the outside wait |

## 10. Decisions

| # | Decision | Result | What would change it |
|---|---|---|---|
| O1 | How a key meets a glass engine | **Decided by Steve: C, bytes through the facade.** Engines stay. The exercise teaches operations, and its non-exportable keys never reach an engine | Steve asks for sign-inside in a lesson |
| O2 | Chains on glass | **Ed25519-signed only this round.** RSA and ECDSA chains go to the OS transport, with a named refusal | Steve wants a chain he did not make on glass |
| O3 | Where items live | **Default stands: gitignored `.security/` in the project** | The repo goes public. Then `%LOCALAPPDATA%`, a one-line change |
| O4 | Facade in or out of process | **In-process.** 2.35 ms per call. `IVault` keeps the door open | A lesson that attacks a compromised Host |
| O5 | Master key | **Plain file,** per Steve's "not super-secure". The vault page says so | Steve wants sealing taught |
| O6 | Showing keys | **Decided by Steve:** the toggle, section 6. A non-exportable key shows only a fingerprint, even when ON, per the lead's ruling. `VAULT_EXPORT_REFUSED` stands | Closed |
| O7 | Axes | **Two.** Section 7 | Closed |
| O8 | Wizards | **Decided by Steve: 5 flows as data, all 15 types** | Closed |
| O9 | DUKPT and passkey | **Decided by Steve: stay available,** and the screen says no outside tool can judge them | Closed |
| O10 | PIN and PAN | **Test values only.** Stands. Section 1.6 | Steve asks, and Dave has read it |
| O11 | Names and dates | **Read-only and fixed this round** (my call, on Iolo's finding). Sections 2.5, 3.4 | A lesson needs a learner's name |
| O12 | Flow ids and spine | **This doc's ids govern (lead).** Nancy's five-screen default path governs the spine | Closed |
| O13 | Vault exercise | **Routes, not a lab,** because the learner types. Section 4.3 | A tour step must bind to it |
| O14 | How the suite reaches a learner's key | **`ProbeRequest.Credentials` and `CredentialSet.FromFiles`** (Echo's option A, lead's pick). Section 3.3 | Closed |

## 11. Prior art and arithmetic

| Item | Finding |
|---|---|
| Catalog check | `E:\dev\MMP.Library\docs\system-design-catalog.md`: no vault or HSM entry. Took "multi-step process with independent failure at each step" for the flows, and the arithmetic habit. Rejected queues and caches |
| Style | Modular monolith plus lab node processes, unchanged. One new module, `NetSec.Vault` |
| Closest shape, keys | HashiCorp Vault transit: "encryption as a service", versioned keys, sign and verify (page read this session). Jared read `exportable` and sealing in Vault's API docs |
| Closest shape, flows | An XState-style machine that owns its moves (house rule, `1rMgw0Q5MgY`) |
| Where we differ | One learner, one machine, loopback, test keys. Labs export each key on each run, which a real system would avoid, and the audit list shows it. We show the audit log and the keys on purpose, since teaching is the job |
| When this is wrong | A team sharing a vault, or a production key in the folder |

| Arithmetic | Value |
|---|---|
| Assumption | 1 learner, 20 lesson runs a day, up to 15 exports a run |
| Rate | Average well under 1 call per second. Measured ceiling: about 425 sign calls per second, with an audit row each (1000 in 2348 ms) |
| Added time per run | About 35 ms at 15 exports, and a person reads the result |
| Key rows | 15 types, 5 versions, about 300 B each: about 22 KB |
| Audit growth | About 100 B per row (1011 rows in 106 KB). 300 rows a day is 30 KB a day, about 33 MB in 3 years. No pruning needed |
| Result | One SQLite file. No cache, no queue, no pool |

| Gems | Use |
|---|---|
| Used | `decide-at-authoritative-boundary` (readiness), `replaceable-seam` (provider), `plain-sentence-error-surface` (flow errors), `paths-plain-at-the-boundary` (key files), `server-replaces-never-merges` (flow step, toggle flip), `seeded-hash-linked-custody-chain` (audit) |
| Novel | None needed yet |

## 12. Disposition

Ready to build after Pre. Echo takes sections 6.6, 7.1, 9.1, and 9.2. Nancy takes sections 6.5, 7.1, and 8. Heather takes section 8.7 with Cussler. The first builder takes V0.

**Where this doc and `docs/modes-real-world.md` differ, this doc governs, because each row is a later decision:**

| Jared's doc | This doc | Authority |
|---|---|---|
| Section 3.12, and recommendation 5: keep the passkey shape on Mock | Available, with the no-outside-judge line | Steve, O9 |
| Section 4: sealing, roles, wrapped import, deletion | Cut this round | Lead's cut list, Steve's "not super-secure" |
| Sections 1 and 2: the word "Real" | "My test key" | Lead's list, item c |
| Section 7: the wizard line, "This course shows every key..." | "Use test keys only. This course shows your keys on screen and in saved files." A non-exportable key does not show, so "every" is too wide | Lead's ruling |

Jared's traps, proof rows, and accuracy limits all stand. His section 3 is the reference for wizard copy.
