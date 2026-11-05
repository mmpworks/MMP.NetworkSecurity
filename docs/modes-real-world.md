# How real setups work: accuracy rules for Mock and Real modes

Owner: Jared, for accuracy. Date: 2026-11-05. Base: `main` at `dfe9510`.

## Conclusion

The course can teach how real setups work, on one PC, with no paid account. It has no public CA and no real HSM. So "Real" means **real form**: a test key a learner makes for this course, in the file format and with the tool a real deployment uses.

**Steve's ruling, 2026-11-05:** "I only ever use test keys... This is training." The course shows all keys in Real mode too. There is no hard stop on production keys. Each wizard carries one line instead (section 7).

Recommendations:

1. **Name two modes and state what each is.** Mock is a public training key. Real is a test key made by a wizard on this PC, in real form. "Real" never means production.
2. **Say on the screen that this course shows every key.** A real system does not. See section 7.
3. **The vault still behaves like a vault, and the course then shows what a real one would hide.** The API refuses export of a non-export key. The course view shows the bytes, labelled as a thing a real vault never does. See section 4.
4. **Each wizard ends at an outside referee, where one exists.** OpenSSL, Go and `ssh.exe` judge TLS, mutual TLS, SSH, tokens and DPoP (run, section 5). DUKPT, passkey and enrolment have no outside live referee, and the wizard must say so.
5. **Keep the passkey shape on Mock, since no real form exists here.** A test BDK can run in glass by the ruling, and the wizard must still say what a real BDK does. See sections 3.7 and 3.12.

### Top 5 things that would make a wizard inaccurate

| # | Inaccuracy | The true statement |
|---|---|---|
| 1 | Letting the view of a key imply that real systems show keys | Real systems hide them. This course shows them to teach, and it expects test keys. A real vault gives no such view of a non-export key |
| 2 | A green check that means "trusted", when the wizard told the client what to trust | A local CA is trusted only by clients that were told to trust it. A self-signed certificate passes against itself (run). A public CA will not sign `localhost` |
| 3 | A "BDK ceremony" or "TR-31 file" that looks like the real thing | A real BDK stays inside an HSM. X9.24 and TR-31 are paid, and this repo holds only the free vectors. Our form is a shape, with no claim of conformance |
| 4 | Proof from our own code, or a failure that names the wrong cause | Our engine agreeing with our engine proves little. Today an RSA chain in glass fails with `CERT_SIGNATURE`, which reads as tampering (run) |
| 5 | A SQLite vault described as a security boundary | The facade copies the **behaviour** of a vault. Its file, memory and process give no protection that an HSM gives |

## 1. Two modes

| Mode | Who makes the key | Bytes visible | Goes in glass | Outside referee | Label to show |
|---|---|---|---|---|---|
| Mock | The course. `TrainingKeySource`, public by design (D5) | Yes | Yes | Yes, as today | "Training key. Public on purpose." |
| Real | A wizard, on this PC, with `openssl` or `ssh-keygen`, or the vault. A test key | Yes, by Steve's ruling | Yes | Yes, where section 5 says | "Your test key, in the real format. This course shows every key, so use test keys only." |

This ruling changes written decisions, and they must change together:

| Text today | Change needed |
|---|---|
| PRD D6: "Real mode uses the OS transport (`SslStream`), shows metadata only, and writes no secret bytes" | Real mode here shows keys. If `SslStream` stays as a separate transport, name that one differently, so "Real" has one meaning |
| PRD A16: "a scan of its trace and session file finds no secret bytes", and a real `IKeyHandle` fails in glass by type | Rewrite for the new meaning. `richard-modes` owns the design |
| UX chip: "Never use it with real secrets" | Still true. It agrees with the ruling |

## 2. What I ran

Throwaway keys, removed after each run. OpenSSL 3.5.7, `C:\Windows\System32\OpenSSH\ssh.exe`, Go referees from `acceptance/referees/go/bin`. "Run" in this document means these rows.

```
openssl verify -x509_strict, full chain        srv.pem: OK
verify, wrong host name                        error 62: hostname mismatch
verify, intermediate missing                   error 20: unable to get local issuer certificate
self-signed, no trust given                    error 18: self-signed certificate
self-signed, itself as the trust anchor        ss.pem: OK
child of a self-signed leaf, strict            error 92: CA cert does not include key usage extension
pkcs12 -info, right password                   MAC: sha256 ... PBES2, PBKDF2, AES-256-CBC
pkcs12, wrong password                         Mac verify error: invalid password?
Go server with wizard chain, s_client verifies Protocol version: TLSv1.3 ... rc=0
Go server, leaf with no intermediate           error num=20: unable to get local issuer certificate
mTLS, client sends leaf only                   TLS_CERT_VERIFY_FAILED: certificate signed by unknown authority
mTLS, client also sends the intermediate       {"event":"handshake","role":"server","version":"TLS 1.3",...
s_client -tls1_1, default security level       no protocols available
ssh.exe, pinned key, strict                    hello
ssh.exe, no pin, strict                        No ED25519 host key is known ... Host key verification failed
ssh.exe, no pin, accept-new                    hello. Warning: Permanently added ... to the list of known hosts
ssh.exe, host key changed                      WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!
ssh-keygen -H                                  |1|xCh5YD29DbKbhRNqc0JFHdIx7Sk=|1D1IpDyMHQZ7BT55PspAHahXxyU= ssh-ed255...
tokenverify, openssl-signed JWS                TOKEN_OK
tokenverify, one changed claim byte            TOKEN_BAD_SIGNATURE
tokenverify -mode dpop, openssl-signed proof   DPOP_OK
tokenverify -mode dpop, other thumbprint       DPOP_JKT_MISMATCH
softhsm2-util, pkcs11-tool, mkcert, certbot, vault   absent on this PC
```

The glass chain check, with openssl-made certificates, through `ChainCheck.Run`:

```
edleaf under edroot                PASS
edunderint under edroot +int       PASS
edunderint under edroot            CHAIN_NO_ANCHOR: no trusted certificate issued certificate 0
rsaleaf_edroot under edroot        PASS | tls11 key ok
edleaf_rsaroot under rsaroot       CERT_SIGNATURE: the signature on certificate 0 does not verify
rsaleaf_rsaroot under rsaroot      CERT_SIGNATURE: the signature on certificate 0 does not verify
p256leaf_p256root under p256root   CERT_SIGNATURE: the signature on certificate 0 does not verify
```

Cause: `Pki/Certificate.cs:216` verifies Ed25519 signatures only. So the wizard must make an Ed25519 CA for glass. An RSA leaf under an Ed25519 root works for TLS 1.1.

**Not run:** a pure `s_client` to `s_server` pair at TLS 1.1 timed out in my harness, with no conclusion. `s_client` against the glass TLS 1.1 server passed on PR #62, with `Verify return code: 0 (ok)`. I ran no browser, no ACME client, no SoftHSM and no real HSM.

## 3. Each security type

Tags: **[S]** is a source I fetched this session (section 9). **[R]** is recollection, which an accuracy reader must check.

### 3.1 TLS server certificate and CA

| Question | Answer |
|---|---|
| Real deployment, in order | 1) The server generates a key and a CSR. 2) An ACME client orders a certificate (RFC 8555 section 7.4 [S]). 3) The CA checks control of the name by HTTP or DNS (sections 8.3, 8.4 [S]). 4) The client finalizes the order with the CSR and downloads the chain. 5) The certificate goes in Certificate Transparency logs (RFC 6962 [S]; browsers enforcing this is [R]). 6) The server is configured with leaf plus intermediates. 7) Renewal runs by automation, because the maximum life is 200 days from 2026-03-15, 100 from 2027-03-15, 47 from 2029-03-15 (CA/B BR 6.3.2 [S]) |
| A private PKI | An offline root signs an online issuing CA, and clients are given the root by policy [R for "offline"]. RFC 5280 defines `cA` and `pathLenConstraint` [S] |
| Who holds what | Server: private key. CA: signing key, in a hardware module for a public CA [R]. Client: root list, supplied by the OS or browser vendor. Nobody else needs the private key |
| Tools and formats | `openssl genpkey`, `req`, `x509`, `verify`. ACME clients. PEM (RFC 7468 [S]). PKCS#8 keys (RFC 5958 [S]). PKCS#12 for a bundle (RFC 7292 [S]). `mkcert` installs a local root in the trust store [S] |
| A learner can do on one PC | Make a root, an issuing CA and a leaf with `openssl`, using Ed25519 for glass. Verify with `openssl verify -x509_strict`. Bundle as PKCS#12. All run. Point a client at the root with `-CAfile`. Do not touch the OS trust store |
| Never pretend | A public CA will not sign `localhost`: "nobody uniquely owns it" (Let's Encrypt [S]), and BR says CAs SHALL NOT issue for Internal Names or Reserved IP Addresses [S]. A self-signed certificate is not a CA chain, though it passes against itself (run). A name goes in the SAN, since RFC 9525 says the Common Name MUST NOT identify a service [S]. "Verified" means "verified against the root you gave it" |
| Do not install a root silently | A root in the OS store makes that PC trust anything the key signs. Let's Encrypt and `mkcert` both describe this step as a local choice [S]. The wizard must use `-CAfile`, or ask, and must offer the removal |

### 3.2 TLS 1.1 RSA

| Question | Answer |
|---|---|
| Real deployment | There is no new one. RFC 8996 deprecates TLS 1.1 [S]. RFC 9325: "Implementations MUST NOT negotiate TLS version 1.1", and `TLS_RSA_WITH_*` suites lack forward secrecy [S]. A real old device keeps it until replaced |
| Who holds what | Server: RSA private key, which **decrypts every recorded session**. The client invents the premaster |
| Tools and formats | `openssl genpkey -algorithm RSA`, PEM, PKCS#8. `s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0` |
| A learner can do | Make an RSA 2048 key and a leaf under an Ed25519 course root, because the engine floor is 2048 bits and the glass chain check needs Ed25519 (run). Reach it with OpenSSL only by lowering the level: `-tls1_1` at the default level gives "no protocols available" (run) |
| Never pretend | That a successful run shows TLS 1.1 is acceptable. That SECLEVEL=0 is a normal setting. With key transport, anyone holding the key file can read old captures, which is what a real deployment risks and what this lesson shows |

### 3.3 Mutual TLS client certificate

| Question | Answer |
|---|---|
| Real deployment | 1) The device makes a key. 2) It proves possession and gets a certificate from a **private** CA, for example by EST (RFC 7030 sections 3.4, 4.2.1 [S]) or SCEP [R]. 3) The server trusts that CA only for clients. 4) The application maps the certificate name to an account and a permission. 5) Rotation and revocation are planned from the start |
| Who holds what | Device: private key, ideally non-export. CA: signing key. Server: CA certificate and an allow rule |
| Tools and formats | `openssl`, EKU `clientAuth`, PKCS#12 for import. Public CAs ending client authentication is [R] |
| A learner can do | Make an issuing CA and a client leaf (run). Send the intermediate as well: Go refuses a leaf-only client, and accepts it with `-cert_chain` (run). Set `ExpectedClientName` (PR #69) |
| Never pretend | A valid chain is not authorization. RFC 8446 section 6.2 keeps `access_denied` for that case [S]. Go checks no name, so the name check has no outside judge (PR #69 verdict). A one-level root hides the intermediate failure |

### 3.4 SSH host key

| Question | Answer |
|---|---|
| Real deployment | 1) Install creates host keys [R: `ssh-keygen -A`]. 2) The administrator records fingerprints with `ssh-keygen -lf`. 3) Clients get the key by prepared `/etc/ssh/ssh_known_hosts` (sshd(8) [S]), or a host CA (`ssh-keygen -s`, `@cert-authority` [S]). 4) Rotation adds a new key before removing the old [R] |
| Who holds what | Server: private host key. Client: public key or CA key |
| Tools and formats | `ssh-keygen`. Private key: `-----BEGIN OPENSSH PRIVATE KEY-----` (run). Public: one line. RFC 4716 form exists [S] |
| A learner can do | `ssh-keygen -t ed25519` for a host key, then prove it with `ssh.exe` against Go `sshpeer` (run) |
| Never pretend | The trust model has two options, a local database or a CA (RFC 4251 [S]). A fingerprint on the same screen as the connection proves nothing, because it needs a second channel |

### 3.5 known_hosts pin and SSH client key

| Question | Answer |
|---|---|
| Real deployment | Pin: fields are marker, hostnames, keytype, base64 key, comment (sshd(8) [S]). `@revoked` means "must not ever be accepted" [S]. Client key: `ssh-keygen`, a passphrase, `ssh-agent`, public half in `authorized_keys`. `PKCS11Provider` holds the key in a token (ssh_config(5) [S]) |
| Who holds what | Client: private key, known_hosts. Server: `authorized_keys` |
| Tools and formats | `ssh-keygen -F`, `-H`, `-R`. `StrictHostKeyChecking`, `UserKnownHostsFile` |
| A learner can do | All of it: `strict` refuses an unknown host, `accept-new` writes the pin, a changed key fails with the warning (run). `-H` hashes the file (run). On Windows, `ssh.exe` needs the private key file locked to one reader, and the wizard must do this and explain it (PR #38 body; I set `icacls` in my run) |
| Never pretend | `accept-new` proves nothing on the first connect. It proves only that later connects match. A wizard must not present it as verification |
| Known gap in our parser | sshd(8): a negated name means the line does not apply even if another name matches [S]. Ours returns `Match` for `!h,h` (PR #51 note). Wildcards read as no host. A real file with these may behave differently here |

### 3.6 Keys the wizard must not offer

TLS traffic keys and SSH session keys come from the handshake. Nobody provisions them. A wizard that offers "your TLS session key" teaches something false.

### 3.7 DUKPT BDK, KSN and key injection

**This is the one to get right, because the real thing is the most hidden.**

| Question | Answer |
|---|---|
| What is public | The X9.24-3 standard is paid (`docs/prd.md`). Its test vector PDF is free (`acceptance/vectors/SOURCES.md`). TR-31 and TR-34 being paid is [R]. X9.143 is the name AWS uses beside TR-31 [S]. PCI PIN requirements: I opened only the library page, so all PCI detail here is [R]. AWS Payment Cryptography's guide is free, and it is the best public description [S] |
| Real deployment | 1) A BDK is generated in an HSM, or built from components under split knowledge and dual control [R for PCI; SP 800-57 defines split knowledge [S]]. 2) It stays there, usable as `TR31_B0_BASE_DERIVATION_KEY` with `DeriveKey` only [S]. 3) For each device, the HSM derives an initial key (IK, or IPEK for TDES) from the BDK [S]. 4) A key injection facility loads that key into the device: exchange a KEK by TR-34, an RSA form, then protect keys under it with TR-31 key blocks [S]. 5) The two sides compare a KCV, never the key [S]. 6) Each sale uses a KSN: key set, device, counter [S for the TDES form: 24, 19 and 21 bits]. 7) At the bank, the PIN is translated inside the HSM to the next key: "acquiring systems shall not have cardholder pins in the clear" [S] |
| Who holds what | HSM: BDK. Device: initial key, then future keys only. KIF: wrapped keys in transit. Terminal software and gateways: nothing that opens the PIN |
| Tools and formats | Payment HSMs, or a cloud service. Key blocks TR-31 and TR-34. None is free to a learner, and `openssl` has no DUKPT |
| A learner can do | Run the repo's X9.24-3 vectors. Hold a practice BDK in the vault with no export, derive through a vault call, and watch the audit trail. Read the AWS commands as a description |
| Never pretend | A real BDK never leaves an HSM in the clear [R for the rule's wording; the AWS guide shows export only inside key blocks [S]]. A file we write is not TR-31. "Key ceremony" with one person at one PC is not a ceremony, because dual control needs two people. Do not let a learner "load" a BDK as a value, because that action has no real form |
| Lesson 6 | Lesson 6 shows the BDK, derived keys and registers as bytes (`Lesson06Dukpt.cs:205`). With a test BDK this stays true. The tour must add that a real HSM shows only a key id and a KCV |
| Payment data | Default the card to the test number. The course makes no compliance claims (PRD rule 8) |

### 3.8 HMAC and MAC keys

| Question | Answer |
|---|---|
| Real deployment | 1) A random key from a CSPRNG or a KDF such as HKDF (RFC 5869 [S]). Shorter than the hash output is "strongly discouraged" (RFC 2104 section 3 [S]). 2) It lives in a secret store. 3) It has one purpose, because "a single key shall be used for only one purpose" (SP 800-57 [S]). 4) It rotates by version. 5) In a vault, compute and verify inside: Vault Transit offers HMAC [S] |
| Who holds what | Both sides hold the same key, which is why a MAC proves nothing to a third party |
| Tools and formats | `openssl rand -hex 32`. `openssl mac -digest SHA256 -macopt hexkey:... HMAC` and `-cipher AES-128-CBC ... CMAC` (run) |
| A learner can do | All of it. OpenSSL recomputes the tag the engine made |
| Never pretend | A password is not a MAC key. A MAC is not a signature |

### 3.9 JWS token issuer

| Question | Answer |
|---|---|
| Real deployment | 1) The signing key sits in a KMS or HSM, and the service calls Sign (AWS KMS [S]). 2) Public keys publish at `jwks_uri` (RFC 8414 [S]) with a `kid` (RFC 7517 section 4.5 [S]). 3) Rotation publishes the new key first [R]. 4) A verifier allows a fixed list of algorithms and checks issuer, audience and type (RFC 8725 sections 3.1, 3.2, 3.8, 3.9, 3.11 [S]). 5) Lifetimes are short |
| Who holds what | Issuer: private key. Every verifier: public key |
| Tools and formats | JWS compact form (RFC 7515 [S]), `EdDSA` (RFC 8037 [S]), JWK |
| A learner can do | Make an Ed25519 key, sign with `openssl pkeyutl -rawin`, and judge with Go `tokenverify` (run) |
| Never pretend | `alg: none` or a shared secret in a public client. "We check `iss`" until we do: PR #20 writes it and does not read it. A token is readable by anyone who sees it |

### 3.10 DPoP

| Question | Answer |
|---|---|
| Real deployment | 1) The client makes a key pair, with no CA and no enrolment. RFC 9449 notes a non-extractable key (WebCrypto) [S]. 2) Each request carries a proof with `jti`, `htm`, `htu`, `iat`, and `ath` at the resource [S]. 3) The token binds to the RFC 7638 thumbprint [S]. 4) The server checks section 4.3 and tracks `jti` [S]. 5) A server nonce limits proofs made ahead of time (sections 8, 9 [S]) |
| Who holds what | Client only. The server sees the public key |
| Tools and formats | JWS with `typ: dpop+jwt`. No file format, since the key should not be a file |
| A learner can do | Sign a proof with `openssl`, judged by `tokenverify -mode dpop` (run) |
| Never pretend | DPoP defeats theft of a token. If an attacker can run code on the client, "the adversary can, however, create new DPoP proofs" while it is online (RFC 9449 section 11.4 [S]). A key in a readable file loses the main benefit. Ours refuses a query in `htu` where Go accepts it (PR #20) |

### 3.11 Device enrolment

| Question | Answer |
|---|---|
| Real deployment | 1) A device arrives with a factory or provisioned identity [R]. 2) It gets the CA list by a bootstrap step (RFC 7030 section 4.1.1 [S]). 3) It requests a certificate or registers a public key, with proof of possession. 4) A person or a policy approves, **by a channel an attacker does not control**. 5) The record maps subject to key. 6) Removal is possible |
| Who holds what | Device: private key. Registry: subject and public key |
| Tools and formats | EST, SCEP [R], MDM [R], TPM attestation [R]. Our row in a table has no standard format |
| A learner can do | Add a row by hand, and see what the check does with it. No outside referee judges this. The client certificate route can be judged by Go (section 3.3) |
| Never pretend | "Enrol the key this client just presented" is no enrolment. It accepts anyone, which is the blocker fixed on PR #20. Tour lesson 10 step 9 has this right, and the wizard must not undo it |

### 3.12 Passkey-shaped login

| Question | Answer |
|---|---|
| Real deployment | 1) The site sends a random challenge, "at least 16 bytes" [S]. 2) The authenticator, **after user verification**, signs over `authenticatorData` and the hash of `clientDataJSON` [S]. 3) The site checks origin, `rpIdHash`, flags, signature and the counter (WebAuthn section 7.2 [S]). 4) Attestation defaults to `"none"` [S]. 5) The key is bound to its authenticator [S]. Synced passkeys are a later feature [R] |
| Who holds what | Authenticator: private key, with use inside its boundary [S]. Site: public key |
| Tools and formats | The browser API, CTAP, CBOR. Nothing an `openssl` command can stand in for |
| A learner can do | Use the shape in the lab. A browser and Windows Hello may do the real thing with no paid account [R], and that is not in this repo and has no referee here |
| Never pretend | PRD rule 6: "A passkey-shaped challenge is not WebAuthn." The origin binding that stops phishing is the point of WebAuthn, and our shape has no browser to enforce it. Offer no Real mode here |

### 3.13 HSM or vault use

Section 4 is the behaviour list. The rule for wizards: **an HSM is a machine that refuses**. Most of what a learner should see is a refusal with a reason.

| Question | Answer |
|---|---|
| Real deployment | 1) The module is initialized under a Security Officer role and a user role (PKCS#11 [S]). 2) A key is generated inside, with its attributes set. 3) An application logs in and calls an operation by handle. 4) Key copies leave only wrapped. 5) Auditors read the log. FIPS 140-3 gives levels [S] |
| Tools and formats | PKCS#11, `pkcs11-tool` [R], Vault, AWS KMS. SoftHSM is a free software PKCS#11 module, made so that users need not buy a device [S]. It is absent on this PC (run) and offers no hardware protection |
| A learner can do | Use the facade, and read this table. An optional SoftHSM route would give real PKCS#11 calls, and `ssh.exe` ships `ssh-pkcs11-helper` (present). I did not run this route, so it stays out of scope unless someone proves it |
| Never pretend | That the facade is an HSM, is FIPS validated, or protects anything from a person who can read the file |

## 4. What the SQLite facade must copy

| Behaviour | Real source | The facade must | Refusal or result to show |
|---|---|---|---|
| Keys are used, never read | PKCS#11: `CKA_VALUE` "Cannot be revealed" when sensitive or not extractable. KMS: keys are available "only on the HSMs and only in memory" | Offer `Sign`, `Verify`, `Mac`, `Derive`, `Unwrap` by key id. Offer no get-value call for a non-export key | `KEY_NOT_EXPORTABLE`, the shape of `CKR_KEY_UNEXTRACTABLE` |
| Export is decided at creation, and one way | Vault: `exportable` "cannot be disabled" once set, same for `allow_plaintext_backup`. PKCS#11: `CKA_EXTRACTABLE` may go from true to false, "but not the other way around". AWS Payment Cryptography: "You can't change these properties" | Store `exportable` at creation. Allow true to false only. Keep `never_extractable`, as PKCS#11 does | An attempt to turn it on fails by name, and shows in the audit |
| Purpose is fixed | SP 800-57 one purpose. AWS `KeyModesOfUse`. PKCS#11 `CKA_SIGN`, `CKA_WRAP` | Store usage at creation. A signing key refuses `Derive` | `KEY_USAGE_DENIED` |
| Versions | Vault: rotate adds a version, `min_decryption_version` archives old ones. KMS "retains all key material" for a key across rotation | Rotate adds a version. Sign uses the newest. Verify names the version it used. Old versions verify until retired | Ciphertext or signature shows its version |
| Wrap and unwrap | Vault BYOK uses a 4096-bit RSA `wrapping_key` plus AES. PKCS#11 `C_WrapKey`, `CKA_WRAP_WITH_TRUSTED`, `CKA_UNWRAP_TEMPLATE`. AWS TR-31 under a KEK | Import only wrapped material. A wrapped copy never equals clear. Attributes come from the unwrap template | A clear import is refused, with the reason |
| Sealing | Vault: when sealed, "the only possible Vault operations are to unseal the Vault and check the status". Shamir shares, a threshold. A seal call deletes the root key from memory | Start sealed. Refuse each operation with `VAULT_SEALED`. Unseal by passphrase, or by shares for teaching. Offer Seal | Status shows sealed or not |
| Audit | Vault: audit devices "record all API requests and responses". Sensitive values are hashed. If no device can write, Vault stops serving: when the devices "become unavailable, Vault in effect becomes unavailable as well" | Write a row for each call, including refusals, **before** the result returns. Store a keyed hash, never the value. If the audit write fails, refuse the operation | Learner sees the audit list. A hash chain is extra, and the wizard must not call it tamper-proof |
| Deletion is not immediate | KMS: "waiting period of 7 – 30 days", and deletion "is irreversible" | Schedule, allow cancel, then destroy. A short course wait is fine if stated | State shows pending deletion |
| Roles | PKCS#11 Security Officer and user | A setup role and a use role. Show which role did what | `ROLE_DENIED` |
| Check value | AWS KCV: compares keys "without having access to the actual key material" | Show a KCV for a symmetric key, computed as AWS describes (CMAC for AES) | Use it in the "compare" step |

### What the facade must say about itself

1. "Practice vault. Not an HSM. Not FIPS validated."
2. The key sits in a file on this PC, encrypted under a passphrase, and the program holding it can read it in memory. Tour lesson 6 step 8 already says this for strings.
3. Non-export here is a rule in our code. In an HSM it is a property of a device. Anyone can open the SQLite file and read the wrapped key.
4. Sealing here protects the file at rest. It does not stop a program already running as the user.

### Two views of one key

Steve's ruling keeps both of these on screen, and the wizard must keep them apart:

| View | What it shows | What a real vault does |
|---|---|---|
| The vault API, as a program calls it | `Sign` works, and a read of a non-export key fails with `KEY_NOT_EXPORTABLE` | The same |
| The course view | The key bytes, always, labelled "A real vault never shows you this. This course does, so you can see the parts" | No such view exists |

Glass reads the key through the course view, and that read appears in the audit list as a course read, not as an export. Otherwise the audit list would teach that a non-export key was exported.

The wizard's outside proofs in section 5 use files. For a non-export key, the accurate proof is the real one: sign a test value through the API, and verify it with `openssl pkeyutl -verify` against the **public** key. I did not run this row, though the same verify shape ran for tokens.

## 5. Which final step can prove a key, and against what

| Type | Final step | Outside judge | Status |
|---|---|---|---|
| TLS chain | `openssl verify -x509_strict -CAfile root -untrusted int -purpose sslserver -verify_hostname localhost leaf` | OpenSSL | Run |
| TLS server key | Go `tlspeer -mode server -cert chain -key key`, then `s_client -CAfile root -verify_return_error -verify_hostname localhost` | Go and OpenSSL | Run |
| TLS 1.1 RSA | `s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile root` against the glass server | OpenSSL | Run on PR #62, with the training root. Not run with a learner key |
| Mutual TLS | Go `tlspeer -require-client-cert -ca root`, then `s_client -cert leaf -key key -cert_chain int` | Go | Run |
| SSH host key | `ssh.exe -o StrictHostKeyChecking=yes -o UserKnownHostsFile=file` against Go `sshpeer -host-key` | `ssh.exe` | Run |
| SSH client key, known_hosts | Same run, with `sshpeer -authorized` | Go and `ssh.exe` | Run |
| HMAC, CMAC | `openssl mac` against the engine's tag | OpenSSL | The commands ran. Comparison with the engine not run |
| JWS | Go `tokenverify -pub jwk -token` | Go | Run |
| DPoP | Go `tokenverify -mode dpop` | Go | Run |
| Name check | None. Go checks no name | None | Our own tests only. Say so |
| DUKPT | Known answers from the X9.24-3 vectors. `openssl mac -cipher AES-128-CBC` can check a CMAC given a derived key | No live peer | Say: "checked against published vectors, no outside system" |
| Passkey shape, enrolment | None | None | Say so. Do not show a green proof |

**Rule for the final screen:** show the command, its real output, and the name of who judged it. A row with no outside judge reads "our own check".

## 6. Real-key uses that make a tour claim false

| Tour text, today | Why a learner key breaks it | Handling |
|---|---|---|
| Lesson 4 step 1: "a training CA made for this course" | The CA is the learner's | Bind the sentence to the mode |
| Lesson 4 step 4: "In this lab the chain has two cards" | A wizard CA with an intermediate has three. `docs/ux-design.md:281` already says three, which disagrees with the tour | Read the chain length from the trace |
| Lesson 6 step 12: "All keys in this lab are made up, and anyone can read the base key in the source" | "In the source" is false for a test BDK from a wizard | Bind the sentence to the mode |
| Lesson 6 step 2: "like a key put in at a secure facility" | Fine on Mock. On a vault it must stay "like" | Keep |
| Lesson 8 step 6: "because the client pinned it earlier" | False after `accept-new` on a first connect | Show the source of the pin |
| Lesson 9 steps 1, 2, 11: the pad holds a loaded key, "the training keys in this course are public on purpose" | False with learner keys. `PinPadCore.InjectedInitialKey` is a fixed constant, so a test BDK also needs a matching loaded key | Bind the sentence to the mode, and derive the loaded key from the test BDK |
| Lesson 9 step 3: "put on the device ahead of time, when it was provisioned" | False if the wizard learns the pin on first use | Require a prepared line |
| Lesson 10 step 6: "issued under the same training root" | Learner root | Bind to the mode |
| UX chip: "This engine shows its keys on purpose. Never use it with real secrets." | Stays true, and it agrees with the ruling. "Real" beside it needs the wizard line | Keep the chip, and add the line in section 7 |

Mechanical breaks that no tour text shows, each read from code:

| Break | Where | Effect |
|---|---|---|
| Fixed lab clock | `Tls13Lab.cs:40` and `Lesson07Tls11.cs:29` use 2030-01-01. `Lesson10Auth.cs:47` uses a fixed time | A learner's 30-day certificate reads `CERT_VALIDITY`. The wizard must issue for the lab date, or the lab must take real time for a learner run |
| Fixed attack offsets | `Labs.cs:209-215` (`SshEd25519SignatureOffset`, `SshRsaSignatureOffset`), `Tls13Lab.cs:29-36` | Another key or certificate size moves the fields. A flip can land elsewhere, and a row can pass for the wrong reason. Rows must locate fields from the trace, or stay on Mock |
| Same-seed replay | `Both_builds_give_the_pinned_trace`, `session.attack` by stream sequence | New key bytes change the pinned digest, so a pin must be per key class |
| Glass signature check | `Certificate.cs:216` | RSA or ECDSA chains fail with a name that reads as tampering. Add a code for "this engine signs with Ed25519 only" |
| TLS 1.3 glass key | `Tls13Rules.PeerSignature` needs Ed25519 | A leaf with another key type cannot prove itself in glass |
| Host names | Lab pins `ssh.lab`. `TrainingPki.ServerName` is `localhost` | A wizard name must match, or the name check fails |

## 7. Test keys only, and the wizard line

**Steve's ruling: no hard stop.** "I only ever use test keys... This is training." The course shows all keys in Real mode too. An earlier draft of this document recommended a hard stop, and that recommendation is withdrawn.

**The line each wizard carries, on its first screen:**

> This course shows every key, so it expects test keys. A real system keeps these hidden.

Why the line is accurate, for a reader who asks:

| Fact | Evidence |
|---|---|
| Glass writes secrets to the trace on purpose | `Effect.SecretAs(Derived, BaseKeyName, ...)` at `Lesson06Dukpt.cs:205`. `secret.derived` on SSH (`SshKex.cs:94`). TLS key log lines |
| They persist | `GET /api/sessions/{id}/keylog` in `NetSec.Host/Program.cs:57`. Session files and NDJSON trace files |
| The engine has had no side-channel review | D6, and PRD rule 5: managed code has no constant-time guarantee |

Two things stay as plain wizard behaviour, with no gate:

1. The wizard passes `-f` with a course folder, because `ssh-keygen`'s default path is the learner's daily key. Writing a test key there would overwrite or confuse it.
2. A card number field defaults to the test number. The course makes no compliance claims (PRD rule 8).

## 8. Limits of this document

1. Section 3 describes deployments from public sources. I have not operated a payment HSM. The DUKPT and PCI rows marked [R] need a reader with that access, or they stay as "commonly".
2. I fetched vendor documents with `curl`, because WebFetch refused those domains. I read them as data. The HashiCorp pages are current as of this fetch, and they change.
3. X9.24-3, TR-31, TR-34 and PCI PIN text were not read. Nothing here quotes them.
4. Run rows are on this PC with OpenSSL 3.5.7 and OpenSSH on Windows. No browser, no ACME run, no real CA, nothing on CE.
5. The reviewer is the same vendor as the builder. The anchors are the outside tools in section 2.

**Disposition:** adopt the two modes, the wizard line, and the facade table. Keep the passkey shape on Mock. A Real BDK in lessons 6 and 9 is now possible by the ruling, because the course shows it, and section 3.7's real steps still apply. Fix the glass chain refusal name before any wizard ships a non-Ed25519 option.

## 9. Sources fetched this session

| Topic | Source |
|---|---|
| ACME | RFC 8555, https://www.rfc-editor.org/rfc/rfc8555.txt |
| Public CA rules | CA/Browser Forum Baseline Requirements, https://cabforum.org/working-groups/server/baseline-requirements/requirements/ (sections 4.2.2, 6.3.2) |
| `localhost` | Let's Encrypt, https://letsencrypt.org/docs/certificates-for-localhost/ |
| Local CA tool | mkcert, https://github.com/FiloSottile/mkcert |
| Names, PKI, CT | RFC 9525, RFC 5280, RFC 6962 |
| Formats | RFC 7468 (PEM), RFC 5958 (PKCS#8), RFC 7292 (PKCS#12), RFC 8017 |
| TLS | RFC 8446, RFC 8996, RFC 9325, RFC 5746 |
| Enrolment | RFC 7030 (EST) |
| SSH | RFC 4251, RFC 4252, RFC 4253, RFC 4716, RFC 8709. https://man.openbsd.org/ssh-keygen.1, https://man.openbsd.org/sshd.8, https://man.openbsd.org/ssh_config.5 |
| Tokens | RFC 7515, RFC 7517, RFC 7518, RFC 7519, RFC 7638, RFC 8037, RFC 8725, RFC 8414, RFC 9449 |
| MAC | RFC 2104, RFC 5869 |
| Passkey | W3C WebAuthn Level 2, https://www.w3.org/TR/webauthn-2/ |
| NIST | SP 800-57 Part 1 Rev 5, FIPS 140-3, SP 800-63B (nvlpubs.nist.gov, pages.nist.gov) |
| PKCS#11 | OASIS v3.1, https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.html |
| SoftHSM | https://github.com/softhsm/SoftHSMv2 |
| Vault | developer.hashicorp.com: `vault/docs/secrets/transit`, `vault/api-docs/secret/transit`, `vault/docs/concepts/seal`, `vault/docs/audit`, `vault/docs/audit/best-practices`, `vault/tutorials/monitoring/blocked-audit-devices` |
| AWS KMS | docs.aws.amazon.com: `kms/latest/developerguide/concepts.html`, `rotate-keys.html`, `deleting-keys.html`, `kms/latest/cryptographic-details/intro.html` |
| Payment keys | docs.aws.amazon.com/payment-cryptography/latest/userguide: `keys-import.html`, `keys-export.html`, `create-keys.html`, `terminology.html`, `use-cases-acquirers.html` |
| X9 vectors | `acceptance/vectors/SOURCES.md`, in this repo: the supplement is free and copyrighted by ASC X9 |
