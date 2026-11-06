# Conformance matrix: does the course follow the standards?

Author: Jared. Date: 2026-11-06. Base: main `7b569a1`. Owner of the gap clauses: Echo.

## Conclusion

On each path that the 166 selected acceptance clauses ran, the course gave the right answers: 166 of 166 passed this session. The other 95 clauses did not run, so this page says nothing from them. One point stays undecided: the DUKPT counter limit, where the engine and the X9 Python reference differ and the unread standard decides (section 6). Most rows that fall short omit or mis-signal something the standard requires. Section 4 lists those for TLS 1.3.

**The two changes I would make first:**

1. **Fix one on-screen claim in lesson 6.** Claim `L6-C01` says future keys stay safe when a derived key leaks. That holds for one working key. I tested the engine: stolen registers rebuild every later sale. Lesson 6 also never names AES DUKPT or X9.24-3.
2. **Name what each protocol engine leaves out, on screen, and fix the small TLS 1.3 misses.** TLS 1.3, TLS 1.1 and SSH each omit items the standard marks as required. The lessons name only some of them. One line per lesson turns each omitted feature into a named training simplification. Section 4 lists five TLS 1.3 receiver checks, each small to fix.

| Count | Result |
|---|---|
| Rows conforming, with no gap and no bug | **19 of 30** |
| Rows that run correctly on their path, with named gaps or a bug | 10 of 30 |
| Rows UNVERIFIED | 1 of 30 (the AES walk's round states: the product code does not exist yet) |
| Rows with official vectors that a clause ran this session | **17 of 30**: 14 with values committed in the repo (rows 3, 15 to 27), 2 fetched at run time against a pinned hash (rows 1, 2), 1 group constants only (row 28) |
| Rows with official vectors in the repo that only a unit test ran | 1 of 30 (row 11, ML-KEM) |

**Row status words:**

| Word | Means |
|---|---|
| CONFORMS | A result from this session passed, for the inputs and sizes it covers. The row has no bug and no gap. A row with no vectors keeps this word only if I read the cited sections this session and tested what they require |
| PATH OK, GAPS | What runs passed. The row also has at least one gap or bug, listed in the row |
| UNVERIFIED | Nothing ran |

**Evidence rule, by Steve's ruling.** "We should be able to trust microsoft's library." So a match with the .NET library counts as conforming for a primitive the library covers, for the inputs and sizes the comparison ran. A missing official vector is not a gap on such a row. The evidence columns stay apart, so a reader can see which kind of evidence each row has.

**Deviation rule.** Each deviation is a **bug**, a **simplification** named on screen, or a **gap**. Items the standard marks optional are not deviations.

## 1. What the run covered

Machine: Windows `10.0.26300`. Commit `7b569a1`, acceptance commit `ed4ffa7`.

```
pwsh acceptance/run.ps1 -Clauses A1,A2,A3,A4,A5,A6,A7,A8,A10,A10a,A11
[acceptance] 166 of 166 clauses PASS (0 FAIL, 0 NOT RUN); M = 261
A1 52 of 52   A2 12 of 12   A3 15 of 15   A4 20 of 20   A5 20 of 20   A6 4 of 4
A7 12 of 12   A8 12 of 12   A10 7 of 7    A10a 3 of 3   A11 9 of 9
```

The other 95 of the 261 clauses are outside this job (A9, A12 to A17). I did not run them. I also ran two test sets:

```
dotnet test tests/NetSec.Tests -c Release
Passed!  - Failed: 0, Passed: 672, Skipped: 0, Total: 672 - NetSec.Tests.dll (net10.0)
Passed!  - Failed: 0, Passed: 672, Skipped: 0, Total: 672 - NetSec.Tests.dll (net48)
dotnet test tests/NetSec.Host.Tests -c Release --filter TrainingKeyBcl|OsTransportLive|SshExe
Total tests: 12. Passed 12
```

The rest of `NetSec.Host.Tests` did not run. Most clauses run twice: once on the net10 build, and once on the CF-compiled build on the desktop CLR. Nothing here ran on real Windows CE hardware. `L7-S10`, `L8-S14` and `L9-S12` say so on screen.

| Referee | Version |
|---|---|
| .NET library | .NET `10.0.14` |
| OS provider for the library on Windows | CNG: `bcryptprimitives.dll 10.0.26100.9711`, `ncrypt.dll 10.0.26100.1591`. `MLKem.IsSupported`, `SHA3_256.IsSupported`, `Shake128.IsSupported` and `AesGcm.IsSupported` are all true |
| Windows TLS (OS transport, lesson 5) | `schannel.dll 10.0.26100.1`, through `SslStream`. `Lesson_5_on_the_os_transport_talks_tls_13_and_shows_no_secret` passed. This path is Windows code, so it is no evidence about the course's engine |
| OpenSSL | `3.5.7` |
| Go | `go1.26.2`, `crypto/tls`, `golang.org/x/crypto v0.58.0` |
| OpenSSH | `ssh.exe`, `OpenSSH_10.3p1` |

The version lines come from a separate probe on the same machine, with the same runtime roll-forward. The A2 referee does not print its own version.

## 2. Rows the library cannot check

These rows come first because Steve's ruling leaves them to other evidence.

| # | Standard and section | Code path | Official vectors | Run on official vectors today? | Library or peer cross-check | Deviations, by bucket | On screen? | Status |
|---|---|---|---|---|---|---|---|---|
| 1 | **AES DUKPT**, ANSI X9.24-3-2017 (paid, not read) | `Dukpt/DukptDerivation.cs`, `DukptPinPad.cs`, `DukptBank.cs`, `Labs/Lesson06Dukpt.cs` | X9 free supplement PDF, annex B values | **Yes.** `A3.vec.aes128-from-aes128` 68, `A3.vec.aes128-from-aes256` 68, `A3.vec.aes256-from-aes256` 68, `A3.vec.all-usages` 72 | moov-io/dukpt: section 6. `A3.sales1000.agree` 6,000 (pad against bank) | **Bug:** `L6-C01` overstates (section 6). **Gap:** counter limit edge, X9 Python and the engine differ at 16 one bits (section 6). **Gap:** the variant is unnamed | Bug text is on screen. Variant: no. Erase limit: yes, `L6-S09` | PATH OK, GAPS |
| 2 | **PIN block format 4**, ISO 9564-1 (paid, not read) | `Dukpt/PinBlock.cs` | X9 supplement | **Yes.** `A3.pinblock.format4` 27 | moov-io: opens 54 of 54 course blocks, and the course opens 54 of 54 moov blocks | None found | Not needed | CONFORMS |
| 3 | **TLS 1.3 key schedule**, RFC 8446 section 7.1 | `Tls13/Tls13KeySchedule.cs` | RFC 8448 section 3 | **Yes.** `A4.rfc8448.*`, 10 clauses: early, handshake, master, traffic secrets, keys and IVs, Finished, transcript hashes, exporter and resumption | `A6.keylog.openssl.*`: key log equal to OpenSSL on 4 labels, both groups | None found | Not needed | CONFORMS |
| 4 | **TLS 1.3 message order and records**, RFC 8446 sections 2, 4, 5, 9 | `Tls13/Tls13Engine.cs`, `Tls13ClientTable.cs`, `Tls13ServerTable.cs`, `Tls13Records.cs`, `Tls13Session.cs` | RFC 8448 covers one trace's values only | The order runs on live peers, not on a vector | `A5.client.openssl.*`, `A5.client.go.*`, `A5.server.openssl.*`, `A5.server.go.*`, both groups. Section 3 states how far this goes | **Simplification:** no KeyUpdate. **Gap:** no HelloRetryRequest, and so no `cookie` (section 9.2 MUST). **Gap:** no secp256r1 key exchange, no `rsa_pkcs1_sha256`, `rsa_pss_rsae_sha256` or `ecdsa_secp256r1_sha256` (section 9.1 MUST). **Gap:** no ChaCha20 (SHOULD) | KeyUpdate: yes, `L5-S14`. The rest: no | PATH OK, GAPS |
| 5 | **TLS 1.3 checks a peer must make**, RFC 8446 sections 4.1 to 4.2, 4.4, 5, 6, 7.4.2 | `Tls13/Tls13Rules.cs`, `Tls13Codes.cs`, `KeyExchange.cs:SharedX25519` | None | Not applicable | `A7.downgrade-sentinel.tls13-client-beside-control`, `A7.alert70.*`. Section 4 maps each check to a test | **Gap:** 5 receiver misses, by reading the code against the MUST list: section 4 | Named checks show in the lab. The misses: no | PATH OK, GAPS |
| 6 | **Hybrid X25519MLKEM768**, RFC 10024 | `Tls13/KeyExchange.cs` | None read | Not applicable | `A5.*.x25519mlkem768`, `A6.keylog.openssl.x25519mlkem768`: OpenSSL reports the group by name. `The_hybrid_shares_have_the_sizes_rfc_10024_names`, `Nist_encapsulation_key_checks_match`, `An_all_zero_x25519_result_is_refused_on_both_roles_beside_a_good_share`. RFC 10024 sections 4.2 and 4.3 read: key check, ciphertext length, zero check, each alert 47 in `KeyExchange.cs` and `Tls13Codes.cs` | None found. Other hybrids in RFC 10024 are optional | Not needed | CONFORMS |
| 7 | **TLS 1.1 messages and checks**, RFC 4346 sections 7 and 9 | `Tls11/Tls11Engine.cs`, `Tls11Rules.cs`, `Tls11Messages.cs` | None | Not applicable | `A7.tls11.openssl.*`, `A7.tls11.server.openssl.*`, both key exchanges, both roles. Bad RSA padding gets a random premaster (`Tls11Rules.cs:332-335`) | **Gap:** no `TLS_RSA_WITH_3DES_EDE_CBC_SHA`, RFC 4346 section 9 MUST. **Gap:** no session resumption and no client certificate. **Simplification:** no Lucky Thirteen claim | Lucky Thirteen: yes, `L7-S07`. Weak points: `L7-S10`. The rest: no | PATH OK, GAPS |
| 8 | **TLS 1.1 PRF and CBC records**, RFC 4346 sections 5, 6.2.3 | `Tls11/Tls11Prf.cs`, `Tls11Records.cs` | None published | Not applicable | Both A7 live runs depend on them. `The_prf_gives_the_openssl_answer_for_an_even_secret`, `The_prf_shares_the_middle_byte_of_an_odd_secret`, `A_replayed_record_fails_because_the_mac_covers_the_count`, `One_flipped_bit_fails_the_record`. RFC 4346 sections 5 and 6.2.3.2 read: padding filled and checked, one code for both failures | **Simplification:** section 6.2.3.2 requires equal processing time, and the lab makes no such claim | Yes, `L7-S07` | CONFORMS |
| 9 | **SSH transport, key exchange, key derivation, packets**, RFC 4253, RFC 8731, RFC 8709, RFC 4344, strict KEX draft | `Ssh/SshEngine.cs`, `SshKex.cs`, `SshExchange.cs`, `SshPackets.cs` | None published for the engine's suites | Not applicable | `A8.ssh.modern.*`, `A8.ssh.legacy.*` (Go), `A8.ssh.exe-to-glass-server` (OpenSSH). Section 3 states how far this goes. `The_keys_take_K_as_an_mpint_too`, `A_long_key_extends_by_hashing_again` | **Gap:** RFC 4253 lists `3des-cbc`, `diffie-hellman-group1-sha1` and `ssh-dss` as REQUIRED, and the engine has none. Later RFCs may relax these (from memory, UNVERIFIED). **Gap:** no key re-exchange, which stops by the name `SSH_REKEY_UNSUPPORTED`. **Simplification:** a real old peer has not run | Old-peer limit: yes, `L8-S14`. Modern's limits: `L8-S03`. Rekey and required list: no | PATH OK, GAPS |
| 10 | **SSH user auth and connection**, RFC 4252, RFC 4254 | `Ssh/SshClientRules.cs`, `SshServerRules.cs`, `SshSession.cs` | None | Not applicable | Same A8 runs: exec and tunnel. `A8.ssh.hostkey-changed-beside-control` | **Simplification:** exec answers from a fixed table. **Gap:** public key auth only (RFC 4252 password is SHOULD) | Fixed table: yes, `L8-S11`. Auth method list: no | PATH OK, GAPS |
| 11 | **ML-KEM-768**, FIPS 203 (not read this session) | `Crypto/MlKem768.cs`, `KPke.cs`, `Poly.cs`, `MlKemEncoding.cs`, `MlKemSampling.cs` | NIST ACVP. In the repo: `tests/NetSec.Tests/vectors/mlkem768-acvp.txt`, 36 records | **Yes, by unit test.** `Nist_keygen_vectors_match`, `Nist_encapsulation_vectors_match`, `Nist_decapsulation_vectors_match_including_modified_ciphertext`, `Nist_encapsulation_key_checks_match`, `Nist_decapsulation_key_checks_match`. No acceptance clause runs them | **.NET library peer:** `A2.mlkem768.ours-encaps-bcl-decaps` 400, `A2.mlkem768.bcl-encaps-ours-decaps` 400, on CNG. Live hybrid with OpenSSL and Go | None found. ML-KEM-512 and 1024 are not run, and no lesson needs them | Not needed | CONFORMS (768, on this OS) |
| 12 | **X.509 paths**, RFC 5280, RFC 8410 | `Pki/Certificate.cs`, `Der.cs`, `TrainingCa.cs` | None | Not applicable | `A5.pki.leaf-verifies-under-openssl`, `A5.client.openssl.untrusted-chain-refused`. `Each_chain_failure_has_its_code_beside_a_passing_control`, `A_leaf_cannot_act_as_an_issuer`, `An_unknown_critical_extension_is_refused_and_a_non_critical_one_is_read_past` | **Gap:** no revocation, no policy processing, no name constraints | Two-card chain: `L4-S05`. The rest: no | PATH OK, GAPS |
| 13 | **Signed tokens and DPoP**, RFC 8037, RFC 7638, RFC 9449 | `Auth/Auth.cs` | Not checked | No | `A11.token.verifies-under-go-tokenverify`, `A11.mtls.go-referee-requires-client-cert`, `A11.catalog.every-row-beside-control` | **Simplification:** passkey-shaped, "It is not WebAuthn". **Gap:** a subset of RFC 9449 section 4.3 steps runs in one stated order, with replay left to the caller; only `EdDSA` | WebAuthn: yes, `L10-S12`. DPoP subset: no | PATH OK, GAPS |
| 14 | **AES walk's round states** (PR #146, design only) | None yet. Planned `Crypto/AesKey.Walk.cs` | FIPS 197 (2001) appendix C | **UNVERIFIED for the product.** The anchor is ready: my independent Python matched 372 of 372 values in order, from the PDF whose hash matches `SOURCES.md` | Plan: run-time guard against `EncryptBlock`, BCL on the output | Not built | Not built | UNVERIFIED |

## 3. How far the live protocol runs go

A live run with an outside peer is strong evidence on one thing: the two sides agree on every byte of the path they took. A wrong label, wrong transcript or wrong key derivation fails the run at once. The limits:

| Limit | Applies to |
|---|---|
| It covers the suites and groups the run chose. TLS 1.3: `X25519` and `X25519MLKEM768`, Ed25519 signatures. TLS 1.1: `AES128-SHA`, `ECDHE-RSA-AES128-SHA`. SSH: Modern and Legacy | A5, A7, A8 |
| A peer accepts more than the standard demands. So a run shows the course's messages are acceptable. It does not show that the course refuses every bad message. Sections 2 row 5 and 4 carry that | A5, A7, A8 |
| The peers ran on one machine, over loopback, with one software version each | A5, A7, A8 |
| A TLS 1.3 peer that offers only P-256 gets a refusal by name, by my reading of `Tls13ServerTable.cs:92` and `Tls13ClientTable.cs:50`. So the course does not interoperate with such a peer. `A_hello_retry_request_is_refused_by_name` pins one side. I did not run this against a peer | A5 |
| No peer that lacks the SSH strict KEX marker has run. `L8-S14` says so | A8 |

## 4. Checks a conforming TLS 1.3 peer must make

I listed every MUST in RFC 8446 sections 4.1, 4.2.1 to 4.2.3, 4.2.7, 4.2.8, 4.4, 5, 6 and 7.4 by script, 176 sentences, and read each one against the engine. Most bind the sender or a feature the engine does not build. These five receiver checks are missing or give another alert. I found them by reading the code, and I did not run them.

| Must | Section | The engine | Code |
|---|---|---|---|
| A server aborts with `illegal_parameter` unless the ClientHello compression is one zero byte | 4.1.2 | Takes the field and never reads it | `Tls13Messages.cs:207` |
| A client aborts with `unsupported_extension` on an extension it did not request | 4.2 | Skips unknown ServerHello extensions, and does not parse EncryptedExtensions | `Tls13Messages.cs`, `Tls13ClientTable.cs:19` |
| A server aborts with `missing_extension` when `signature_algorithms` is absent | 4.2.3 | Refuses by name with alert 40 | `Tls13ServerTable.cs:91` |
| A client aborts with `illegal_parameter` on a `supported_versions` value it did not offer | 4.2.1 | Refuses by name with alert 70 | `Tls13ClientTable.cs` |
| A client aborts with `decode_error` on an empty server Certificate | 4.4.2.4 | Refuses by name with the chain code, alert 48 | `Certificate.cs:278` |

The engine refuses in three of the five. The refusal names a check, and only the alert number differs from the RFC.

The checks below are present:

Each test below passed this session. `Every_attack_in_the_catalog_is_caught_by_its_named_check_beside_the_control` runs each catalog attack beside a control, including `L4-flip-cert-verify`, `L5-flip-finished` and `L5-flip-record-byte`. `Every_byte_of_an_x25519_handshake_gives_a_named_result_at_both_tamper_points` flips each byte of a handshake.

| Check | Section | Test or clause |
|---|---|---|
| Downgrade sentinel in the server random | 4.1.3 | `A7.downgrade-sentinel.tls13-client-beside-control`, `A_downgrade_sentinel_is_named_beside_a_plain_old_server` |
| Refuses a version it does not speak | 4.2.1 | `A7.alert70.modern-server-beside-legacy-control` |
| CertificateVerify signature over the transcript | 4.4.3 | `Every_attack_in_the_catalog_is_caught_by_its_named_check_beside_the_control` (`L4-flip-cert-verify`) |
| Finished compare | 4.4.4 | `VerifyFinished_takes_the_right_value_and_refuses_a_flip_and_a_short_value` |
| AEAD tag on every protected record | 5.2 | Same test (`L5-flip-record-byte`) |
| A clear record after keys is refused | 5 | `A_clear_record_after_keys_is_refused_on_both_roles` |
| A message may not cross a key change | 5.1 | `A_message_may_not_cross_a_key_change` |
| ServerHello legacy version and compression | 4.1.3 | `A_server_hello_with_a_bad_legacy_version_or_compression_is_refused` |
| A dummy change_cipher_spec is limited | 5, D.4 | `A_dummy_ccs_passes_only_as_one_byte_of_value_1_and_only_before_the_peers_finished` |
| Record length limit | 5.1, 5.2 | `A_message_with_no_row_names_the_state_and_a_record_length_past_the_limit_fails_now` |
| All-zero X25519 result refused | 7.4.2 | `An_all_zero_x25519_result_is_refused_on_both_roles_beside_a_good_share` |
| Certificate chain, dates and name | 4.4.2, RFC 5280 | `Each_chain_failure_has_its_code_beside_a_passing_control`, `A5.client.openssl.untrusted-chain-refused` |
| A flaw ends in a fatal alert | 6 | `An_abort_fails_the_tls13_engine_by_name_with_a_fatal_alert` |
| Closing without close_notify is named truncation | 6.1 | `A_tcp_close_with_no_close_notify_is_named_truncation_on_both_roles` |

## 5. Primitives the library or published vectors cover

| # | Standard | Code path | Official vectors | Run on official vectors today? | .NET library or peer comparison | Deviations | On screen? | Status |
|---|---|---|---|---|---|---|---|---|
| 15 | **AES**, FIPS 197 | `Crypto/AesKey.cs` | Appendix C | `A1.aes-ecb` 12 | `A2.aes` 16,667, on CNG | None. Table lookups can leak by cache: stated in `AesKey.cs:8`, and lesson 11 teaches timing | Timing: yes | CONFORMS |
| 16 | **ECB, CBC**, SP 800-38A | `Crypto/Modes.cs`, `Lesson01Aes.cs` | Appendix F | `A1.aes-ecb` 12, `A1.aes-cbc` 4 on `Modes.cs`. F.2.5 is left out, because the PDF text scrambles it | `A2.aes` includes CBC. Two loops sit outside `Modes.cs`: lesson 1's ECB unlock (`Lesson01Aes.cs:212`, `Lesson_1_use_ecb_leaks_in_the_text_and_no_check_fires`) and SSH's old suite CBC (`SshPackets.cs`, `A8.ssh.legacy.*`) | None. Padding method: the document leaves it open | Modes: yes | CONFORMS |
| 17 | **CTR**, SP 800-38A | Two paths. `Modes.Ctr`, with no product caller. `SshPackets.cs:30-37`, the loop lesson 8 runs | Appendix F | `A1.aes-ctr` 6, on `Modes.Ctr` only | `A2.aes` on `Modes.Ctr`, through the library's ECB. **The running SSH loop has live evidence only:** `A8.ssh.modern.*`, `A8.ssh.exe-to-glass-server` | None | Not needed | CONFORMS |
| 18 | **GCM**, SP 800-38D | `Crypto/Gcm.cs`, `Gf128.cs` | NIST CAVP | `A1.aes-gcm` 1,050 | `A2.gcm` 21,000, on CNG | None. The engine builds the 96-bit nonce and 128-bit tag only, and the document allows that. The lab's nonce detector is not part of GCM | Detector: yes, `L1-S09` | CONFORMS |
| 19 | **CMAC**, RFC 4493, SP 800-38B | `Crypto/Cmac.cs` | RFC 4493 section 4 | `A1.cmac` 4 | The library has no CMAC | None | Not needed | CONFORMS |
| 20 | **HMAC**, RFC 2104 | `Crypto/Hmac.cs` | RFC 2202, RFC 4231 | `A1.hmac-md5`, `A1.hmac-sha1`, `A1.hmac-sha256`, `A1.hmac-sha384`, `A1.hmac-sha512`: 37 | `A2.hmac` 10,000, on CNG | None | Not needed | CONFORMS |
| 21 | **HKDF**, RFC 5869 | `Crypto/Hkdf.cs` | Appendix A | `A1.hkdf-sha256` 6, `A1.hkdf-sha1` 8 | `A2.hkdf` 10,000, on CNG | None | Not needed | CONFORMS |
| 22 | **SHA-1, SHA-2**, FIPS 180-4 | `Crypto/Sha1Hash.cs`, `Sha256Hash.cs`, `Sha512Hash.cs`, `BlockHash.cs` | NIST CAVP | `A1.sha1` 340, `A1.sha256` 340, `A1.sha384` 660, `A1.sha512` 660. Short messages and the first 3 long ones. No Monte Carlo set | No A2 clause for hashes | None. SHA-1 is named as weak | Yes, `L8-S13` | CONFORMS |
| 23 | **SHA-3, SHAKE**, FIPS 202 | `Crypto/Keccak.cs`, `Sha3Hash.cs`, `Shake.cs` | NIST CAVP | `A1.sha3-256` 700, `A1.sha3-512` 380, `A1.shake128` 377, `A1.shake256` 313 | No A2 clause | None | Not needed | CONFORMS |
| 24 | **MD5**, RFC 1321 (TLS 1.1 PRF only) | `Crypto/Md5Hash.cs` | Appendix A.5 | `A1.md5` 35 | No A2 clause | None | Not needed | CONFORMS |
| 25 | **DES, Triple DES**, FIPS 46-3, SP 800-67 | `Crypto/Des.cs`, `TdesKey.cs` | NIST CAVP | `A1.tdes` 500 | None | None. No file in `src/NetSec.Core` outside these two calls them | Not needed | CONFORMS |
| 26 | **X25519**, RFC 7748 | `Crypto/X25519.cs`, `Fe25519.cs` | Sections 5.2, 6.1 | `A1.x25519` 8. The 1,000,000 iteration value is not used | The library has none. OpenSSL and Go live | None | Not needed | CONFORMS |
| 27 | **Ed25519**, RFC 8032 | `Crypto/Ed25519.cs`, `Ge25519.cs`, `Sc25519.cs` | Section 7.1 | `A1.ed25519` 25 | The library has none. OpenSSL, Go and OpenSSH live | None | Not needed | CONFORMS |
| 28 | **DH group 14**, RFC 3526 | `Crypto/DhGroup14.cs`, `BigUInt.cs`, `Montgomery.cs` | The group values only | The group: `A1.dh-group14`, from RFC 3526. The shared secrets in that clause are OpenSSL-made | OpenSSL, 9 values. Go in `A8.ssh.legacy.*` | None | Not needed | CONFORMS |
| 29 | **RSA PKCS#1 v1.5**, RFC 8017 | `Crypto/Rsa.cs`, `BigUInt.cs`, `Montgomery.cs`, `Pki/RsaPkcs8.cs`, `Tls11/Tls11RsaKeys.cs` | None used | No. `A1.rsa` 60 values are OpenSSL-made | OpenSSL, live A7. .NET library on key format only: `The_bcl_imports_the_pkcs8_and_exports_the_same_spki` | **Simplification:** class returns false on bad padding, "Do not copy"; the TLS 1.1 server hides this. **Gap:** this warning is not on screen | Key transport weakness: yes, `L7-S05`. Padding warning: no | PATH OK, GAPS |

## 5a. Randomness, across rows

| # | Standard | Code path | Official vectors | Run on official vectors today? | Library or peer cross-check | Deviations | On screen? | Status |
|---|---|---|---|---|---|---|---|---|
| 30 | **Random values**: RFC 8446 appendix C.1, RFC 4346 section 6.2.3.2, SP 800-38A appendix C, SP 800-38D section 8.2.2 | `Platform/SeededRandom.cs` for every Host session (`SessionManager.cs:223`). `Platform.cs:35` wraps the system generator, which `NetSec.Node` and `NetSec.CeDevice` use when they get no seed | Not applicable | Not applicable | `A10a.randoms-differ` on the bridge run | **Gap:** every nonce, IV, TLS random and fresh key share in a lesson comes from a seed, so one seed replays them all. The class comment says "Training use only". This is what makes forks and goldens work | The status bar shows the seed (`App.vue:247`). No text says what it means | PATH OK, GAPS |

## 6. DUKPT in depth

**Which variant.** Lesson 6 runs **AES DUKPT, ANSI X9.24-3-2017**, with an AES-128 base key and AES-128 PIN keys (`Lesson06Dukpt.cs:49-50`). It does not run the TDES form on Steve's Wikipedia page.

**Free sources, checked.** X9 publishes a free supplement: test vectors and Python source. The lead's memory was right. The PDF SHA-256 begins `ae9bb01d`, and it equals the hash in `sources.lock.json`. I read the Python and did not run it. It sets `NUMREG = 32` and `MAX_WORK = 16`, which match the engine. The vectors made from the PDF stay out of git, as `SOURCES.md` says.

**moov-io/dukpt (Steve approved this run).** This is peer interop evidence. It does not prove X9.24 conformance by itself.

| Item | Value |
|---|---|
| Commit | `06e666882e78b91faa13ef0d2ad154de00a92b63` |
| Licence | Apache-2.0 |
| Variants | AES in `pkg/aes` (X9.24-3-2017), TDES in `pkg/des` |
| Where its vectors come from | Its test file cites X9.24-3 "B.1". I checked 3 of its values against the X9 PDF, and all 3 appear there |
| What ran | `pkg/aes` and `pkg`, in a scratch folder, with `GOTOOLCHAIN=local` and the module cache in that folder. The AES path imports `crypto/*`, `encoding/*` and two declared modules. It has no network, no file write, no `init`, no generate step. Nothing went into the repo |
| moov's own tests | `go test ./pkg/aes/ ./pkg/`: ok, ok |

| Comparison with the course, test keys only | Result |
|---|---|
| Lesson 6 golden trace: initial key from its base key | 1 of 1 |
| Lesson 6 golden trace: PIN keys of sales 1 to 4 | 4 of 4 |
| Initial key | 72 of 72 |
| Transaction key | 72 of 72 |
| moov opens a course PIN block | 54 of 54 |
| Course opens a moov PIN block | 54 of 54 |
| CMAC under the MAC generation key | 54 of 54 |
| CMAC under the MAC verification key | 54 of 54 |
| CBC under the data encrypt key | 54 of 54 |
| AES-128 working keys from an AES-256 base key | moov refuses 18 of 18 ("mismatched key length and key type"). The course handles this case, and `A3.vec.aes128-from-aes256` passes on the X9 values |

The 72 rows are 4 key families over 18 counters each, up to `0xFFFF0000`.

**Is moov-io a useful independent check?** Yes, for one thing. It reaches counters the X9 PDF does not list, such as 65,535 and `0xFFFF0000`. Recommendation: Echo may add it as a pinned referee. The X9 vectors stay the source.

**The bug: `L6-C01`.** The claim reads: "If a present derived key is compromised, past and future keys stay uncompromised." It came from Wikipedia. Engine result, after 3 sales:

```
counter 1: from stolen registers False
counter 2: from stolen registers False
counter 3: from stolen registers False
counter 4: from stolen registers True equals real key True
counter 1000: from stolen registers True equals real key True
counter 65536: from stolen registers True equals real key True
```

One leaked working key exposes one sale. Stolen registers expose every later sale, and no earlier sale. The neighbouring text in `L6-S01` is correct, and it says only "past sales".

**The gap: the counter limit.** My model of the X9 Python's state logic (key values left out) and the engine first differ after counter `0x1FFFE`, which has 16 one bits.

| | Next counter | Rule |
|---|---|---|
| X9 Python reference | `0x1FFFF`, 17 one bits | `oneBits <= MAX_WORK` |
| Engine, and moov-io's validity check | `0x20000` | At most 16 one bits |

That is sale 131,071, and no lesson reaches it. The paid standard's text decides this, and I have not read it. `A_counter_at_the_one_bit_limit_with_a_low_bit_clear_skips_the_values_below_that_bit` pins the engine's rule.

## 7. How I know the row list is complete

1. **By directory.** I listed `src/NetSec.Core`. `Crypto`, `Dukpt`, `Pki`, `Tls11`, `Tls13`, `Ssh`, `Auth` map to rows. A script checked that each `.cs` file in those directories is named in this document. These support files belong to a row without being listed in it: `Tls13Messages`, `Tls13Suite` (row 4); `Tls11Codes`, `Tls11Session`, `Tls11Training` (row 7); `SshCodes`, `SshFields`, `SshHostKey`, `SshRows`, `SshKeyBlob` (row 9); `KeyFileReader`, `TrainingPki` (row 12). `Arg`, `ConstantTime`, `Endian`, `Hashes`, `IHash` and `IRandomSource` hold no standard of their own.
2. **By the standards the code names.** I grepped `src/NetSec.Core`, `NetSec.Host`, `NetSec.Node` and `NetSec.CeDevice` for RFC, FIPS, SP 800, X9, ISO, PKCS, JWT, DPoP, WebAuthn and X.509. Each name maps to a row, or to the list below.
3. **By the clauses and the test vectors.** Each A1 to A4 clause maps to a row, and so does the one vector file under `tests/NetSec.Tests/vectors` that is not also a clause.
4. **By the sources of randomness.** Row 30 came from reading how the Host builds a session.

Named in the code, with no row of their own:

| Name | Why |
|---|---|
| RFC 4251, 5656, 7517, 7518, 5208, 5958 | Encoding and key format rules, covered by rows 9, 13, 29 |
| RFC 5746 | Renegotiation signal, inside row 7 |
| RFC 8422 | X25519 in TLS 1.1 ECDHE, inside row 7 |
| RFC 8996, RFC 9325 | Deprecation and key size guidance, not protocols |
| SP 800-131A Rev. 2 | Status of TDEA, in a comment in `TdesKey.cs`. Not read this session, so that comment is UNVERIFIED. It changes no behaviour |
| OpenSSH `PROTOCOL.key` | File format of `OpenSshFile` (`TrainingPki.cs:84`). I read its overall format. `ssh.exe` reading that file in `A8.ssh.exe-to-glass-server` is the evidence |

Directories with no standard: `Bridge` (the course's own composition, lesson 9, tested by A10), `Labs`, `Machine`, `Io`, `Trace`, `Errors`, `Bytes`, `Platform`, `Keys` (the course's own SHAKE256 training keys), `Native` (lesson 11's compare). The frames in lessons 0 to 3 are the course's own format. `NetSec.Vault` uses the .NET library's `AesGcm`, `HKDF` and `SHA256` directly, so it holds no primitive of ours.

## 8. Standards not read

| Standard | Why | What I relied on |
|---|---|---|
| ANSI X9.24-3-2017 | Paid | X9's free vectors and Python, moov-io, Wikipedia as a lead |
| ISO 9564-1 | Paid | X9's PIN block vectors, moov-io |
| FIPS 203, FIPS 180-4, FIPS 202, FIPS 46-3, SP 800-67, SP 800-38B, SP 800-131A, RFC 7748, RFC 8032, RFC 8037, RFC 8017, RFC 8448, RFC 4493, RFC 2104, RFC 5869, RFC 3526, RFC 1321, RFC 4344, RFC 7638, RFC 9449, RFC 5280, RFC 4254, RFC 8731, RFC 8709, strict KEX draft | Free, not read this session | Vectors, the .NET library, live peers, and the section numbers the code cites |

Read this session: FIPS 197 (2001 and upd1), SP 800-38A, SP 800-38D in part, the RFC 8446 sections named in section 4 plus 9.1 and 9.2, RFC 4346 sections 5, 6.2.3.2 and 9, RFC 4253 in part, RFC 4252 in part, RFC 10024 sections 4.2, 4.3 and 7.1, the overall format in `PROTOCOL.key`.

Secondary pages, treated as leads only: Wikipedia and Futurex on DUKPT. False lines from them are in the accuracy sheet (section 5.15), which lives outside this repo.

## 9. Top fixes

| # | Fix | Bucket | Owner |
|---|---|---|---|
| 1 | Rewrite `L6-C01` and name AES DUKPT in lesson 6: one leaked working key exposes one sale, and stolen registers expose later sales | Bug | Richard, then Jared's accuracy pass |
| 2 | One on-screen line in lesson 5: no HelloRetryRequest, no P-256, and no RSA or ECDSA signatures | Gap to simplification | Richard |
| 3 | One on-screen line in lesson 7: no 3DES suite, no resumption, no client certificate. One in lesson 4: no revocation | Gap to simplification | Richard |
| 4 | One on-screen line in lesson 8: no rekey, no password auth, and the algorithms RFC 4253 lists as REQUIRED that it omits | Gap to simplification | Richard |
| 5 | Decide the counter limit from the standard's text, then pin it with a named clause | Gap | Steve, on buying the standard |
| 5a | Fix the five TLS 1.3 receiver checks in section 4, with a test for each | Gap | Jared or Richard |
| 5b | Add a vector clause over the SSH CTR loop, and one over `mlkem768-acvp.txt` | Evidence | Echo |
| 5c | One on-screen line: lessons draw their random bytes from the seed the status bar shows, so a run replays, and a real system must not do this | Gap to simplification | Richard |
| 6 | Build the walk's clauses against the 372 values, using the INVERSE CIPHER runs only | UNVERIFIED | Echo |
| 7 | One on-screen line in lesson 10: which RFC 9449 steps run | Gap to simplification | Richard |

Echo turns each gap above into a clause. A clause can pin the named refusal, such as `A_hello_retry_request_is_refused_by_name`, beside the on-screen line.

## Disposition

Results: rows conforming 19 of 30. Official vectors that a clause ran: 17 of 30 (14 in the repo, 2 fetched at run time, 1 constants only). 1 bug in tour text. No clause or test in this run found a wrong computed value, and the counter limit stays undecided. Recommendation: apply fix 1 now, then fixes 2 to 4, 5c and 7 together as one tour PR, and 5a as one engine PR.
