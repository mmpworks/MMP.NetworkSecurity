# Referees

These tools are the outside referees for `acceptance/` (PRD D10, D11). They share no code with the product. They use standard libraries only, plus `golang.org/x/crypto` v0.58.0 for SSH. A builder never writes in this folder.

Each tool was tested against a peer it shares no code with, except the `sshpeer` client mode (see "Known limits").

## Build and test

```
cd acceptance/referees/go
go build -o bin/ ./...
go test ./peertest/ -count=1

dotnet build acceptance/referees/bcl -c Release
```

The tests generate all keys at run time, in temp folders. The repo holds no key.

## Common rules

1. All listeners default to `127.0.0.1:0`.
2. A server prints its port as the first stdout line. Later lines are JSON, one object per line.
3. A failure prints `{"event":"error","code":"<NAME>","detail":"..."}`. Branch on `code`.
4. Exit codes: 0 means success, 1 means a named rejection, 2 means a usage error (code `USAGE`).
5. `-naccept N` ends a server after N connections. The default is 0, which means run until killed.

## Command lines

### tlspeer

`tlspeer` is a TLS 1.3 client and server on `crypto/tls`.

```
tlspeer -mode server [-listen a:p] [-groups x25519|x25519mlkem768] -cert F -key F
        [-ca F -require-client-cert] [-relay h:p] [-keylog F] [-naccept N]
tlspeer -mode client -connect h:p (-ca F | -insecure) [-groups G] [-cert F -key F]
        [-server-name N] [-relay h:p] [-keylog F]
```

1. The default group is `x25519mlkem768`. The tool pins TLS 1.3 and one group.
2. After a handshake it prints this line. The values come from `ConnectionState`.
   `{"event":"handshake","role":"server","version":"TLS 1.3","versionCode":772,"suite":"TLS_AES_128_GCM_SHA256","suiteCode":4865,"curveID":"X25519MLKEM768","curveIDCode":4588,"peerSubject":"CN=..."}`
3. A server then echoes. A client then joins the session to stdin and stdout. `-relay` sends the session to a TCP address instead.
4. Codes: `TLS_HANDSHAKE_FAILED`, `TLS_CERT_VERIFY_FAILED`, `TLS_CLIENT_CERT_MISSING`, `TLS_RECORD_FAILED`, `TCP_CONNECT_FAILED`, `RELAY_CONNECT_FAILED`.
5. A client with no `-ca` and no `-insecure` is a usage error. A run never uses the machine's trust store.

### sshpeer

`sshpeer` is an SSH-2 server and client on `x/crypto/ssh`.

```
sshpeer [-mode server] -host-key F -authorized F [-listen a:p] [-kex L] [-cipher L] [-mac L]
        [-host-key-alg L] [-allow-tunnel h:p,h:p] [-naccept N]
sshpeer -mode client -connect h:p -identity F -known-host F (-exec "echo hi" | -tunnel h:p)
        [-user training] [-kex L] [-cipher L] [-mac L] [-host-key-alg L]
```

1. The server authenticates by public key only. It accepts any user name.
2. The server answers one exec command, `echo`, inside its own process. It starts no shell and no process. Any other command exits 127. Shell, pty, and subsystem requests are refused.
3. A tunnel opens only to a target named in `-allow-tunnel`. Each attempt prints `{"event":"tunnel","target":"h:p","allowed":true}`.
4. The handshake line holds `kex`, `hostKey`, `cipherC2S`, `macC2S`, `cipherS2C`, `macS2C`, `user`, and `peerVersion`.
5. Client codes: `HOST_KEY_CHANGED`, `HOST_KEY_UNKNOWN`, `SSH_AUTH_FAILED`, `SSH_HANDSHAKE_FAILED`, `TCP_CONNECT_FAILED`, `TUNNEL_REFUSED`, `EXEC_FAILED`.
6. `-known-host` is a known_hosts file. A non-default port uses the form `[127.0.0.1]:2222`.
7. `-exec` writes the handshake line, then the command output. `-tunnel` writes the handshake line, then joins the channel to stdin and stdout.

The legacy suite:

```
sshpeer -host-key rsa.key -authorized user.pub -kex diffie-hellman-group14-sha1 -cipher aes128-cbc -mac hmac-sha1 -host-key-alg ssh-rsa
```

The library refused nothing in this suite. It needs each name listed, and `sshpeer` lists them through the flags. Without `-host-key-alg`, an RSA key offers `rsa-sha2-256`, `rsa-sha2-512`, and `ssh-rsa`, and the client picks. That is the design section 9 form. Add the flag to force `ssh-rsa`.

### gogateway

`gogateway` terminates SSH from the device and opens TLS 1.3 to the next hop. It forwards bytes unopened.

```
gogateway -host-key F -authorized F -next h:p (-ca F | -insecure)
          [-groups x25519mlkem768] [-kex L] [-cipher L] [-mac L] [-host-key-alg L]
          [-cert F -key F] [-server-name N] [-keylog F] [-listen a:p] [-naccept N]
```

1. Each `direct-tcpip` channel becomes one TLS session to `-next`. The target the device asks for appears in `{"event":"channel","target":"h:p"}` and is otherwise ignored.
2. A next hop that refuses the group gets a named error, and the device's channel is rejected.
3. The gateway offers no sessions.

### tap

`tap` is a referee and not a teaching tool. It lets the suite compare the wire with the app's trace from outside the app. The app has its own decoder for learners.

```
tap -listen a:p -to h:p -log hop.hex [-flip-at N] [-flip-dir c2s|s2c] [-naccept N]
```

The log has one record per line, and each record is written before its bytes are forwarded:

```
<conn> <c2s|s2c> <offset> <hex>
# flip conn=<conn> dir=<c2s|s2c> offset=<offset> from=<hex> to=<hex>
```

1. `conn` counts from 1. `offset` counts from 0, per connection and per direction.
2. The log starts empty at each start of `tap`.
3. `-flip-at N` inverts one byte (XOR 0xFF). `-flip-dir` selects the direction, and the default is `c2s`.
4. The flip happens once per process. A product that reconnects gets a clean stream, so the suite sees the first failure.
5. The hex holds the bytes as forwarded. After a flip, the record holds what the receiver got, and the flip line holds the original.

### tokenverify

```
tokenverify -pub issuer.pub -token <jws>
tokenverify -mode dpop -token <proof> -htm POST -htu https://h/p [-now UNIX] [-max-age 60]
            [-nonce S] [-access-token T] [-jkt T] [-seen FILE]
```

1. `-pub` takes PEM (SPKI) or a JWK.
2. The jws mode checks the signature and the header (EdDSA, no `crit`). It prints the payload. It does not read `exp` or `aud`. The suite checks claim policy from the payload.
3. Jws codes: `TOKEN_OK`, `TOKEN_MALFORMED`, `TOKEN_BAD_ALG`, `TOKEN_BAD_HEADER`, `TOKEN_BAD_SIGNATURE`.
4. The dpop mode runs the RFC 9449 section 4.3 checks, except check 1 (one header field), which belongs to an HTTP server. It accepts EdDSA and ES256.
5. Dpop codes: `DPOP_OK`, `DPOP_MALFORMED`, `DPOP_MISSING_CLAIM`, `DPOP_BAD_TYP`, `DPOP_BAD_ALG`, `DPOP_BAD_JWK`, `DPOP_BAD_SIGNATURE`, `DPOP_HTM_MISMATCH`, `DPOP_HTU_MISMATCH`, `DPOP_NONCE_MISMATCH`, `DPOP_IAT_WINDOW`, `DPOP_ATH_MISMATCH`, `DPOP_JKT_MISMATCH`, `DPOP_REPLAY`.
6. `-seen` keeps used proof ids in a file, so replay detection spans separate runs. A proof that fails another check does not use up its id.

### BCL oracle

The oracle is a .NET 10 console program. It reads one JSON request per line and writes one JSON response per line. Byte values are lowercase hex. An optional `id` comes back unchanged.

```
{"id":1,"op":"hash","alg":"sha256","data":"616263"}
{"id":1,"ok":true,"digest":"ba7816bf..."}
```

| `op` | Fields | Result fields |
|---|---|---|
| `info` | none | `runtime`, `mlkem`, `sha3`, `shake` |
| `hash` | `alg` (`md5`, `sha1`, `sha256`, `sha384`, `sha512`, `sha3-256`, `sha3-384`, `sha3-512`, `shake128`, `shake256`), `data`, `length` for shake | `digest` |
| `hmac` | `alg` (`sha1`, `sha256`, `sha384`, `sha512`), `key`, `data` | `mac` |
| `hkdf` | `alg`, `ikm`, `length`, optional `salt`, `info` | `okm` |
| `rsa-keygen` | `bits` | `n`, `e`, `d`, `p`, `q`, `dp`, `dq`, `qi` |
| `rsa-sign`, `rsa-verify` | the key fields, `alg` (sha1, sha256), `data`, and `signature` to verify | `output` (the signature, or 1 or 0) |
| `rsa-encrypt`, `rsa-decrypt` | the key fields, `data` | `output` (PKCS#1 v1.5) |
| `hkdf-extract` | `alg`, `ikm`, optional `salt` | `prk` |
| `hkdf-expand` | `alg`, `prk`, `length`, optional `info` | `okm` |
| `aes-ecb-encrypt`, `aes-ecb-decrypt` | `key`, `data`, optional `padding` (`none`, `pkcs7`) | `output` |
| `aes-cbc-encrypt`, `aes-cbc-decrypt` | `key`, `iv`, `data`, optional `padding` | `output` |
| `aes-gcm-encrypt` | `key`, `nonce`, `data`, optional `aad`, `tagLength` | `output`, `tag` |
| `aes-gcm-decrypt` | `key`, `nonce`, `data`, `tag`, optional `aad` | `output` |
| `mlkem768-keygen` | `seed` (64 bytes, d then z) | `ek`, `dk` |
| `mlkem768-encaps` | `ek` | `ciphertext`, `secret` |
| `mlkem768-decaps` | `seed` or `dk`, `ciphertext` | `secret` |

Error codes: `UNKNOWN_OP`, `UNKNOWN_ALG`, `BAD_REQUEST`, `GCM_TAG_MISMATCH`, `CRYPTO_ERROR`. The default padding is `none`.

## Notes for the acceptance author

1. **Add `-rev` or `-www` to each `openssl s_server` command in design section 9.** On Windows, plain `s_server` reads stdin in its main loop.
   - With an idle stdin pipe, the handshake never finishes. `TestOpenSSLServerHangsOnIdleStdinWithoutRev` pins this.
   - With a closed stdin, the server stops at the first connection.
   - With `-rev` or `-www`, an idle pipe works. `-rev` also gives an echo, with each line reversed.
2. **`-quiet` hides the port.** `s_server -accept 0` prints the port in its `ACCEPT` line, as in `ACCEPT [::]:55617`, and `-quiet` removes that line.
3. **The A6 key log comparison must allow for `EXPORTER_SECRET`.** Go writes 4 secret lines. OpenSSL writes the same 4, plus `EXPORTER_SECRET`, plus a comment line. The product's log can hold 4 or 5 lines.
4. **`s_client` prints the group in two forms.** It prints `Negotiated TLS1.3 group: X25519MLKEM768` for the hybrid and `Peer Temp Key: X25519, 253 bits` for X25519.
5. **Git Bash rewrites `/CN=x`** in an argument to a Windows program. Set `MSYS_NO_PATHCONV=1`, or start the program from PowerShell or Go.
6. **`SYSLIB5006` is not needed.** `MLKem` compiled on SDK 10.0.204 without the pragma, with warnings as errors.
7. **The BCL has no encapsulation with a chosen message.** `mlkem768-encaps` always draws its own randomness. A2 can test in both directions, but a fixed FIPS 203 encapsulation vector cannot run through this oracle.
8. **The BCL has no X25519 or Ed25519 API,** so the oracle has no operation for them.

## Peer pairings

| Referee | Peer | Status |
|---|---|---|
| `tlspeer` server | OpenSSL 3.5.7 `s_client`, both groups | Works. Both sides report the group. The key logs match |
| `tlspeer` client | OpenSSL 3.5.7 `s_server`, both groups | Works. The key logs match |
| `tlspeer` mutual TLS | OpenSSL 3.5.7 `s_client` with and without a certificate | Works |
| `sshpeer` server | `ssh.exe` 9.5p2: exec, `-L`, changed host key, modern and legacy suites | Works. `ssh.exe -v` confirms the algorithm names |
| `sshpeer` client | `sshpeer` server only | Not independent. See below |
| `tap` | Byte comparison in the test process, both directions, 1 MiB and 700 KB | Works |
| `gogateway` | `ssh.exe` to `tlspeer`, with a `tap` on each hop | Works. `tlspeer` is the same library family as the gateway's TLS client |
| `tokenverify` jws | RFC 8037 A.4 vector, OpenSSL Ed25519 signature | Works |
| `tokenverify` dpop | RFC 9449 figures 2 and 13, with the published `jkt` and `ath` | Works |
| BCL hash, HMAC, HKDF | Python `hashlib` and `hmac`, published vectors | Works |
| BCL HKDF | Go `crypto/hkdf` | Works |
| BCL AES modes | Go `crypto/aes`, FIPS 197, GCM spec test case 2 | Works |
| BCL ML-KEM-768 | Go `crypto/mlkem`, both directions, plus implicit rejection | Works |

## Known limits

1. **The `sshpeer` client mode has no independent server on this machine.** The machine has no `sshd`, and Git for Windows ships none. The client tests pair it with `sshpeer`'s own server. They prove the flags and the named errors. They do not prove interoperability with another SSH implementation. The changed-key behaviour is proved independently only from `ssh.exe` against the server mode.
2. **`gogateway` next-hop TLS was tested against `tlspeer`.** `tlspeer` server mode is proved against OpenSSL separately, but the pair in the test both use `crypto/tls`.
3. **`tokenverify` does not read claims in the jws mode,** and the dpop mode does not see HTTP headers.
4. **The tests run on Windows.** The peer paths and `icacls` are Windows forms. The referees themselves are portable Go, but they are untested elsewhere.

## Routine calls made

1. The module path is `mmpworks.local/netsec/referees`. It is local only and resolves through no proxy.
2. The flip inverts all 8 bits (XOR 0xFF), because the brief says "flips one byte".
3. `-flip-at` fires once per process, because the brief says "one byte". The added `-flip-dir` selects the direction, with `c2s` as the default.
4. `-host-key-alg`, `-naccept`, `-listen`, `-connect`, `-server-name`, and `-insecure` are additions to design section 9. Every design command line still works as written.
5. The `tokenverify` dpop mode also accepts ES256, because the RFC 9449 published vectors use it. Only EdDSA and ES256 pass the `alg` check.
6. `bcl/` holds its own `Directory.Build.props` and `Directory.Build.targets`. They stop MSBuild from picking up the C# 3 settings a later repo-root file may set.
7. The Go tests fail, and do not skip, when a pinned peer is missing or reports another version. A skip would hide a lost anchor.
