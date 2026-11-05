# Referee contract

Conclusion: the suite starts the referees under `acceptance/referees` and reads what they print. This file lists the command lines, the output
lines and the exit codes the suite expects. Jared writes the referees (`referees/go`, `referees/bcl`). The Go and BCL programs did not exist when
the suite was written, so this file is the suite's expectation. If a referee differs, change this file and `acceptance/lib/Harness/Referees.cs`
in one pull request to `acceptance/`. A clause whose referee is missing is NOT RUN REFEREE_MISSING, by name.

## 1. Build

| Referee | Build command (run by `run.ps1`) | Output the suite uses |
|---|---|---|
| Go programs | `go build -o <work>\referees\go\bin\ ./...` in `acceptance/referees/go` (needs `go.mod`) | `tlspeer.exe`, `sshpeer.exe`, `gogateway.exe`, `tap.exe`, `tokenverify.exe` |
| BCL oracle | `dotnet build acceptance/referees/bcl/<project>.csproj -c Release -o <work>\referees\bcl` | the DLL named in the `*.runtimeconfig.json`, started with `dotnet <dll>` |

Pinned system tools: `C:\Program Files\Git\mingw64\bin\openssl.exe` must print `OpenSSL 3.5.7`, and `C:\Windows\System32\OpenSSH\ssh.exe` must print `OpenSSH_for_Windows_9.5p2`. A different version is NOT RUN REFEREE_VERSION.

## 2. Rules for every Go program

1. Listen on 127.0.0.1 only. Port 0 means a free port.
2. A program that listens prints `LISTEN 127.0.0.1:<port>` as soon as it can accept, and flushes stdout.
3. A program exits 0 when its one connection ends cleanly. It prints `ERR <text>` and exits non-zero on a failure.
4. Output lines are plain text, one per line, in the formats below. Extra lines are allowed.

## 3. Programs

| Program | Command line | Behavior and output |
|---|---|---|
| `tlspeer` server | `-mode server -listen 127.0.0.1:0 -groups x25519\|x25519mlkem768 -cert srv.pem -key srv.key [-relay 127.0.0.1:B]` | TLS 1.3 only, offers only the named group. After the handshake prints `STATE version=TLS13 suite=<name> group=<name>`, where group is the Go curve name (`X25519` or `X25519MLKEM768`). Without `-relay` it writes back every byte it reads. With `-relay B` it copies every byte it reads to 127.0.0.1:B |
| `tlspeer` client | `-mode client -connect 127.0.0.1:P -groups x25519\|x25519mlkem768 -ca root.pem -servername localhost -send hello` | Verifies the server certificate against `root.pem`. Prints the same `STATE` line, sends `hello` and a newline, prints `RECV <text>` for the echo, and exits 0 |
| `sshpeer` | `-listen 127.0.0.1:0 -host-key <file> -authorized <file> -kex curve25519-sha256\|diffie-hellman-group14-sha1 [-cipher aes128-ctr\|aes128-cbc] [-mac hmac-sha2-256\|hmac-sha1] -allow-tunnel 127.0.0.1:Q` | SSH-2 server. The host key file is an OpenSSH private key (Ed25519) or PKCS#8 PEM (RSA). `-authorized` is an `authorized_keys` file; any user name is accepted with a listed key. Offers only the named algorithms. After key exchange prints `NEGOTIATED kex=<name> cipher=<name> mac=<name> hostkey=<ssh-ed25519\|ssh-rsa>`. A `session` channel with an `exec` request for text C sends `EXEC:<C>` and a newline as channel data, then exit status 0 and EOF. A `direct-tcpip` request to the allowed target copies bytes both ways to that TCP port. Any other target gets "administratively prohibited" |
| `gogateway` | `-listen 127.0.0.1:0 -host-key <file> -authorized <file> -kex ... -cipher ... -mac ... -upstream 127.0.0.1:P -upstream-ca root.pem -upstream-name localhost -groups x25519mlkem768` | An `sshpeer`-like SSH server (prints `LISTEN` and `NEGOTIATED`). It copies the data of the first channel the client opens, unopened, over TLS 1.3 to the upstream and prints `UPSTREAM group=<name>` |
| `tap` | `-listen 127.0.0.1:A -to 127.0.0.1:B -log <file> [-flip-at N]` | Relays one connection. Appends one line to the log for every chunk, in arrival order and flushed: `C2S <hex>` for client to server, `S2C <hex>` for server to client. `-flip-at N` XORs 0x01 into byte N (counted from 0) of the client-to-server stream, once. Prints `LISTEN 127.0.0.1:A` |
| `tokenverify` | `-pub <file> -token <compact JWS>` | The file holds the 32-byte Ed25519 public key as 64 hex digits. Exit 0 and `OK <claims json>` when the EdDSA signature holds. Exit 1 and `REJECT <reason>` otherwise |

The suite uses these key files: the Ed25519 host key and the client authorization come from the training keys (`ITrainingKey`), so `sshpeer`
presents the host key the glass client trusts. A second run presents `attacker-ed25519` to test the changed host key.

## 4. BCL oracle (stdin and stdout)

The program prints `READY bcl-oracle/1 <runtime version>` first. Each request is one line: an operation name, then arguments separated by one
space. Binary arguments are hex; an empty value is `-`. The reply is one line: `OK <result> [<result>]` or `ERR <CODE>`. The program ends when stdin closes.

| Request | Reply |
|---|---|
| `aes-ecb <key> <data> enc\|dec` | `OK <data>`. No padding. Data is a whole number of blocks |
| `aes-cbc <key> <iv> <data> enc\|dec` | `OK <data>`. No padding |
| `aes-ctr <key> <counter16> <data>` | `OK <data>`. The 16-byte counter block increments as a big-endian number |
| `gcm-seal <key> <nonce12> <aad> <plaintext>` | `OK <ciphertext followed by 16-byte tag>` |
| `gcm-open <key> <nonce12> <aad> <ciphertext+tag>` | `OK <plaintext>` or `ERR AUTH` |
| `hmac sha256\|sha384\|sha512 <key> <data>` | `OK <mac>` |
| `hkdf sha256\|sha384\|sha512 <ikm> <salt> <info> <length>` | `OK <okm>` |
| `mlkem768-keygen` | `OK <encapsulation key> <decapsulation key>`. FIPS 203 encodings, 1184 and 2400 bytes |
| `mlkem768-encaps <encapsulation key>` | `OK <ciphertext> <shared secret>` |
| `mlkem768-decaps <decapsulation key> <ciphertext>` | `OK <shared secret>` |

A2 sends 10,000 requests for each of AES, HMAC, HKDF and GCM, and 200 rounds of each ML-KEM direction, over one process.
