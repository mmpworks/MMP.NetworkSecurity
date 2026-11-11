# Vector provenance for the TypeScript core tests

Conclusion: each file in this folder is copied from a named source by a script that computes nothing. No value is typed by hand.

These files live here, and not in `acceptance/vectors`, because that folder is pinned and belongs to the acceptance suite.

## Files

| File | Holds | Source | How it was read | Second check |
|---|---|---|---|---|
| `tls12-openssl-rsa.nsv` | One full TLS 1.2 handshake: 7 handshake messages, both random values, the encrypted and the clear pre-master secret, the master secret, both encrypted Finished records, and the RSA test key of the server as numbers | Recorded on 2026-11-11 from OpenSSL 3.5.7 9 Jun 2026 (`s_server` and `s_client` on one machine) | `tools/extract-tls12-openssl.py`: messages from `-msg`, raw records from `-debug`, secrets from `-keylogfile`. The script checks each length and that the key log lines match the capture | `test/tls12.test.ts`: node:crypto `privateDecrypt` gives the pre-master secret; the library gives the master secret of the key log, both `verify_data` values, and opens both records |
| `tls12-openssl-rsa.capture/` | The raw capture: `client.out`, `keylog.txt`, `server.crt` | The same OpenSSL run | Copied as written (git stores the line ends as LF) | The extractor run on this folder gives `tls12-openssl-rsa.nsv` byte for byte (with `server.key` present) |
| `tls13-rfc8448-records.nsv` | 2 protected records of the RFC 8448 section 3 trace, and their payloads | RFC 8448 section 3, `rfc8448.txt` with the SHA-256 in `acceptance/vectors/sources.lock.json` | `tools/extract-rfc8448-records.py`: it uses the text reader of the acceptance suite, which checks each octet count against the RFC | `test/tls13.test.ts`: the keys of the schedule open both records with AES-GCM |

## The TLS 1.2 capture

1. Suite: `TLS_RSA_WITH_AES_128_GCM_SHA256` (0x009c). RSA key transport. Extended master secret off. No session ticket.
2. Key and certificate: `openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 3650 -subj "/CN=tls12.lesson.test"`
3. Server: `openssl s_server -accept 44330 -cert server.crt -key server.key -tls1_2 -cipher AES128-GCM-SHA256 -no_ems -no_ticket -naccept 1 -quiet`
4. Client: `openssl s_client -connect 127.0.0.1:44330 -tls1_2 -cipher AES128-GCM-SHA256 -no_ems -no_ticket -servername tls12.lesson.test -msg -debug -keylogfile keylog.txt`

The RSA key is a test key. It was made for this capture and it protects nothing. Never use it for a real connection.
The key is in the vector file as numbers (`server_n`, `server_e`, `server_d`, and the CRT values). The PEM file is not committed.
A new capture makes new random values and a new key, so it renews every value of the file.

## Rebuild

```
cd src/NetSec.Core.Ts
python -I tools/extract-tls12-openssl.py <capture folder with server.key> test/vectors/tls12-openssl-rsa.nsv "<openssl version text>"
python -I tools/make-tls12-capture.py
python -I tools/extract-rfc8448-records.py ../../acceptance/vectors/_cache/rfc8448.txt
python -I tools/make-rfc8448.py
node --test "test/**/*.test.ts"
```

## Licence

RFC text: IETF Trust. OpenSSL output: produced here.
