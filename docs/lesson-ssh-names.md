# Lesson 8: names the SSH lab emits

Status: stable. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05.

`docs/lessons-1-3-names.md` holds the rules for arrows, binds, fields, forks, and the end of a run. They all apply here. This file lists what is new.

## Shape of a run

Protocol `ssh`. Lanes `client`, `server`. One session holds two rounds on two sockets. The server role answers from a fixed table and starts no process.

| Round | Stream ids | Suite | Does |
|---|---|---|---|
| 1, modern | `<session>/client/ssh`, `<session>/server/ssh` | `curve25519-sha256`, `aes128-ctr`, `hmac-sha2-256`, `ssh-ed25519` | Exec, then a tunnel |
| 2, legacy | `<session>/client/ssh-legacy`, `<session>/server/ssh-legacy` | `diffie-hellman-group14-sha1`, `aes128-cbc`, `hmac-sha1`, `ssh-rsa` | Exec |

Bind a step to round 2 by its own message (`KexdhInit`, `KexdhReply`), or by the event types `ssh.weak.*`. Other message names repeat in round 2, and a bind takes the first match.

## Messages, in order

| Order | `message` | Direction | Clear on the wire |
|---|---|---|---|
| 1 | `VersionLine` | c to s, then s to c | Yes |
| 2 | `KexInit` | both | Yes |
| 3 | `KexEcdhInit` (round 1) or `KexdhInit` (round 2) | c to s | Yes |
| 4 | `KexEcdhReply` (round 1) or `KexdhReply` (round 2) | s to c | Yes |
| 5 | `NewKeys` | both | Yes |
| 6 | `ServiceRequest` | c to s | No, and neither is anything below |
| 7 | `ServiceAccept` | s to c | |
| 8 | `UserauthQuery` | c to s | |
| 9 | `UserauthPkOk` | s to c | |
| 10 | `UserauthSigned` | c to s | |
| 11 | `UserauthSuccess` | s to c | |
| 12 | `ChannelOpenSession` | c to s | |
| 13 | `ChannelOpenConfirmation` | s to c | |
| 14 | `ChannelRequestExec` | c to s | |
| 15 | `ChannelSuccess` | s to c | |
| 16 | `ChannelData` | s to c (`hello`) | |
| 17 | `ChannelRequestExitStatus`, `ChannelEof`, `ChannelClose` | s to c | |
| 18 | `ChannelClose` | c to s | |
| 19 | `ChannelOpenTunnel` (round 1 only) | c to s | |
| 20 | `ChannelOpenConfirmation` | s to c | |
| 21 | `ChannelData` | c to s, then s to c | |
| 22 | `ChannelEof` c to s, then `ChannelEof`, `ChannelClose` s to c, then `ChannelClose` c to s | | |
| 23 | `Disconnect` | c to s | |

Other names can appear with a referee: `UserauthFailure`, `UserauthBanner`, `ChannelOpenFailure`, `ChannelFailure`, `ChannelWindowAdjust`, `ChannelExtendedData`, `GlobalRequest`, `RequestFailure`, `Ignore`, `Debug`, `Unimplemented`.

## Fields

Offsets index `wire`, as in the other lessons.

| Message state | Fields in order |
|---|---|
| `VersionLine` | `versionLine` |
| Clear packet | `packetLength`, `paddingLength`, `messageType`, then the body fields below, then `padding` |
| Protected packet | `encryptedPacket` (`visibleToWire` false), `mac` (`visibleToWire` true). SSH encrypts the length field too, so the field is hidden. TCP segments and timing can still show packet sizes |

| Clear message | Body fields |
|---|---|
| `KexInit` | `cookie`, `kexAlgorithms`, `hostKeyAlgorithms`, `ciphersC2S`, `ciphersS2C`, `macsC2S`, `macsS2C`, `compressionC2S`, `compressionS2C`, `languagesC2S`, `languagesS2C`, `firstKexPacketFollows`, `reserved` |
| `KexEcdhInit` | `clientShare` |
| `KexEcdhReply` | `hostKey`, `serverShare`, `exchangeSignature` |
| `KexdhInit` | `dhE` |
| `KexdhReply` | `hostKey`, `dhF`, `exchangeSignature` |
| `NewKeys` | none |

`plain` holds the packet payload on every packet event, and the line on `VersionLine`.

## Events

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `ssh.message.sent`, `wire.sent` | sender | as above | |
| `ssh.message.received` | receiver | as above | `plain` after the unlock |
| `ssh.hostkey.seen` | `client` | `SHA256:<base64>`, the OpenSSH fingerprint form | The host key card |
| `ssh.hostkey.first-use` | `client` | The same fingerprint | Only when a caller turns on trust on first use. The default is a refusal, `SSH_HOST_KEY_UNKNOWN`. The lab pins its key, so the lab does not emit it |
| `ssh.kex.strict` | `client`, `server` | `on` or `off` | `on` when both sides offer strict KEX (draft-miller-sshm-strict-kex). Both rounds of the lab show `on` |
| `ssh.exec.exit` | `client` | The exit status, as text | `0` for `echo hello` |
| `ssh.weak.exchange-hash`, `ssh.weak.host-signature`, `ssh.weak.cipher-mode` | `client`, `server` | One short sentence that says what is weak | Round 2 only |
| `secret.derived` | `client`, `server` | none | `secrets[]`, one per event, with the names below |
| `keys.installed` | `client`, `server` | `<cipher>,<mac>,c2s` or `<cipher>,<mac>,s2c` | |
| `check.result` | checker | check name | `check.id`, `check.result`, `check.code` |
| `state.waiting` | waiter | none | `waiting.actor` |

| Secret name | Bytes | From |
|---|---|---|
| `ssh.ephemeral.private` | 32 in round 1, 64 in round 2 | Random |
| `ssh.shared.K` | 32 in round 1, 256 in round 2 | The private part and the peer share |
| `ssh.exchange.H` | 32 in round 1, 20 in round 2 | Both version lines, both `KexInit`, the host key, both shares, K |
| `ssh.session.id` | Same as H | The first H |
| `ssh.iv.c2s`, `ssh.iv.s2c` | 16 | K, H, letter A or B, session id |
| `ssh.key.c2s`, `ssh.key.s2c` | 16 | K, H, letter C or D, session id |
| `ssh.mac.c2s`, `ssh.mac.s2c` | 32 in round 1, 20 in round 2 | K, H, letter E or F, session id |

| Check name | `actor` | Failure code |
|---|---|---|
| `algorithm match` | both | `SSH_NO_COMMON_ALG` |
| `known_hosts match` | `client` | `SSH_HOST_KEY_CHANGED`, `SSH_HOST_KEY_UNKNOWN`, `SSH_HOST_KEY_REVOKED` |
| `host key shape` | `client` | `SSH_HOST_KEY_BAD` |
| `x25519 result not zero` | both | `SSH_KEX_ZERO_SECRET` |
| `exchange signature` | `client` | `SSH_EXCHANGE_SIGNATURE` |
| `packet MAC` | receiver. One passing event per direction, before the first protected packet's `ssh.message.received`. The check runs on every packet, and later passes stay quiet | `SSH_PACKET_MAC` |
| `packet length` | receiver | `SSH_PACKET_LENGTH` |
| `userauth accepted` | `client` | `SSH_AUTH_REFUSED` |
| `userauth signature verify` | `server` | `SSH_AUTH_REFUSED` |
| `exec accepted` | `client` | `SSH_EXEC_REFUSED`, for a refused command or a refused session channel |
| `tunnel allow list` | `server`, which decides (RFC 4254 section 7.2) | `SSH_TUNNEL_REFUSED` |
| `tunnel accepted` | `client`, which only reports the server's answer | `SSH_TUNNEL_REFUSED` |
| `channel number known` | both | `SSH_CHANNEL_UNKNOWN` |
| `channel window` | both | `SSH_CHANNEL_WINDOW` |
| `no rekey in this lab` | both | `SSH_REKEY_UNSUPPORTED` |
| `version line` | both | `SSH_VERSION` |
| `strict kex` | both | `SSH_KEX_STRICT` |
| `channel send queue` | both | `SSH_CHANNEL_QUEUE_FULL` |
| `channel limit` | both | `SSH_CHANNEL_LIMIT` |
| `userauth tries` | `server` | `SSH_AUTH_TRIES` |
| `sequence number` | both | `SSH_SEQUENCE_EXHAUSTED` |
| `peer stayed until the end` | both | `SSH_PEER_DISCONNECT`, `PEER_CLOSED_EARLY` |

## Attacks

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L8-change-host-key` | The server presents another host key. The client's pinned key stays the same | `Rejected` | `SSH_HOST_KEY_CHANGED` | `known_hosts match` |
| `L8-flip-exchange-signature` | Flips one byte of the signature in `KexEcdhReply` | `Rejected` | `SSH_EXCHANGE_SIGNATURE` | `exchange signature` |
| `L8-zero-share` | The server sends an all-zero X25519 share, so both sides would get a secret anyone can compute | `Rejected` | `SSH_KEX_ZERO_SECRET` | `x25519 result not zero` |
| `L8-flip-packet` | Flips one byte of protected `UserauthSigned` | `Rejected` | `SSH_PACKET_MAC` | `packet MAC` |
| `L8-wrong-user-key` | The client names the allowed public key and signs with another private key | `Rejected` | `SSH_AUTH_REFUSED` | `userauth signature verify` |
| `L8-refused-tunnel` | The client asks for `bank.lab:1433`. The allow list holds only `echo.lab:7` | `Rejected` | `SSH_TUNNEL_REFUSED` | `tunnel allow list` |
| `L8-legacy-flip-signature` | Flips one byte of the RSA signature in `KexdhReply`. Round 1 passes first | `Rejected` | `SSH_EXCHANGE_SIGNATURE` | `exchange signature` |

Try-it actions are the same as `docs/lessons-1-3-names.md`. Use `run-attack` with an id above. `expect` is `{ "type": "check", "name": "<check name>", "result": "fail" }`.

## What the tour must state

1. The legacy suite is shown for the old device. SHA-1 has known collision attacks, and `ssh-rsa` signs with SHA-1. `aes128-cbc` with a MAC over the plain text has a published plaintext recovery attack (Albrecht, Paterson and Watson, 2009). The `ssh.weak.*` events say this at the moment it applies.
2. HMAC-SHA-1 has no known practical break. Do not call it broken. It is old, and the modern suite replaces it.
3. Nothing here has run on real CE. The wording is "CF-compiled, run on the desktop CLR, never run on CE".
4. A host key is trusted because the client pinned it earlier. The first connect has no proof at all, so the fingerprint card is the moment to check it another way.
5. The lab's SSH server has a fixed table of two commands, `echo` and `whoami`. It starts no process.
6. The name `Modern` means "newer than the legacy suite". The suite has no encrypt-then-MAC mode, and it is no claim of the best SSH can do.
7. Terrapin (CVE-2023-48795) removes a packet from the start of the protected stream. Both rounds run strict KEX, because the glass client and server both offer it. A peer that does not offer it leaves strict KEX off, and `ssh.kex.strict` says `off`. These two suites still stop the prefix attack then, because the MAC covers the plain text and a deleted packet moves the cipher stream. Jared's sweep on the engine before strict KEX: 0 of 4,000 accepted on each suite. An injected `Ignore` can still kill such a session.
8. A channel holds no more than its window of unread bytes. The window opens again only when the reader reads, so a stalled reader makes the sender wait. That wait has a limit: a sender parked on the window looks silent, so the 30 s read deadline ends the whole session. The same deadline ends an idle tunnel.
9. A ninth channel is refused by name, and the session and its other channels go on.
10. **The old device path has a limit.** No peer without the strict KEX marker has run here, and nothing has run on CE. Steve's CE device is likely that kind of peer. This machine holds no such peer, and no download is allowed. Windows `ssh.exe` 9.5p2 and Go `x/crypto` v0.58.0 offer the marker, by the runs below. Git `ssh` 10.3p1 and PuTTY `plink` 0.80 are the other clients found. They are newer than the Terrapin fix by version, and neither ran here. Two things did run. Our own code with the marker off ran against our own code, on both suites. Against outside code, one side had the marker off and the outside peer offered it, so both ran the old rules: `ssh.exe` against our server, and our client against Go. So the old rules hold against outside code, and a real old peer stays unproved.
