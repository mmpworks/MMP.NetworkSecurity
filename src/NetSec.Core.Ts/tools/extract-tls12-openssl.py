"""Makes test/vectors/tls12-openssl-rsa.nsv from one recorded OpenSSL TLS 1.2 handshake.

Input folder (the capture):
  client.out   output of `openssl s_client ... -msg -debug` (handshake messages and raw socket bytes)
  keylog.txt   output of `-keylogfile` (the RSA line has the pre-master secret, CLIENT_RANDOM has the master secret)
  server.key   the RSA test key of the server (PEM). It was made for this capture only.

Run from src/NetSec.Core.Ts:
    python -I tools/extract-tls12-openssl.py test/vectors/tls12-openssl-rsa.capture test/vectors/tls12-openssl-rsa.nsv "<openssl version text>"
The capture folder must also hold server.key for this step. That file is not committed.

The script copies bytes. It computes nothing, so the vector file shares no code with the library under test.
The private key goes into the file as numbers (n, e, d, p, q, dp, dq, qi), the same way acceptance/vectors/rsa-openssl.nsv holds its keys.
"""
import base64
import os
import re
import sys

MSG = re.compile(r"^(>>>|<<<) TLS 1\.2, Handshake \[length ([0-9a-f]{4})\], (\w+)")
RAW = re.compile(r"^(write to|read from) 0x[0-9a-f]+ \[0x[0-9a-f]+\] \((\d+) bytes => (\d+)")
DUMP = re.compile(r"^[0-9a-f]{4} - ")

NAMES = {
    "ClientHello": "client_hello",
    "ServerHello": "server_hello",
    "Certificate": "certificate",
    "ServerHelloDone": "server_hello_done",
    "ClientKeyExchange": "client_key_exchange",
}


def read_capture(path):
    """Returns (messages, raw). messages: [(direction, name, bytes)]. raw: [(direction, bytes)]."""
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    messages, raw = [], []
    i = 0
    while i < len(lines):
        m = MSG.match(lines[i])
        r = RAW.match(lines[i])
        if m:
            want = int(m.group(2), 16)
            data = bytearray()
            i += 1
            while i < len(lines) and lines[i].startswith("    ") and len(data) < want:
                data += bytes.fromhex(lines[i].strip().replace(" ", ""))
                i += 1
            if len(data) != want:
                raise SystemExit("MESSAGE_LENGTH %s: have %d, want %d" % (m.group(3), len(data), want))
            messages.append((m.group(1), m.group(3), bytes(data)))
            continue
        if r:
            want = int(r.group(3))
            data = bytearray()
            i += 1
            while i < len(lines) and DUMP.match(lines[i]):
                data += bytes.fromhex(lines[i][7:55].replace("-", " ").replace(" ", ""))
                i += 1
            if len(data) != want:
                raise SystemExit("RAW_LENGTH: have %d, want %d" % (len(data), want))
            raw.append(("out" if r.group(1) == "write to" else "in", bytes(data)))
            continue
        i += 1
    return messages, raw


def records(stream):
    """Splits a byte stream into TLS records (5-byte header and body)."""
    out, at = [], 0
    while at + 5 <= len(stream):
        size = int.from_bytes(stream[at + 3:at + 5], "big")
        out.append(stream[at:at + 5 + size])
        at += 5 + size
    if at != len(stream):
        raise SystemExit("RECORD_SPLIT: %d bytes left" % (len(stream) - at))
    return out


def finished_record(stream):
    """The first handshake record after the ChangeCipherSpec record: the encrypted Finished."""
    recs = records(stream)
    for k, rec in enumerate(recs):
        if rec[0] == 0x14:
            nxt = recs[k + 1]
            if nxt[0] != 0x16:
                raise SystemExit("NO_FINISHED_AFTER_CCS")
            return nxt
    raise SystemExit("NO_CCS")


def der_ints(der):
    """The INTEGER values of the RSAPrivateKey inside a PKCS#8 or PKCS#1 key, in order."""
    def tlv(buf, at):
        tag = buf[at]
        size = buf[at + 1]
        at += 2
        if size & 0x80:
            n = size & 0x7F
            size = int.from_bytes(buf[at:at + n], "big")
            at += n
        return tag, buf[at:at + size], at + size

    tag, body, _ = tlv(der, 0)
    if tag != 0x30:
        raise SystemExit("KEY_FORMAT")
    items, at = [], 0
    while at < len(body):
        tag, val, at = tlv(body, at)
        items.append((tag, val))
    # PKCS#8: version, algorithm, OCTET STRING with the RSAPrivateKey.
    if len(items) >= 3 and items[2][0] == 0x04:
        return der_ints(items[2][1])
    return [int.from_bytes(v, "big") for t, v in items if t == 0x02]


def hexint(n):
    h = "%x" % n
    return h if len(h) % 2 == 0 else "0" + h


def main():
    cap, out, version = sys.argv[1], sys.argv[2], sys.argv[3]
    messages, raw = read_capture(os.path.join(cap, "client.out"))
    values = []
    finished = {}
    for direction, name, data in messages:
        if name == "Finished":
            finished["client_finished" if direction == ">>>" else "server_finished"] = data
        elif name in NAMES:
            values.append((NAMES[name], data))
    for key in ("client_finished", "server_finished"):
        values.append((key, finished[key]))
    by = dict(values)
    if len(by) != 7:
        raise SystemExit("MESSAGE_COUNT %d" % len(by))

    values.append(("client_random", by["client_hello"][6:38]))
    values.append(("server_random", by["server_hello"][6:38]))
    cke = by["client_key_exchange"]
    enc = cke[6:]
    if int.from_bytes(cke[4:6], "big") != len(enc):
        raise SystemExit("CKE_LENGTH")
    values.append(("encrypted_pre_master", enc))

    pre = master = None
    for line in open(os.path.join(cap, "keylog.txt"), encoding="utf-8"):
        parts = line.split()
        if len(parts) == 3 and parts[0] == "RSA":
            if bytes.fromhex(parts[1]) != enc[:8]:
                raise SystemExit("KEYLOG_RSA_MISMATCH")
            pre = bytes.fromhex(parts[2])
        if len(parts) == 3 and parts[0] == "CLIENT_RANDOM":
            if bytes.fromhex(parts[1]) != by["client_hello"][6:38]:
                raise SystemExit("KEYLOG_RANDOM_MISMATCH")
            master = bytes.fromhex(parts[2])
    if pre is None or master is None or len(pre) != 48 or len(master) != 48:
        raise SystemExit("KEYLOG_INCOMPLETE")
    values.append(("pre_master", pre))
    values.append(("master_secret", master))

    sent = b"".join(d for way, d in raw if way == "out")
    got = b"".join(d for way, d in raw if way == "in")
    values.append(("client_finished_record", finished_record(sent)))
    values.append(("server_finished_record", finished_record(got)))

    pem = open(os.path.join(cap, "server.key"), encoding="ascii").read()
    der = base64.b64decode("".join(l for l in pem.splitlines() if not l.startswith("-----")))
    ints = der_ints(der)
    if len(ints) != 9 or ints[0] != 0:
        raise SystemExit("KEY_PARTS %d" % len(ints))
    key = list(zip(("n", "e", "d", "p", "q", "dp", "dq", "qi"), ints[1:]))
    if key[3][1] * key[4][1] != key[0][1]:
        raise SystemExit("KEY_PRODUCT")

    lines = [
        "# One TLS 1.2 handshake recorded from %s" % version,
        "# TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c), RSA key transport, extended master secret off, no session ticket.",
        "# Server: openssl s_server -accept 44330 -cert server.crt -key server.key -tls1_2 -cipher AES128-GCM-SHA256 -no_ems -no_ticket -naccept 1 -quiet",
        "# Client: openssl s_client -connect 127.0.0.1:44330 -tls1_2 -cipher AES128-GCM-SHA256 -no_ems -no_ticket -servername tls12.lesson.test -msg -debug -keylogfile keylog.txt",
        "# Recorded 2026-11-11. The RSA key is a test key made for this capture. Never use it for a real connection.",
        "",
        "[tls12-openssl-rsa]",
        "# source: produced by %s (s_server and s_client on one machine); messages from -msg, records from -debug, secrets from -keylogfile" % version,
        "",
    ]
    for name, data in values:
        lines.append("%s = %s" % (name, data.hex()))
    for name, n in key:
        lines.append("server_%s = %s" % (name, hexint(n)))
    open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    print("wrote %s: %d values" % (out, len(values) + len(key)))


if __name__ == "__main__":
    main()
