"""Builds the tampered copies of ledger.ndjson. Reads the key and the ledger. Runs no verifier.

Run from this folder, after gen-fixture wrote ledger.ndjson, seal-pub.pem and ikm.bin.
"""
import base64
import hashlib
import hmac
import json
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).parent
IKM = (HERE / "ikm.bin").read_bytes()
NEW_EVENT = b'{"event":"demo","seq":2,"edited":true}'
EDITED_ROW = 2


def dump(obj):
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()


def b64(raw):
    return base64.b64encode(raw).decode()


def event_key(label, entry_id):
    """HKDF-SHA-256 (RFC 5869): salt is the tenant label, info is the entry ID."""
    prk = hmac.new(label.encode(), IKM, hashlib.sha256).digest()
    return hmac.new(prk, entry_id.encode() + b"\x01", hashlib.sha256).digest()


def entry_hash(entry):
    return b64(hashlib.sha256(dump({**entry, "entry_hash": ""})).digest())


def leaf(payload):
    return hashlib.sha256(b"\x00" + payload).digest()


def tree(nodes):
    """RFC 6962: split at the largest power of 2 below the node count."""
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    return hashlib.sha256(b"\x01" + tree(nodes[:k]) + tree(nodes[k:])).digest()


def root(entries):
    return b64(tree([leaf(base64.b64decode(e["event_payload_jcs"])) for e in entries]))


def write(name, entries, seal):
    lines = [dump(row) for row in entries + [seal]]
    (HERE / name).write_bytes(b"\n".join(lines) + b"\n")


def rewrite(entries):
    """What a key holder can do: edit one event, then make a new tag and link for every row after it."""
    out, prev = [], ""
    for i, entry in enumerate(entries):
        row = dict(entry)
        if i == EDITED_ROW:
            row["event_payload_jcs"] = b64(NEW_EVENT)
            key = event_key(row["tenant_binding_kdf_label"], row["entry_id"])
            row["hmac_sha256"] = b64(hmac.new(key, NEW_EVENT, hashlib.sha256).digest())
        row["prev_hash"] = prev
        row["entry_hash"] = entry_hash(row)
        prev = row["entry_hash"]
        out.append(row)
    return out


def sign_with_own_key(seal, entries):
    """What a key holder cannot do with the real signing key: this signs with a new key of their own."""
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (HERE / "own-key-pub.pem").write_bytes(pem)
    signed = {**seal, "merkle_root": root(entries), "signature_ed25519": "",
              "signing_key_fingerprint": "sha256:" + hashlib.sha256(raw).hexdigest()}
    signed["signature_ed25519"] = b64(private.sign(dump(signed)))
    return signed


rows = [json.loads(line) for line in (HERE / "ledger.ndjson").read_text(encoding="utf-8").splitlines()]
entries, seal = rows[:-1], rows[-1]

# Control on this script: with no edit, it must produce the same hashes, tags and root as the verifier's generator.
assert all(entry_hash(e) == e["entry_hash"] for e in entries), "entry hash differs"
assert root(entries) == seal["merkle_root"], "root differs"
for e in entries:
    key = event_key(e["tenant_binding_kdf_label"], e["entry_id"])
    assert b64(hmac.new(key, base64.b64decode(e["event_payload_jcs"]), hashlib.sha256).digest()) == e["hmac_sha256"], "tag differs"

changed = rewrite(entries)
write("cut-last.ndjson", entries[:-1], seal)
write("rewrite-old-seal.ndjson", changed, seal)
write("rewrite-new-root.ndjson", changed, {**seal, "merkle_root": root(changed)})
write("rewrite-own-signature.ndjson", changed, sign_with_own_key(seal, changed))
print("control holds: this script reproduces every hash, tag and the root on the unedited ledger")
