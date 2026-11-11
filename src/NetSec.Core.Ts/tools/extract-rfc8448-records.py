"""Makes test/vectors/tls13-rfc8448-records.nsv: 2 protected records of RFC 8448 section 3.

The key schedule values of the same trace are in acceptance/vectors/tls13-rfc8448.nsv. That folder is
pinned and belongs to the acceptance suite, so the records for the AES-GCM check live here.

1. The RFC text must have the SHA-256 that acceptance/vectors/sources.lock.json records.
2. The text reader is the one of the acceptance suite (acceptance/vectors/tools/extract_rfc8448.py), loaded as a module.
   It checks each value against the octet count that the RFC prints.

Run from src/NetSec.Core.Ts:
    python -I tools/extract-rfc8448-records.py <rfc8448.txt>
"""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

here = Path(__file__).resolve().parent.parent
vectors = here.parent.parent / "acceptance" / "vectors"


def main(src: str) -> None:
    raw = Path(src).read_bytes()
    lock = json.loads((vectors / "sources.lock.json").read_text(encoding="utf-8"))["rfc8448.txt"]
    digest = hashlib.sha256(raw).hexdigest()
    if digest != lock["sha256"]:
        sys.exit("SOURCE_CHANGED: rfc8448.txt has sha256 %s, the lock says %s" % (digest, lock["sha256"]))

    spec = importlib.util.spec_from_file_location("extract_rfc8448", vectors / "tools" / "extract_rfc8448.py")
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)

    lines = raw.decode("utf-8").split("\n")
    start = next(i for i, l in enumerate(lines) if l.startswith("3.  Simple 1-RTT Handshake"))
    end = next(i for i, l in enumerate(lines) if l.startswith("4.  Resumed 0-RTT Handshake"))
    blocks = reader.blocks(lines[start:end])

    def get(actor: str, field: str, nth: int) -> str:
        hits = [b for b in blocks if b["actor"] == actor and re.search(r"send handshake record", b["head"]) and field in b["fields"]]
        if len(hits) <= nth:
            sys.exit("not found: %s %s #%d" % (actor, field, nth))
        return reader.hexval(hits[nth]["fields"][field])

    values = [
        # The second record that the server sends: EncryptedExtensions, Certificate, CertificateVerify and Finished in one record.
        ("server_flight_payload", get("server", "payload", 1)),
        ("server_flight_record", get("server", "complete record", 1)),
        # The second record that the client sends: its Finished.
        ("client_finished_payload", get("client", "payload", 1)),
        ("client_finished_record", get("client", "complete record", 1)),
    ]
    text = [
        "# Protected records of RFC 8448 section 3 (simple 1-RTT handshake, TLS_AES_128_GCM_SHA256)",
        "# The RFC text has sha256 %s (acceptance/vectors/sources.lock.json)." % digest,
        "",
        "[tls13-rfc8448-records]",
        "# source: RFC 8448 section 3, the 'send handshake record' blocks: 'payload' and 'complete record'",
        "",
    ]
    text += ["%s = %s" % (k, v) for k, v in values]
    out = here / "test" / "vectors" / "tls13-rfc8448-records.nsv"
    out.write_text("\n".join(text) + "\n", encoding="utf-8", newline="\n")
    print("wrote", out.name, len(values), "values")


if __name__ == "__main__":
    main(sys.argv[1])
