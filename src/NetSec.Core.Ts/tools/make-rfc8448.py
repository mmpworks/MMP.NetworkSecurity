"""Write src/rfc8448.ts from acceptance/vectors/tls13-rfc8448.nsv.

The bytes go file to file: no value is typed by hand. Run from src/NetSec.Core.Ts:
    python -I tools/make-rfc8448.py
"""
import re
from pathlib import Path

here = Path(__file__).resolve().parent.parent
nsv = here.parent.parent / "acceptance" / "vectors" / "tls13-rfc8448.nsv"
values: dict[str, str] = {}
for line in nsv.read_text(encoding="utf-8").splitlines():
    m = re.match(r"^([a-z_0-9]+) = ([0-9a-f]*)$", line.strip())
    if m:
        values[m.group(1)] = m.group(2)

KEYS = [
    ("clientPrivate", "client_private"),
    ("clientPublic", "client_public"),
    ("serverPrivate", "server_private"),
    ("serverPublic", "server_public"),
    ("ecdheShared", "ecdhe_shared"),
    ("clientHello", "client_hello"),
    ("serverHello", "server_hello"),
    ("encryptedExtensions", "encrypted_extensions"),
    ("certificate", "certificate"),
    ("certificateVerify", "certificate_verify"),
    ("serverFinished", "server_finished"),
    ("clientFinished", "client_finished"),
    ("ticketNonce", "ticket_nonce"),
]


def chunks(hexstr: str, n: int = 96) -> str:
    parts = [hexstr[i : i + n] for i in range(0, len(hexstr), n)] or [""]
    return " +\n    ".join(f"'{p}'" for p in parts)


out = [
    "/**",
    " * The simple 1-RTT handshake of RFC 8448 section 3 (TLS_AES_128_GCM_SHA256, x25519), as hex.",
    " *",
    " * Made by tools/make-rfc8448.py from acceptance/vectors/tls13-rfc8448.nsv. Do not edit by hand.",
    " * RFC 8448 is by M. Thomson, 2019. The trace bytes are quoted from it under the IETF Trust terms.",
    " */",
    "export const RFC8448 = Object.freeze({",
]
for name, key in KEYS:
    out.append(f"  {name}:\n    {chunks(values[key])},")
out.append("} as const)")
out.append("")
(here / "src" / "rfc8448.ts").write_text("\n".join(out), encoding="utf-8", newline="\n")
print("wrote src/rfc8448.ts with", len(KEYS), "values")
