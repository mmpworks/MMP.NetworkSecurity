"""Write src/tls12capture.ts from test/vectors/tls12-openssl-rsa.nsv.

The bytes go file to file: no value is typed by hand. Run from src/NetSec.Core.Ts:
    python -I tools/make-tls12-capture.py

The private key of the server stays in the vector file. The lesson does not need it:
the pre-master secret comes from the key log of the capture.
"""
import re
from pathlib import Path

here = Path(__file__).resolve().parent.parent
nsv = here / "test" / "vectors" / "tls12-openssl-rsa.nsv"
values: dict[str, str] = {}
for line in nsv.read_text(encoding="utf-8").splitlines():
    m = re.match(r"^([a-z_0-9]+) = ([0-9a-f]*)$", line.strip())
    if m:
        values[m.group(1)] = m.group(2)

KEYS = [
    ("clientHello", "client_hello"),
    ("serverHello", "server_hello"),
    ("certificate", "certificate"),
    ("serverHelloDone", "server_hello_done"),
    ("clientKeyExchange", "client_key_exchange"),
    ("clientFinished", "client_finished"),
    ("serverFinished", "server_finished"),
    ("preMaster", "pre_master"),
    ("clientFinishedRecord", "client_finished_record"),
    ("serverFinishedRecord", "server_finished_record"),
]


def chunks(hexstr: str, n: int = 96) -> str:
    parts = [hexstr[i : i + n] for i in range(0, len(hexstr), n)] or [""]
    return " +\n    ".join(f"'{p}'" for p in parts)


out = [
    "/**",
    " * One full TLS 1.2 handshake (TLS_RSA_WITH_AES_128_GCM_SHA256, RSA key transport, no extended master secret), as hex.",
    " *",
    " * Made by tools/make-tls12-capture.py from test/vectors/tls12-openssl-rsa.nsv. Do not edit by hand.",
    " * The bytes were recorded on 2026-11-11 from OpenSSL 3.5.7 (s_server and s_client on one machine).",
    " * The server key is a test key made for this capture. `preMaster` is the secret that the key log of the capture records.",
    " */",
    "export const TLS12_CAPTURE = Object.freeze({",
]
for name, key in KEYS:
    out.append(f"  {name}:\n    {chunks(values[key])},")
out.append("} as const)")
out.append("")
(here / "src" / "tls12capture.ts").write_text("\n".join(out), encoding="utf-8", newline="\n")
print("wrote src/tls12capture.ts with", len(KEYS), "values")
