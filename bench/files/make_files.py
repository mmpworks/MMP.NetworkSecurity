"""Make the AO-9 benchmark file set from a fixed seed, and write files.tsv (name, bytes, sha256). Run: python -I bench/files/make_files.py

Every file is made here or copied from this repository. No file comes from a third party, because the repository is public.
The PNG is a copy of a screen shot already in docs/screens. The run of the benchmark checks each file against files.tsv,
so a changed file fails the run instead of changing the numbers in silence.
"""
import hashlib
import json
import pathlib
import random
import shutil
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SEED = 20261111
PNG_SOURCE = ROOT / "docs" / "screens" / "aes-block-after-ark0-1280.png"

WORDS = ("key block round cipher nonce tag counter pump sale amount card reader terminal batch ledger hash digest "
         "message record layer session secret public private curve point field prime modulus byte word table").split()


def text(rng, n_bytes):
    """Lines of seeded words, wrapped at about 72 characters, until the text holds n_bytes."""
    out, line, size = [], [], 0
    while size < n_bytes:
        line.append(rng.choice(WORDS))
        if len(" ".join(line)) > 72:
            s = " ".join(line) + "\n"
            out.append(s)
            size += len(s)
            line = []
    return "".join(out)[:n_bytes]


def pdf(rng, pages):
    """A small valid PDF 1.4: one Helvetica font, one text stream per page, and a correct cross-reference table."""
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", None, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    kids = []
    for p in range(pages):
        lines = text(rng, 3000).splitlines()[:40]
        body = "BT /F1 10 Tf 50 780 Td 12 TL\n" + "".join(f"({line}) Tj T*\n" for line in lines) + "ET"
        stream = f"<< /Length {len(body)} >>\nstream\n{body}\nendstream"
        objects.append(stream)
        content_id = len(objects)
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>")
        kids.append(f"{len(objects)} 0 R")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {pages} >>"
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("ascii")
    xref = len(out)
    out += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii")
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode("ascii")
    out += f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    return bytes(out)


def csv(rng, rows):
    """Pump sale rows: id, time, pump, grade, litres, price, total, card suffix."""
    lines = ["sale_id,utc,pump,grade,litres,price_per_litre,total,card_last4"]
    for i in range(rows):
        litres = rng.randint(500, 9000) / 100
        price = rng.randint(140, 220) / 100
        lines.append(f"{100000 + i},2026-11-{1 + i % 28:02d}T{i % 24:02d}:{i % 60:02d}:00Z,{1 + i % 12},"
                     f"{rng.choice(('regular', 'plus', 'premium', 'diesel'))},{litres:.2f},{price:.2f},{litres * price:.2f},{rng.randint(0, 9999):04d}")
    return "\n".join(lines) + "\n"


def jsondoc(rng, items):
    """A batch of terminal events, the shape of a small API payload."""
    events = [{"id": i, "terminal": f"T{rng.randint(1, 40):03d}", "kind": rng.choice(("sale", "void", "refund", "settle")),
               "amount_cents": rng.randint(100, 50000), "words": text(rng, 60).strip()} for i in range(items)]
    return json.dumps({"batch": 7, "events": events}, indent=2) + "\n"


def make():
    rng = random.Random(SEED)
    files = {
        "sample.pdf": pdf(rng, 24),
        "sample.txt": text(rng, 64 * 1024).encode("ascii"),
        "sample.csv": csv(rng, 3000).encode("ascii"),
        "sample.json": jsondoc(rng, 400).encode("ascii"),
        "small-1k.bin": rng.randbytes(1024),
        "large-4mib.bin": rng.randbytes(4 * 1024 * 1024 + 7),  # +7, so the large file ends in a partial block
    }
    for name, data in files.items():
        (HERE / name).write_bytes(data)
    shutil.copyfile(PNG_SOURCE, HERE / "sample.png")
    names = sorted(list(files) + ["sample.png"])
    rows = ["name\tbytes\tsha256"]
    for name in names:
        data = (HERE / name).read_bytes()
        rows.append(f"{name}\t{len(data)}\t{hashlib.sha256(data).hexdigest()}")
    (HERE / "files.tsv").write_text("\n".join(rows) + "\n", encoding="ascii", newline="\n")
    print("\n".join(rows))
    return 0


if __name__ == "__main__":
    sys.exit(make())
