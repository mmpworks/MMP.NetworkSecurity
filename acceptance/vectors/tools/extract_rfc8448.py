"""Builds tls13-rfc8448.nsv from section 3 of RFC 8448 (the simple 1-RTT handshake trace).

Every value is read from the RFC text and its declared octet count is checked.
The suite uses the values to test the TLS 1.3 key schedule (A4) byte for byte.

Run: python -I extract_rfc8448.py <rfc8448.txt> <out file>
"""
import re
import sys


def blocks(lines):
    """Split the trace into blocks. A block starts at '   {actor}  text' and holds 'name (N octets):  hex' fields."""
    out, cur = [], None
    field = None
    for ln in lines:
        if re.match(r"^(Thomson|RFC 8448)\s", ln) or ln.startswith("\f"):
            continue
        m = re.match(r"^   \{(client|server)\}  (.*)$", ln)
        if m:
            cur = {"actor": m.group(1), "head": m.group(2), "fields": {}}
            out.append(cur)
            field = None
            continue
        if cur is None:
            continue
        m = re.match(r"^      ([A-Za-z0-9 _]+?)(?: \((\d+) octets\))?:\s*(.*)$", ln)
        if m:
            name, count, rest = m.group(1), m.group(2), m.group(3)
            field = [name, int(count) if count else None, rest]
            cur["fields"][name] = field
            continue
        if field is not None and re.match(r"^         [0-9a-f]{2}( |$)", ln):
            field[2] += " " + ln.strip()
        elif ln.strip() != "":
            field = None
    return out


def hexval(field):
    name, count, rest = field
    rest = rest.strip()
    if rest.startswith("(empty)"):
        data = ""
    else:
        toks = rest.split()
        if not all(re.fullmatch(r"[0-9a-f]{2}", t) for t in toks):
            sys.exit("field %s is not plain hex: %s" % (name, rest[:60]))
        data = "".join(toks)
    if count is not None and len(data) // 2 != count:
        sys.exit("field %s: %d octets read, RFC says %d" % (name, len(data) // 2, count))
    return data


def main(src, out_path):
    lines = open(src, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if l.startswith("3.  Simple 1-RTT Handshake"))
    end = next(i for i, l in enumerate(lines) if l.startswith("4.  Resumed 0-RTT Handshake"))
    bl = blocks(lines[start:end])

    def get(actor, head_re, field, nth=0):
        hits = [b for b in bl if b["actor"] == actor and re.search(head_re, b["head"]) and field in b["fields"]]
        if len(hits) <= nth:
            sys.exit("not found: %s %s %s #%d" % (actor, head_re, field, nth))
        return hexval(hits[nth]["fields"][field])

    rec = []

    def put(name, value):
        rec.append((name, value))

    put("client_private", get("client", r"create an ephemeral x25519", "private key"))
    put("client_public", get("client", r"create an ephemeral x25519", "public key"))
    put("server_private", get("server", r"create an ephemeral x25519", "private key"))
    put("server_public", get("server", r"create an ephemeral x25519", "public key"))
    put("client_hello", get("client", r"construct a ClientHello", "ClientHello"))
    put("server_hello", get("server", r"construct a ServerHello", "ServerHello"))
    put("encrypted_extensions", get("server", r"construct an EncryptedExtensions", "EncryptedExtensions"))
    put("certificate", get("server", r"construct a Certificate handshake", "Certificate"))
    put("certificate_verify", get("server", r"construct a CertificateVerify", "CertificateVerify"))
    put("server_finished", get("server", r"construct a Finished handshake", "Finished"))
    put("client_finished", get("client", r"construct a Finished handshake", "Finished"))
    put("early_salt_is_zero", "00")
    put("early_ikm", get("server", r'extract secret "early"', "IKM"))
    put("early_secret", get("server", r'extract secret "early"', "secret"))
    put("empty_hash", get("server", r'derive secret for handshake "tls13 derived"', "hash"))
    put("derived_for_handshake", get("server", r'derive secret for handshake "tls13 derived"', "expanded"))
    put("ecdhe_shared", get("server", r'extract secret "handshake"', "IKM"))
    put("handshake_secret", get("server", r'extract secret "handshake"', "secret"))
    put("hash_client_hello_to_server_hello", get("server", r'derive secret "tls13 c hs traffic"', "hash"))
    put("c_hs_traffic", get("server", r'derive secret "tls13 c hs traffic"', "expanded"))
    put("s_hs_traffic", get("server", r'derive secret "tls13 s hs traffic"', "expanded"))
    put("derived_for_master", get("server", r'derive secret for master "tls13 derived"', "expanded"))
    put("master_secret", get("server", r'extract secret "master"', "secret"))
    put("s_hs_key", get("server", r"derive write traffic keys for handshake data", "key expanded"))
    put("s_hs_iv", get("server", r"derive write traffic keys for handshake data", "iv expanded"))
    put("s_finished_key", get("server", r'calculate finished "tls13 finished"', "expanded"))
    put("s_finished_verify_data", get("server", r'calculate finished "tls13 finished"', "finished"))
    put("hash_to_server_finished", get("server", r'derive secret "tls13 c ap traffic"', "hash"))
    put("c_ap_traffic", get("server", r'derive secret "tls13 c ap traffic"', "expanded"))
    put("s_ap_traffic", get("server", r'derive secret "tls13 s ap traffic"', "expanded"))
    put("exp_master", get("server", r'derive secret "tls13 exp master"', "expanded"))
    put("s_ap_key", get("server", r"derive write traffic keys for application data", "key expanded"))
    put("s_ap_iv", get("server", r"derive write traffic keys for application data", "iv expanded"))
    put("c_finished_key", get("client", r'calculate finished "tls13 finished":', "expanded"))
    put("c_finished_verify_data", get("client", r'calculate finished "tls13 finished":', "finished"))
    put("c_ap_key", get("client", r"derive write traffic keys for application data", "key expanded"))
    put("c_ap_iv", get("client", r"derive write traffic keys for application data", "iv expanded"))
    put("hash_to_client_finished", get("client", r'derive secret "tls13 res master"', "hash"))
    put("res_master", get("client", r'derive secret "tls13 res master"', "expanded"))
    put("resumption_secret", get("server", r'generate resumption secret "tls13 resumption"', "expanded"))
    put("ticket_nonce", get("server", r'generate resumption secret "tls13 resumption"', "hash"))

    text = ["# TLS 1.3 key schedule values, RFC 8448 section 3 (simple 1-RTT handshake, TLS_AES_128_GCM_SHA256, x25519)", "",
            "[tls13-rfc8448-1rtt]", "# source: RFC 8448 section 3", ""]
    text += ["%s = %s" % (k, v) for k, v in rec]
    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(text) + "\n")
    print("wrote", out_path, len(rec), "values")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
