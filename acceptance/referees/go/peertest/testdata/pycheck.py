# A second opinion for the BCL oracle, on the Python standard library only. It
# reads one JSON request per line and writes one JSON response per line, with the
# same field names as the oracle. Python has no HKDF, so this file writes out the
# two RFC 5869 steps over hmac.
import hashlib
import hmac
import json
import sys


def from_hex(request, name):
    return bytes.fromhex(request.get(name, ""))


def run_hash(request):
    digest = hashlib.new(request["alg"].replace("-", "_"), from_hex(request, "data"))
    if request["alg"].startswith("shake"):
        return {"digest": digest.hexdigest(request["length"])}
    return {"digest": digest.hexdigest()}


def run_hmac(request):
    mac = hmac.new(from_hex(request, "key"), from_hex(request, "data"), request["alg"])
    return {"mac": mac.hexdigest()}


def run_hkdf(request):
    alg = request["alg"]
    size = hashlib.new(alg).digest_size
    salt = from_hex(request, "salt") or bytes(size)
    prk = hmac.new(salt, from_hex(request, "ikm"), alg).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < request["length"]:
        block = hmac.new(prk, block + from_hex(request, "info") + bytes([counter]), alg).digest()
        okm += block
        counter += 1
    return {"okm": okm[: request["length"]].hex()}


OPERATIONS = {"hash": run_hash, "hmac": run_hmac, "hkdf": run_hkdf}

for line in sys.stdin:
    request = json.loads(line)
    print(json.dumps(OPERATIONS[request["op"]](request)), flush=True)
