"""
The fake Host's practice vault, a real SQLite file with the tables of modes-design.md section 4.1, so the clauses can read and edit it.
Usage: python -I fakevault.py <db> <command> [args]
  init
  put <name> <version> <wrapped hex>
  get <name> <version>               prints the wrapped bytes as hex, or - when the row is missing
  audit <caller> <op> <name> <version> <result> <detail>    prints seq; exit 3 when the insert fails
  rows                                prints the audit rows as JSON
"""
import hashlib
import json
import os
import sqlite3
import sys

ZERO = "0" * 64


def main(argv):
    db, cmd, args = argv[1], argv[2], argv[3:]
    os.makedirs(os.path.dirname(db), exist_ok=True)
    con = sqlite3.connect(db, timeout=20)
    try:
        if cmd == "init":
            con.executescript(
                "CREATE TABLE IF NOT EXISTS key_names(name TEXT PRIMARY KEY, algorithm TEXT, exportable INTEGER, allowed_ops TEXT, provenance TEXT, created_at TEXT);"
                "CREATE TABLE IF NOT EXISTS key_versions(name TEXT, version INTEGER, nonce BLOB, wrapped BLOB, public_key BLOB, fingerprint TEXT, state TEXT, created_at TEXT, PRIMARY KEY(name, version));"
                "CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, caller TEXT, op TEXT, name TEXT, version TEXT, result TEXT, detail TEXT, prev_hash TEXT);")
            con.commit()
        elif cmd == "put":
            con.execute("INSERT OR REPLACE INTO key_versions(name, version, nonce, wrapped, state, created_at) VALUES(?,?,?,?,?,datetime('now'))",
                        (args[0], int(args[1]), b"\0" * 12, bytes.fromhex(args[2]), "active"))
            con.commit()
        elif cmd == "get":
            r = con.execute("SELECT wrapped FROM key_versions WHERE name=? AND version=?", (args[0], int(args[1]))).fetchone()
            print(r[0].hex() if r else "-")
        elif cmd == "audit":
            caller, op, name, version, result, detail = args
            last = con.execute("SELECT seq, at, caller, op, name, version, result, detail, prev_hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = hashlib.sha256("|".join(str(x) for x in last).encode()).hexdigest() if last else ZERO
            cur = con.execute("INSERT INTO audit(at, caller, op, name, version, result, detail, prev_hash) VALUES(datetime('now'),?,?,?,?,?,?,?)",
                              (caller, op, name, version, result, detail, prev))
            con.commit()
            print(cur.lastrowid)
        elif cmd == "rows":
            cur = con.execute("SELECT * FROM audit ORDER BY seq")
            names = [d[0] for d in cur.description]
            print(json.dumps([dict(zip(names, r)) for r in cur.fetchall()], default=str))
        else:
            return 64
    except sqlite3.Error as e:
        print("SQLITE " + str(e), file=sys.stderr)
        return 3
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
