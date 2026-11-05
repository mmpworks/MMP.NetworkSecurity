"""
Reads and edits the Host's practice vault file with the Python standard library, so a clause looks at the file and not at the Host's own report.
Usage: python -I vaultdb.py <command> <path to vault.db>
Commands (each prints one JSON value on stdout; exit 2 when the file is missing):
  audit-rows       every row of the audit table, in seq order
  key-versions     name, version, length of wrapped, for every row of key_versions
  key-versions-full  name, version, nonce and wrapped as hex, for every row of key_versions
  tamper-wrapped   replace the wrapped bytes of every key that is not under exercise/ with zero bytes of the same length; prints the row count
  block-audit      add a trigger that makes every insert into audit fail
  unblock-audit    drop that trigger
  edit-audit       change the detail text of the second audit row, as a person with the file could; prints its seq
Tables as modes-design.md section 4.1 gives them: key_names, key_versions(name, version, nonce, wrapped, ...), audit(seq, at, caller, op, name, version, result, detail, prev_hash).
"""
import json
import os
import sqlite3
import sys


def rows(con, sql):
    cur = con.execute(sql)
    names = [d[0] for d in cur.description]
    return [dict(zip(names, r)) for r in cur.fetchall()]


def main(argv):
    if len(argv) != 3:
        print("usage: vaultdb.py <command> <vault.db>", file=sys.stderr)
        return 64
    cmd, path = argv[1], argv[2]
    if not os.path.isfile(path):
        print(json.dumps({"error": "VAULT_DB_MISSING", "path": path}))
        return 2
    con = sqlite3.connect(path, timeout=20)
    try:
        if cmd == "audit-rows":
            print(json.dumps(rows(con, "SELECT * FROM audit ORDER BY seq"), default=str))
        elif cmd == "key-versions":
            print(json.dumps(rows(con, "SELECT name, version, length(wrapped) AS wrapped_len FROM key_versions ORDER BY name, version"), default=str))
        elif cmd == "key-versions-full":
            out = []
            for name, version, nonce, wrapped in con.execute("SELECT name, version, nonce, wrapped FROM key_versions ORDER BY name, version"):
                out.append({"name": name, "version": version, "nonceHex": (nonce or b"").hex(), "wrappedHex": (wrapped or b"").hex()})
            print(json.dumps(out))
        elif cmd == "tamper-wrapped":
            cur = con.execute("UPDATE key_versions SET wrapped = zeroblob(length(wrapped)) WHERE name NOT LIKE 'exercise/%'")
            con.commit()
            print(json.dumps({"changed": cur.rowcount}))
        elif cmd == "block-audit":
            con.execute("CREATE TRIGGER IF NOT EXISTS acceptance_block_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit blocked by acceptance'); END")
            con.commit()
            print(json.dumps({"blocked": True}))
        elif cmd == "edit-audit":
            row = con.execute("SELECT seq FROM audit ORDER BY seq LIMIT 1 OFFSET 1").fetchone()
            if row is None:
                print(json.dumps({"error": "TOO_FEW_ROWS"}))
                return 3
            con.execute("UPDATE audit SET detail = 'edited by acceptance' WHERE seq = ?", (row[0],))
            con.commit()
            print(json.dumps({"seq": row[0]}))
        elif cmd == "unblock-audit":
            con.execute("DROP TRIGGER IF EXISTS acceptance_block_audit")
            con.commit()
            print(json.dumps({"blocked": False}))
        else:
            print("unknown command " + cmd, file=sys.stderr)
            return 64
    except sqlite3.Error as e:
        print(json.dumps({"error": "SQLITE", "detail": str(e)}))
        return 3
    finally:
        con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
