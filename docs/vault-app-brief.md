# App brief: the vault page and the vault exercise screens

For Nancy. The Host side is built in PR #125 (slice V1). This brief gives the wire facts. The screen words, the layout and the test ids are already in `docs/wizards-ux.md` section 5.5 and section 9 (ids row "Vault exercise"). Use those words as written.

## 1. What to build

1. **The vault page.** It opens from the map footer (`sec-vault-exercise`). It shows the vault's key list and the audit list. It carries the statement in section 4.
2. **The exercise, three screens:** `vault-sign-derive`, `vault-refuse`, `vault-audit` (`docs/wizards-ux.md` 5.5).
3. **Not a lab.** The exercise has no tour file, no trace stream, and no session. It changes no mode and no key a lesson uses. `GET /api/lessons` does not list it.

## 2. Routes

All routes take and give JSON. A refusal is HTTP 409 or 503 with `{ code, message, retryable, requestId }`. Branch on `code`, never on `message`.

| Route | Body | Reply on success |
|---|---|---|
| `GET /api/security/vault/keys` | | `{ keys: [ { name, algorithm, exportable, allowedOps[], provenance, versions, fingerprint, hidden?, publicHex? } ] }` |
| `GET /api/security/vault/audit?after=N` | | `{ rows: [ { seq, at, caller, op, name, version?, result, detail, prev_hash } ] }`, at most 500 rows after `seq` N |
| `POST /api/security/vault/exercise/sign` | `{ text }` | `{ keyName, version, inputHex, signatureHex, publicKeyHex, command, output, code }` |
| `POST /api/security/vault/exercise/derive` | `{ label }` | `{ keyName, version, label, outputHex, code }` |
| `POST /api/security/vault/exercise/export` | `{}` | Always refused: HTTP 409, `code: VAULT_EXPORT_REFUSED` |
| `POST /api/security/vault/exercise/audit-check` | `{}` | `{ rows[], firstBadSeq, code }`. `firstBadSeq` is 0 while the chain is whole |

Field notes:

1. `hidden` is `"non-exportable"` on the two exercise keys and absent on flow keys. A key with `hidden` shows its fingerprint only, even with Show keys ON, with the line in section 4.
2. `publicHex` is present for Ed25519 keys. `exercise/derive` has none, and its `fingerprint` reads `check:` and six hex digits.
3. The key list never holds key bytes. Flow keys (`token.issuer`, `device.enrolment`) are listed by their type id.
4. `code` is `"OK"` on success. Sign gives `REFEREE_MISSING` when OpenSSL is not on the machine. The signature is still made, and `output` says why no check ran.
5. `command` and `output` on sign are the real OpenSSL command and its real output. Show both in code blocks, as every Check screen does (`docs/wizards-ux.md` section 6).
6. `firstBadSeq` names the row whose `prev_hash` no longer fits the row before it. When a person edits row N, the check names row N + 1. Say "row N + 1 does not fit the row before it", never "row N + 1 was changed".
7. Audit `caller` values the learner will see: `host/vault-setup` (made the exercise keys), `host/vault-exercise` (the three screens), `host/lab-<n>` (a lesson took a flow key), `host/key-route` (the key view read a flow key), `host/flow-my-login` (a flow placed a key), `host/flow` (a flow's review or check read a key). Show the caller as given. These rows are not attacks.
8. Derive returns `outputHex`. The screen in 5.5 shows a fingerprint per derived key. Make it in the app as `SHA256:` plus the unpadded base64 of SHA-256 over the `outputHex` bytes, the format the Host uses for public keys. Show `outputHex` itself only while Show keys is ON.

## 3. Codes and the words for each

| Code | Where | HTTP | Words on screen |
|---|---|---|---|
| `VAULT_EXPORT_REFUSED` | Refuse screen, every time | 409 | "The vault refused. This key cannot be read out." (`docs/wizards-ux.md` 5.5). Show the code beside it |
| `VAULT_AUDIT_FAILED` | Any exercise call | 503 | "The vault could not write down this request, so it refused it. Try again." `retryable` is true |
| `VAULT_UNWRAP_FAILED` | Key view of a flow key, a lesson start | 409 | "The key could not open what it locked. Make the keys again." (`docs/wizards-ux.md` 5.4, the lesson-keys flow) |
| `VAULT_OP_REFUSED` | No screen sends it | 409 | "This key may not do that. A key's use is fixed when it is made." |
| `REFEREE_MISSING` | Sign, in `code` | 200 | Show `output` as given. It names `NETSEC_OPENSSL` |

`VAULT_AUDIT_FAILED` has no words in `docs/wizards-ux.md` yet. The line above is my draft. Check it against Heather's copy rules before you ship it.

## 4. Lines that must show

1. On the vault page: "Practice vault. Not an HSM. Not FIPS validated. Non-export is a rule in our code. Anyone can open the SQLite file and read the wrapped key." (`docs/modes-design.md` section 4.1)
2. Beside every key with `hidden: "non-exportable"`, word for word: "The course refuses to show it. A real HSM would refuse too. These files could still open it here." (`docs/modes-design.md` section 6)
3. On the Derive station: "A typed label stands in for a key serial number. This is the idea behind DUKPT. It is not DUKPT." (`docs/wizards-ux.md` 5.5)
4. First line of `vault-sign-derive`: "Use test keys only. This course shows your keys on screen and in saved files."

## 5. Clauses that judge it

1. `A17.vault.exercise-walk` runs the routes today and passes on #125. It names Playwright too, so it can grow a UI walk on your ids.
2. `A17.ui.vault-exercise` (`docs/wizards-ux.md` section 9): the 3 screens show sign, derive, refuse and audit results, and refuse names `VAULT_EXPORT_REFUSED`.
3. `A17.ui.first-screen-line`: `vault-sign-derive` shows the test-keys line first.

## 6. How to try it

1. Start the Host from the #125 branch: `dotnet run --project src/NetSec.Host -c Release`. Its first line reads `HOST-READY port=<port> token=<token>`.
2. `curl -s -X POST http://127.0.0.1:<port>/api/security/vault/exercise/sign -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d "{\"text\":\"hi\"}"` gives a full sign reply. With no token the Host answers 401 `HOST_TOKEN_REFUSED`.
3. `NETSEC_SECURITY_DIR` points the Host at a throwaway folder, so a test run never touches your own `.security/`.

Questions on the routes go to Richard (`richard-modes`).
