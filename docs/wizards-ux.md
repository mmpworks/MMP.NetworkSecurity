# MMP.NetworkSecurity: setup wizards, UX design

Author: Nancy. Date: 2026-11-05. Status: design for review, no product code. Branch `docs/wizards-ux`, off `docs/security-modes` (`d124d62`).
Inputs: `docs/modes-design.md` (sections 1, 2, 6, 8, 10), `docs/ux-design.md`, Steve's request (quoted in section 0). `docs/modes-real-world.md` from Jared was not on `origin` or in `E:\dev\ns-modes-real` when this was written, and I asked `jared-referees` for it. The accuracy limits here come from `modes-design.md` 1.6, 1.8, 6.3 and 8.5, which quote Jared's findings. Section 12 lists what to recheck when his file lands.

## Conclusion

1. **One Security setup screen holds 15 rows, one per switchable type. A wizard opens from a row, or from a lesson that refuses to start.** The Host's step machine owns every move. The UI draws the step it is given and sends the learner's answer back.
2. **The learner starts from a goal, not from a list.** "I want to run lesson 10 with my own keys" makes the Host list the types lesson 10 needs, in dependency order. Nobody has to learn all 15 types first.
3. **Every screen answers five questions in the same order:** what is this, why does it exist in the real world, what do I do now, what does success look like, and what do I do if it fails. One decision per screen, with a recommended default already selected.
4. **The last step of every wizard is "prove it works".** It shows the real command and the real output of a separate tool (OpenSSL, `ssh.exe`) in everyday words, and states whether the proof came from an outside tool or from this course's own code.
5. **The first slice is `token.issuer` (family F6, `modes-design.md` slice M0).** Section 4 walks its eight screens with the words on each. Section 5 lists the other 14 types.
6. **The wizards say true things that are easy to skip.** A public CA will not sign `localhost`. A self-signed certificate is not a chain. A key typed here is a test key, and this course shows it on screen. Section 8 lists each statement and where it appears.
7. **Disposition:** ready for review by Steve, Richard, and Echo. Echo can write acceptance clauses from the test ids in section 9. Section 12 holds 8 open questions.

Steve's words, 2026-11-05: "When we are out of Mock mode for a given security type, we need wizards to walk us through the configuration and registration of the keys and certificates. When all is configured, then the training can be run with real data. The wizards need to be humanized and the UX be a logical flow so as not to assume any knowledge on the user's part." And: use test keys only, and a "Show keys" toggle.

## 1. Where it lives

### 1.1 Top bar

| Item | Place | Test id | Behavior |
|---|---|---|---|
| Security setup button | After the `host-chip`, before the mode switch | `security-setup-button` | Opens the Security setup screen. Shows a small count badge when any type is Real and not ready (`security-badge`) |
| Keys chip | Beside `training-only-label` | `keys-chip` | Reads `Keys: practice` when all 15 types are Mock. Reads `Keys: 3 real` when 3 types are Real. Click opens the Security setup screen |
| Show keys switch | Right of the view switch | `show-keys-switch` | One switch, default ON, same in Mock and Real. Label: `Show keys`. Tooltip: "On: this course shows your keys on screen and in saved files. Off: it shows a short fingerprint instead." The same store value drives the copy on the Security setup screen |
| OS transport button | Existing `transport-switch` | `transport-switch` | The text changes from "Real mode" to "OS transport" (`modes-design.md` 7.1), so the word "Real" means one thing: a real key |

`training-only-label` stays as it is. The two chips answer two questions: whose code speaks the protocol, and whose key signs.

### 1.2 The Security setup screen

A full-window screen, not a panel. It replaces the splitpanes area and keeps the top bar. `Esc` or the Back to lessons button returns to the last lesson.

| Zone | Content | Test id |
|---|---|---|
| Header | Title `Security setup`, the one-line test-keys rule (copy id `wizard.common.test-keys-only`), the `show-keys-switch` repeated | `sec-page`, `sec-test-keys-line` |
| Goal card | "Run a lesson with my own keys" and a lesson picker. Starts the guided path (section 2) | `sec-goal-card`, `sec-goal-lesson` |
| Map | 6 groups, 15 rows (table below) | `sec-map` |
| Footer | `Use practice keys everywhere` (undo all), link to the glossary | `sec-all-mock`, `sec-glossary` |

The map groups follow dependencies, top to bottom:

| Group (plain title) | Rows (type ids) |
|---|---|
| Web security (TLS) | `pki.root-ca`, `tls13.server`, `tls.trust`, `tls13.client`, `tls11.server` |
| Remote login (SSH) | `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.known-hosts`, `ssh.client` |
| Card PIN keys (DUKPT) | `dukpt.bdk`, `dukpt.pad` |
| Sign-in tokens | `token.issuer`, `device.enrolment` |
| Locks and seals | `lab.aes-key`, `lab.seal-key` |

The groups hold 5, 4, 2, 2, and 2 rows: 15 in all.

Each row has these cells. The Host sends every value in `GET /api/security`. The UI invents none.

| Cell | Shows | Test id |
|---|---|---|
| Name | Plain title, for example `Server certificate (TLS 1.3)`. The type id appears small, as a hint for Echo and for logs | `type-row-<typeId>`, `type-title-<typeId>` |
| What it is for | One sentence from the copy file | `type-why-<typeId>` |
| Mode | Two-button switch `Practice | Real`. `Real` is disabled with a reason when the Host says `canGoReal` is false | `type-mode-<typeId>` |
| State | A chip with words and an icon, never color alone: `Practice key`, `Needs setup`, `Set up, not proven`, `Proven`, `Broken` | `type-state-<typeId>` |
| Used by | Lessons that read this type, for example `Lessons 4, 5, 7` | `type-usedby-<typeId>` |
| Action | One button: `Set up`, `Prove it`, `Fix it`, `Change`, or `Continue setup` | `type-action-<typeId>` |
| Why not | When `canGoReal` is false: "Set up the certificate authority first." with a link that opens that row's wizard | `type-whynot-<typeId>` |

State words map to the Host's states (`modes-design.md` 2.2):

| Host state | Chip words | Action button |
|---|---|---|
| Mode Mock | `Practice key` | `Set up my own` (switches to Real and opens the wizard) |
| `Unconfigured` | `Needs setup` | `Set up` |
| `Configured` | `Set up, not proven` | `Prove it` |
| `Verified` | `Proven` | `Change` |
| `Broken` | `Broken: <one-sentence cause>` | `Fix it` |
| A wizard is open | `Setup paused at step 3 of 8` | `Continue setup` |

### 1.3 How a learner arrives from a lesson

A lesson that reads a Real type that is not `Verified` does not start. The Host answers `session.start` with `SECURITY_TYPE_NOT_READY` or `SECURITY_TYPE_NOT_PROVEN`, naming each type. The UI shows this banner over the tour panel and the diagram, never a silent fallback:

| Part | Words (copy id `sec.refusal.*`) | Test id |
|---|---|---|
| Banner | "Lesson 10 needs 2 keys that are not ready yet." | `security-needs-banner` |
| One line per type | "Server certificate: needs setup. [Set up now]" | `needs-row-<typeId>`, `needs-setup-<typeId>` |
| Second button | `Use practice keys for this lesson` (flips only the needed types to Mock, after a one-line confirmation) | `needs-use-practice` |

The lesson rail shows a small key badge on a lesson whose types are not ready (`lesson-keys-badge-<n>`, title "2 keys need setup"). Clicking it opens the same banner. The wizard opened this way returns to the lesson when it finishes (section 3.5).

## 2. The flow

### 2.1 First time

| Step | What the learner sees | Who decides |
|---|---|---|
| 0 | Everything is Practice. Nothing needs doing. The first-run line on the Security setup screen: "Every lesson works now with built-in practice keys. Set up your own keys only when you want to." | Host: all types Mock |
| 1 | Learner opens Security setup, picks a lesson in the goal card | Learner |
| 2 | The screen lists the types that lesson needs, in order, each with its state | Host: `LabCatalog.Needs(lesson)` plus dependency order |
| 3 | `Start` opens the first wizard in that list. When it finishes, the next one opens with a `Next: <title>` button | Host: wizard machine |
| 4 | When all are `Proven`, the goal card shows `Run lesson 10 now` | Host: `SecurityReadiness.Decide` |

### 2.2 Order of types and dependencies

The Host computes the order and sends it. This table is for review and for the clauses.

| Type | Needs first | Why |
|---|---|---|
| `pki.root-ca` | none | Every certificate below traces to it |
| `tls13.server`, `tls13.client`, `tls11.server` | `pki.root-ca` | A certificate needs a CA to sign it |
| `tls.trust` | `pki.root-ca` | The trust list holds the root. Default: follows the root |
| `ssh.host-ed25519`, `ssh.host-rsa` | none | A host key stands alone |
| `ssh.known-hosts` | the host key type it pins | The pin is made from that public key |
| `ssh.client` | none | A user key stands alone |
| `dukpt.bdk` | none | The base key starts the ladder |
| `dukpt.pad` | `dukpt.bdk` | The pad's key derives from the base key |
| `token.issuer`, `device.enrolment`, `lab.aes-key`, `lab.seal-key` | none | Each stands alone |

Two rules the Host enforces and the UI explains in words. If the types disagree, the lab refuses with `SECURITY_TYPES_DISAGREE`. Example: the server certificate is Real and the trust list is Practice. The banner says: "The server's certificate is your own. The list of trusted authorities is still the practice one, so the certificate would never be trusted. Set up the trust list, or switch the server back to practice."

### 2.3 Which type first

`token.issuer` is the first slice (`modes-design.md` slice M0). It has no dependency, it runs in lesson 10, and the check is one OpenSSL command. Section 4 walks it. `pki.root-ca` is the first type a TLS learner meets, and section 5 gives its screens.

## 3. The wizard frame (all families)

### 3.1 Layout

A modal sheet over the Security setup screen, 720 px wide at most, centered. The sheet never covers the top bar.

```
+------------------------------------------------------------+
| Set up: Token signing key          Step 3 of 8     [x Close]|
| ---------------------------------------------------------- |
|  WHAT THIS IS                                              |
|  <2 sentences>                                             |
|  WHY IT EXISTS IN THE REAL WORLD                           |
|  <2 sentences>                                             |
|  WHAT YOU DO NOW                                           |
|  <the one decision or entry, with the recommended answer   |
|   already selected and marked "Recommended">               |
|  WHAT GOOD LOOKS LIKE                                      |
|  <1 sentence>                                              |
|  [ failure box appears here when a check refuses ]         |
| ---------------------------------------------------------- |
|  [Back]                       [Cancel setup]   [Continue]  |
+------------------------------------------------------------+
```

| Zone | Test id |
|---|---|
| Sheet | `wizard-sheet` |
| Header: title, `Step n of m` | `wizard-title`, `wizard-progress` |
| Four copy blocks | `wizard-what`, `wizard-why`, `wizard-do`, `wizard-good` |
| The one control (radio group, field, file picker, or generate button) | `wizard-control` |
| Glossary terms inside copy | `term-<id>`, as in `ux-design.md` section 5 |
| Failure box | `wizard-error`, `wizard-error-code`, `wizard-error-fix` |
| Test-keys line (Intro step only, before any source choice) | `wizard-test-keys-line` |
| Buttons | `wizard-back`, `wizard-cancel`, `wizard-next` |
| Why a button is disabled | `wizard-next-reason` (always present, empty when enabled, as `next-reason` is in the tour) |

### 3.2 The spine

Every family runs the Host's spine: `Intro`, `ChooseSource`, source steps, `ReadBack`, `Place`, `Prove`, `Done` (`modes-design.md` 8.4). The UI never adds, skips, or reorders a step. It renders `step.kind` (`explain`, `choose`, `file`, `entry`, `generate`, `review`, `prove`, `done`) and offers only the buttons in `step.allowed`.

### 3.3 Words and reading level

1. All words live in `app/src/wizard-copy.json`, keyed by `copyId`, the way `field-gloss.json` works. `tools/tour_lint.py` holds the file to grade 8.9. The tic gate scans it. Cussler humanizes it (milestone M8).
2. One idea per sentence, 20 words at most. Active voice. The reader is an experienced engineer who has never studied this field, so no step assumes a term. The first use of a term in a screen is a glossary term (`{{term:id}}`).
3. Each failure box has three parts: what happened in one sentence, what to do in one sentence, and a `Details` fold for the code and log text (gem `plain-sentence-error-surface`).
4. Buttons say what they do: `Make a key for me`, `Choose a file`, `Check it with OpenSSL`. A button never says `OK` or `Submit`.

### 3.4 Keyboard and back

| Key | Action |
|---|---|
| `Enter` | The primary button (`Continue`), when enabled |
| `Esc` | Opens the cancel sheet: "Keep my place and close, or throw this setup away?" Two buttons: `Keep my place` (default) and `Throw it away` |
| `Alt+Left` | `Back` |
| `Tab` | Moves through the control, the glossary terms, then the buttons. The focus ring is 2 px, as everywhere |
| `Space` | Selects the focused radio choice |

`Back` works up to `Place` (`modes-design.md` 8.4). After `Place` a new version exists, and the `Back` button is replaced by `Change my answers`, which starts a new setup that keeps the earlier version stored. A failed proof loses nothing.

### 3.5 Resume and undo

| Case | Behavior | Needs from the Host |
|---|---|---|
| Learner closes the sheet with `Keep my place` | The row says `Setup paused at step 3 of 8`. `Continue setup` reopens the same step | An open wizard survives the sheet |
| Learner quits the app mid-wizard | On the next start the row still says `Setup paused`. Answers that are not secrets are kept. A typed secret (a DUKPT component) is never kept: that step asks again | The Host stores `{wizardId, state, stepSeq, answers}` without secrets in `.security/`. **This is a contract request** (open question Q3): `GET /api/security` types need `openWizardId` |
| Learner wants practice keys again | Row action `Use practice key again`, always allowed, one click, one confirmation line: "Your key stays saved. The course stops using it." The Host's `PUT .../mode {Mock}` always works | Exists (`modes-design.md` 8.1) |
| Learner flips the mode switch to `Real` with no binding | The wizard opens at once. Closing it with `Keep my place` leaves the mode at `Real`, state `Needs setup`, and the banner in 1.3 appears at the next lesson start | Exists |
| A wizard finishes and a lesson sent the learner here | `Done` shows `Back to lesson 10`, which closes the sheet and starts the lesson | UI only |

## 4. One full wizard: the token signing key (`token.issuer`, family F6)

The first slice. Source choices in M0 are file-backed (`modes-design.md` slice M0): `Make a test key for me` writes an Ed25519 key file under `.security/`, and `Use a key file I already have` reads a PEM. The vault source (M1) adds nothing to the screens.

Eight screens. Ids are `wiz-token-issuer-<n>` with the Host's state in brackets. Words are the copy-file text; Cussler will adjust voice, not facts.

### Screen 1 of 8: Intro (`wiz-token-issuer-intro`, state `Intro`, kind `explain`)

| Block | Words |
|---|---|
| Title | Set up: the key that signs tokens |
| What this is | A {{token}} is a small signed note that says who you are and what you may do. This setup gives the course your own key to sign those notes. |
| Why it exists | In a real system, one service signs tokens and every other service checks the signature. If the signing key leaks, anyone can make tokens. So the key is guarded. |
| What you do now | Read this, then choose `Continue`. You will make or pick a key, name the issuer, and test it. It takes about 3 minutes. |
| What good looks like | At the end, lesson 10 signs its tokens with your key, and OpenSSL agrees the signatures are good. |
| Test-keys line (first, before any choice) | Use test keys only. This course shows your keys on screen and in saved files. *(When Show keys is Off the line reads: "This course hides key bytes on screen for now. Saved files can still hold them.")* |
| Buttons | `Cancel setup`, `Continue` (default) |
| Fails when | Nothing here fails. |

### Screen 2 of 8: Choose a source (`wiz-token-issuer-source`, `ChooseSource`, kind `choose`)

| Block | Words |
|---|---|
| What this is | The signing key is a long secret number. You can have the course make a new one, or use a file you already have. |
| Why it exists | Real teams do both. A team makes a key once, keeps it safe, and points the service at it. |
| What you do now (one decision) | **Make a test key for me** (Recommended). Or: Use a key file I already have. |
| What good looks like | You will see the key's fingerprint in two screens, so you can tell which key you chose. |
| Choices | `make` (default), `file` |
| Fails when | Nothing here fails. |

### Screen 3 of 8, path A: Generate (`wiz-token-issuer-generate`, kind `generate`)

| Block | Words |
|---|---|
| What this is | The course will make an {{ed25519}} key. Ed25519 is a modern signing method with short keys. |
| Why it exists | The token checks in this course read Ed25519 signatures only, so this is the kind that works here. |
| What you do now | Choose `Make the key`. The key is saved in the `.security` folder of this project. |
| What good looks like | You see `Key made` and the key's fingerprint. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not save the key file. Check that the project folder can be written, then try again." |

### Screen 3 of 8, path B: Pick a file (`wiz-token-issuer-file`, kind `file`)

| Block | Words |
|---|---|
| What this is | A {{pem}} file is a text file that holds a key between two lines that start with five dashes. |
| Why it exists | PEM is the common way to move a key between tools. OpenSSL makes it. |
| What you do now | Choose `Choose a file`. A window opens. Pick the private key file. The path goes to the course, not the bytes. |
| What good looks like | You see `Read it: an Ed25519 key` and its fingerprint. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not open that file. Pick it again, or move it into the project folder." `KEY_FILE_FORMAT`: "That file is not a PEM key. Make one with `openssl genpkey -algorithm ed25519 -out issuer.pem`, then pick it." `KEY_FILE_ENCRYPTED`: "That key has a passphrase. This course cannot ask for it. For a test key, remove it with `openssl pkey -in issuer.pem -out issuer-open.pem`, then pick the new file." `KEY_ALGORITHM_NOT_IN_ENGINE`: "That key is RSA (or ECDSA). Token checks here read Ed25519 only. Make an Ed25519 key instead." |

### Screen 4 of 8: Name the issuer (`wiz-token-issuer-issuer`, kind `entry`)

| Block | Words |
|---|---|
| What this is | The {{issuer}} is the name written inside every token that says who signed it. It is a web address. |
| Why it exists | A service that checks a token needs to know whose signature to trust. The issuer name tells it which key to use. |
| What you do now | Keep the suggested name `https://pump.training/issuer`, or type another web address. |
| What good looks like | The name starts with `https://`. |
| Fails when | `ISSUER_NAME_BAD`: "An issuer name must be a web address that starts with https://. Try `https://pump.training/issuer`." *(Code to add in the Host list; open question Q6.)* |

### Screen 5 of 8: Name the audience (`wiz-token-issuer-audience`, kind `entry`)

| Block | Words |
|---|---|
| What this is | The {{audience}} says which service a token is meant for. |
| Why it exists | A token for the pump API must not work on the billing service. Each service checks that its own name is in the audience. |
| What you do now | Keep `https://pump.training/api`, or type another web address. |
| What good looks like | The name starts with `https://`. |
| Fails when | Same as screen 4. |

### Screen 6 of 8: Read it back (`wiz-token-issuer-readback`, `ReadBack`, kind `review`)

| Block | Words |
|---|---|
| What this is | This is a summary of what you chose. Nothing is saved yet. |
| Why it exists | Real teams read a key's details before they use it, because a wrong key causes a failure far from the cause. |
| What you do now | Check the facts. Choose `Back` to change one, or `Continue` to save. |
| Facts shown (from the Host) | Kind: Ed25519. Fingerprint: `SHA256:...`. Public key (shown when Show keys is On; a fingerprint when Off). Issuer. Audience. Where it will be saved. A line: "This is a test key. This course shows it on screen." |
| What good looks like | The fingerprint matches the one on the earlier screen. |
| Fails when | Nothing fails here. The Host already refused a bad key on screen 3. |

### Screen 7 of 8: Save it (`wiz-token-issuer-place`, `Place`, kind `generate`)

| Block | Words |
|---|---|
| What this is | The course saves your key as a new version. Your practice key stays saved too. |
| Why it exists | Real systems keep old key versions, so a bad change can be undone. |
| What you do now | Choose `Save my key`. |
| What good looks like | You see `Saved as version 1`. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not write the project folder. Check disk space and folder rights, then try again. Your earlier key is unchanged." |

### Screen 8 of 8: Prove it works (`wiz-token-issuer-prove`, `Prove`, kind `prove`)

| Block | Words |
|---|---|
| What this is | The course asks OpenSSL, a separate tool written by other people, to check a token signed with your key. |
| Why it exists | If the course checked itself, a mistake could hide. A different tool has no reason to agree. |
| What you do now | Choose `Check it with OpenSSL`. |
| What good looks like | You see the real command, the real answer, and `OpenSSL agrees`. |
| Shown after the run | The command, for example `openssl pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin`. The tool's output, for example `Signature Verified Successfully`. In words: "OpenSSL read the public half of your key, and said the signature on the token is good." A tier line: `Proof by an outside tool.` |
| Fails when | `REFEREE_MISSING`: "OpenSSL was not found. Git for Windows includes it. Set the path in `NETSEC_OPENSSL`, or install Git for Windows, then run the check again." `PROOF_FAILED`: "OpenSSL said the signature is bad. This means the key and the token do not match. Choose `Back to the start` and make the key again. The output is below." |

### Done (`wiz-token-issuer-done`, `Done`, kind `done`)

| Block | Words |
|---|---|
| What happened | Your token signing key is `Proven`. Lesson 10 now signs its tokens with it. |
| What you do now | `Run lesson 10` (when you came from a lesson), `Set up the next key`, `Back to the map`, or `Use practice key again`. |

## 5. The other 14 types, step by step

Each row lists the Host's steps in order, with the decision on each. Every screen uses the frame in section 3 and the five-part words. The Intro and Done screens exist for each type and are not repeated. "Default" is the recommended answer. "Fix" is what the failure box tells the learner.

| Type (family) | Plain title | Source choices (default first) | Screens after Intro, one decision each | Typical failures and fix |
|---|---|---|---|---|
| `pki.root-ca` (F1) | Certificate authority | Make one for me. Import PEM. PKCS#12 (RSA). OS store (RSA) | 1 Key kind: Ed25519 (default) or RSA (note: Ed25519 runs in the course's own engines, RSA runs through the OS transport). 2 Name: `MMP Training Root`. 3 Years valid: 5. 4 Read it back (is a CA: yes). 5 Save. 6 Prove: `openssl verify -CAfile root.pem root.pem`, then a test leaf | `KEY_FILE_FORMAT`: make one with OpenSSL, command shown. `CERT_NOT_A_CA`: "This certificate is not allowed to sign others. Pick a CA certificate." `CERT_SIGNATURE_ALG_UNSUPPORTED`: "The course can check Ed25519 signatures. This root uses RSA or ECDSA. Make an Ed25519 root." |
| `tls13.server` (F1) | Server certificate (TLS 1.3) | Make one for me. Import PEM. PKCS#12 (RSA). OS store (RSA) | 1 Names the server answers to: `localhost` (default). 2 Which authority signs it: my root (default). 3 Days valid: 90. 4 Read it back. 5 Save. 6 Prove: `openssl s_client -tls1_3 -CAfile <anchors> -verify_return_error` | `CERT_NAME_MISSING`: "The certificate does not name `localhost`." `KEY_CERT_MISMATCH`: "This certificate and key are not a pair. Pick the key that made it." `CHAIN_INCOMPLETE`: "The authority between your certificate and the root is missing. Add it to the file." |
| `tls.trust` (F2) | List of trusted authorities | Follow my root (default). Import certificates | 1 Source. 2 If import: pick files, read each back (name, expiry, is a CA). 3 Save. 4 Prove: `openssl verify -CAfile <anchors> <server certificate>` | `CERT_EXPIRED`: "This authority's certificate ended on <date>. Pick a newer one." `CERT_NOT_A_CA`. |
| `tls13.client` (F1) | Device certificate (mutual TLS) | Make one for me. Import PEM | 1 Device name: `pump-reader-4`. 2 Signer: my root. 3 Days valid: 90. 4 Include the middle authority? shown only when the signer is not the root (default Yes). 5 Read back. 6 Save. 7 Prove: `openssl s_server -tls1_3 -Verify 1 -CAfile <anchors>` against the course's client | `CHAIN_INCOMPLETE`: "The server cannot find who signed your certificate. A client under a middle authority must send that authority too. Add it." (Jared: Go refused a leaf-only client with `certificate signed by unknown authority`.) `CERT_USAGE_WRONG`: "This certificate is for servers. A device needs one for clients." |
| `tls11.server` (F1, RSA only) | Old-style server certificate (TLS 1.1) | Make one for me. Import PEM. PKCS#12 | 1 Key kind: RSA 2048, no choice, with the reason on screen ("TLS 1.1 key transport uses RSA"). 2 Names: `localhost`. 3 Signer: my root. 4 Read back. 5 Save. 6 Prove: `openssl s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile <anchors>` | `PKCS12_PASSWORD`: "That file needs a password. Type it, or export again with none." `KEY_ALGORITHM_NOT_IN_ENGINE`: "TLS 1.1 here needs an RSA key." |
| `ssh.host-ed25519` (F3) | Server identity key (modern) | Make one for me. Import OpenSSH | 1 Source. 2 If import: pick `ssh_host_ed25519_key`. 3 Read back: public line and `SHA256:` fingerprint. 4 Save. 5 Prove: `ssh.exe -F NUL -o BatchMode=yes -o UserKnownHostsFile=<pin> ... echo hello` | `KEY_FILE_FORMAT`: "Not an OpenSSH private key. It starts with `-----BEGIN OPENSSH PRIVATE KEY-----`." `KEY_FILE_ENCRYPTED`. |
| `ssh.host-rsa` (F3) | Server identity key (legacy RSA) | Make one for me. Import OpenSSH | Same as above, with a line on screen: "RSA host keys here sign with SHA-1, which is weak. Lesson 8 uses it to show a legacy round." | Same as above |
| `ssh.client` (F3) | User key for signing in | Make one for me. Import OpenSSH. Add "for the CE process": file only | 1 Source. 2 Who uses it: the course's own client (default) or the CE process (file only). 3 Read back. 4 Save. 5 Prove: `ssh.exe` with the key file for a file key. A vault key shows `Proof by this course's own code, a weaker proof.` | `KEY_ALGORITHM_NOT_IN_ENGINE`: "Sign-in keys here are Ed25519 only." |
| `ssh.known-hosts` (F4) | Remembered server key (pin) | Follow my host key (default). Paste a `known_hosts` line. Learn on first connect | 1 Source. 2 Show the fingerprint, ask the learner to compare it by another way, for example read it back from the server file (decision: `It matches` or `It does not match`). 3 Save. 4 Prove: connect to the host key type's server. Then a mismatch demonstration that names `SSH_HOST_KEY_CHANGED` | `KNOWN_HOSTS_LINE_BAD`: "That line does not parse. Wildcards are refused. Use `host key-type base64`." |
| `dukpt.bdk` (F5) | Base key for card PIN keys | Enter components (default). Import a vendor test key | 1 Why components: "Two or three people each hold a part, so no one holds the whole key." 2 Component 1 (masked field, 32 hex characters), shows its check value. 3 Component 2, check value. 4 A third component? (Yes or No; default No). 5 Combine: the key is the XOR of the parts, made inside the box. Learner compares the final check value with the one on their own paper. 6 Can the key be read back later? `Yes, so I can see it` (default) or `No, like a real HSM` (one-way, with the line "This key cannot be read. A real HSM would refuse too."). 7 Read back. 8 Save. 9 Prove: a control first (the published X9 test base key must give the published vector), then a round trip with your key | `DUKPT_COMPONENT_LENGTH`: "A component is 32 hex characters (16 bytes). You typed <n>." `DUKPT_KCV_MISMATCH`: "The check value differs. You mistyped a digit. Retype that component." |
| `dukpt.pad` (F5, derived) | PIN pad key | Follows the base key. No other choice | 1 Explain: the pad gets its key from the base key and a key id, as a key loader would. 2 Read back: a new key id each run. 3 Prove: one sale, pad to bank | `VAULT_KEY_UNKNOWN`: "Set up the base key first." (with a link) |
| `device.enrolment` (F7) | Device sign-in key (passkey-shaped) | Make one for me. Import PEM | 1 Subject name: `pump-reader-4`. 2 Source. 3 Read back: the enrolment row the issuer will hold (subject, public key). 4 Save. 5 Prove: OpenSSL checks a challenge answer signed with the device key | `KEY_ALGORITHM_NOT_IN_ENGINE`: "Device keys are Ed25519 here." |
| `lab.aes-key` (F8) | Data key for lesson 1 | Make a wrapping key for me | 1 One screen: make the key. 2 Prove: wrap, unwrap, compare with the .NET library | `VAULT_UNWRAP_FAILED` |
| `lab.seal-key` (F8) | Data key for lesson 2 | Make a wrapping key for me | Same as above | `VAULT_UNWRAP_FAILED` |

`token.issuer` is the 15th type and is walked in section 4.

## 6. The proof step in everyday words

Every Prove screen has the same four parts, in this order: the real command in a code block, the real output in a code block, one sentence in words, and a tier line.

| Part | Rule | Test id |
|---|---|---|
| Command | The text the Host ran, with paths shortened to file names | `prove-command` |
| Output | The last 20 lines the tool printed. No editing | `prove-output` |
| In words | One sentence the copy file keeps per type: "OpenSSL read your server's certificate and said it traces to your root." | `prove-words` |
| Tier | `Proof by an outside tool.` or `Proof by this course's own code, a weaker proof.` (glass to glass) | `prove-tier` |

| Outcome | What the learner sees | Next |
|---|---|---|
| Pass | Green check and `OpenSSL agrees` (or the tool's name). The type becomes `Proven` | `Done` |
| `PROOF_FAILED` | Red cross, the output, and the one-sentence cause from the copy file | `Back to the start` or `Cancel setup`. The earlier key stays saved |
| `REFEREE_MISSING` | An amber note, not a failure of the key: "The test tool is missing. Your key is saved but not proven." | Fix steps in section 8 row 9. The type stays `Set up, not proven` |

## 7. Show keys on every wizard screen

| Where | With the switch On | With the switch Off |
|---|---|---|
| Read-back facts | The key bytes in a `Show all` fold, copy button | `fp:` fingerprint and length, "Hidden by the Show keys switch" |
| Prove output | As the tool printed | The tool output is unchanged (it holds public data), key file paths only |
| DUKPT component fields | Masked while typed, always. The check value shows | Same |
| The setup screen header | Test-keys line says "This course shows your keys on screen and in saved files." | Says "This course hides key bytes on screen for now. Saved files can still hold them." |
| A non-exportable key | Shows the fingerprint and the line "This key cannot be read. A real HSM would refuse too." | Same |

Flipping the switch while a wizard is open replaces the facts block from the Host. The wizard does not move.

## 8. True statements the wizards must make

| # | Statement | Where it appears | Source |
|---|---|---|---|
| 1 | A public certificate authority will not sign a certificate for `localhost`. Public CAs check that you control a public name, and `localhost` is nobody's. So a server certificate here comes from a CA you make. | `pki.root-ca` Intro and `tls13.server` screen 2 | `modes-design.md` 1.8; the course's training CA |
| 2 | A self-signed certificate is not a chain. It vouches for itself, so nothing outside it proves it. A chain ends in a root that the checker already trusts. | `pki.root-ca` Intro, `tls.trust` Intro | PRD framing; `ChainCheck` |
| 3 | The course's own engines check Ed25519 signatures only. An RSA or ECDSA certificate fails with a named code. RSA runs through the OS transport. ECDSA is not supported in the course's engines. | `KEY_ALGORITHM_NOT_IN_ENGINE` and `CERT_SIGNATURE_ALG_UNSUPPORTED` boxes, kind choice screens | `modes-design.md` 1.8, 8.5 |
| 4 | A leaf under a middle authority must be sent with that authority, for a client too. A leaf alone gets `certificate signed by unknown authority`. | `tls13.client` screen 4 and `CHAIN_INCOMPLETE` | Jared's finding, `modes-design.md` 8.5 |
| 5 | Use test keys only. This course shows your keys on screen and in saved files. Nothing here can tell a test key from a production key. | Every Intro, before any choice | `modes-design.md` 8.2 |
| 6 | The key store is a plain file, and anyone with both files reads every key. It is not a production vault. | `Place` screens | `modes-design.md` O5 |
| 7 | Card numbers and PINs stay test values. The wizard has no field for them. | `dukpt.bdk` Intro, `dukpt.pad` Intro | `modes-design.md` 1.6, O10 |
| 8 | A key made non-exportable cannot be read back, one way, as in a real HSM. | `dukpt.bdk` screen 6, vault key choices | `modes-design.md` 6.3 |
| 9 | If the test tool is missing, the key is saved but not proven, and lessons will not run on it. | Prove screen, `REFEREE_MISSING` | `modes-design.md` 2.3 |
| 10 | A proof by the course's own code is weaker than a proof by an outside tool. | `prove-tier` | `modes-design.md` 8.6 |

## 9. Screens and stable test ids

Names never change after the first build. Echo writes clauses from this table.

### 9.1 Security setup screen

| Area | Ids |
|---|---|
| Top bar | `security-setup-button`, `security-badge`, `keys-chip`, `show-keys-switch`, `transport-switch` |
| Page | `sec-page`, `sec-test-keys-line`, `sec-goal-card`, `sec-goal-lesson`, `sec-goal-start`, `sec-map`, `sec-group-<web|ssh|dukpt|tokens|locks>`, `sec-all-mock`, `sec-glossary`, `sec-back` |
| Row (15) | `type-row-<typeId>`, `type-title-<typeId>`, `type-why-<typeId>`, `type-mode-<typeId>`, `type-mode-practice-<typeId>`, `type-mode-real-<typeId>`, `type-state-<typeId>`, `type-usedby-<typeId>`, `type-action-<typeId>`, `type-whynot-<typeId>`, `type-undo-<typeId>` |
| Refusal | `security-needs-banner`, `needs-row-<typeId>`, `needs-setup-<typeId>`, `needs-use-practice`, `lesson-keys-badge-<n>` |
| Guided list | `guide-list`, `guide-item-<typeId>`, `guide-next`, `guide-run-lesson` |

`<typeId>` values: `pki.root-ca`, `tls13.server`, `tls.trust`, `tls13.client`, `tls11.server`, `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.known-hosts`, `ssh.client`, `dukpt.bdk`, `dukpt.pad`, `token.issuer`, `device.enrolment`, `lab.aes-key`, `lab.seal-key`.

### 9.2 Wizard frame

`wizard-sheet`, `wizard-title`, `wizard-progress`, `wizard-what`, `wizard-why`, `wizard-do`, `wizard-good`, `wizard-control`, `wizard-test-keys-line`, `wizard-error`, `wizard-error-code`, `wizard-error-fix`, `wizard-error-details`, `wizard-back`, `wizard-cancel`, `wizard-next`, `wizard-next-reason`, `wizard-cancel-sheet`, `wizard-keep-place`, `wizard-throw-away`.

Controls: `wizard-choice-<choiceId>` (radio), `wizard-field-<fieldId>` (text entry), `wizard-file-button`, `wizard-file-path`, `wizard-generate-button`, `wizard-facts`, `wizard-fact-<name>`, `wizard-show-all`, `wizard-copy`.

### 9.3 Screens by family

Pattern: `wiz-<typeId>-<step>`. `<step>` values are listed here. A test walks every step of one type per family and asserts the Host's `step.state`.

| Family | Step ids |
|---|---|
| All | `intro`, `source`, `readback`, `place`, `prove`, `done` |
| F1 (`pki.root-ca`, `tls13.server`, `tls13.client`, `tls11.server`) | `kind`, `generate`, `file`, `keyfile`, `chain`, `p12-password`, `os-pick`, `names`, `signer`, `validity`, `device-name`, `middle-ca` |
| F2 (`tls.trust`) | `file`, `each-cert` |
| F3 (`ssh.host-*`, `ssh.client`) | `generate`, `file`, `who-uses` |
| F4 (`ssh.known-hosts`) | `paste`, `compare`, `learn` |
| F5 (`dukpt.bdk`, `dukpt.pad`) | `why-components`, `component-1`, `component-2`, `third-component`, `combine`, `readable`, `follows` |
| F6 (`token.issuer`) | `generate`, `file`, `issuer`, `audience` |
| F7 (`device.enrolment`) | `subject`, `generate`, `file` |
| F8 (`lab.aes-key`, `lab.seal-key`) | `generate` |

Distinct screen ids in this design: 6 shared, 12 in F1, 2 in F2, 3 in F3, 3 in F4, 7 in F5, 4 in F6, 3 in F7, 1 in F8: **41 screen ids**, plus the Security setup screen, the refusal banner, and the cancel sheet: **44 screens** in all. One wizard shows from 7 screens (`lab.aes-key`: intro, source, generate, read back, save, prove, done) to 12 (`dukpt.bdk`).

### 9.4 Prove step

`prove-command`, `prove-output`, `prove-words`, `prove-tier`, `prove-run`, `prove-pass`, `prove-fail`, `prove-missing`.

### 9.5 Acceptance clauses this table supports (for Echo)

| Proposed id | Asserts |
|---|---|
| `A17.ui.map-has-15-rows` | The map shows 15 rows with the ids above |
| `A17.ui.mode-switch-undo` | `type-mode-practice-<id>` is always enabled and returns the row to Practice |
| `A17.ui.refusal-names-types` | A lesson on an unready type shows `security-needs-banner` with one `needs-row-<id>` per type |
| `A17.ui.wizard-token-issuer-walk` | The 8 screens of section 4 show in order and end `Proven` |
| `A17.ui.next-reason-present` | `wizard-next-reason` exists on every screen, empty when `wizard-next` is enabled |
| `A17.ui.error-names-fix` | Every `wizard-error` has a non-empty `wizard-error-fix` |
| `A17.ui.show-keys-switch` | The switch flips key bytes to fingerprints in `wizard-facts` |
| `A17.ui.resume` | After closing the sheet, `type-action-<id>` reads `Continue setup` and reopens the same step |
| `A17.copy.grade` | `wizard-copy.json` scores grade 8.9 or lower |
| `A17.copy.tic-gate` | `tic-gate.py` passes on the copy file |

## 10. Mockups

### 10.1 Security setup screen (section 1.2)

```
+--------------------------------------------------------------------------------+
| Network Security Lab [TRAINING ONLY] [Keys: 2 real] [engine connected]         |
|                       [Security setup (1)]  Tour|Free  Endpoints|..  Show keys (o)|
+--------------------------------------------------------------------------------+
| Security setup                                           [Back to lessons]     |
| Use test keys only. This course shows your keys on screen and in saved files.  |
|                                                                                |
| +-- Run a lesson with my own keys ----------------------------------------+  |
| |  Lesson: [ 10 Client proof and permission v ]            [ Start ]       |  |
| +--------------------------------------------------------------------------+  |
|                                                                                |
| WEB SECURITY (TLS)                                                             |
| Certificate authority      Practice | Real   [Proven]        Lessons 4,5,7,10 [Change]|
| Server certificate (1.3)   Practice | Real   [Needs setup]   Lessons 4,5,7,9,10 [Set up]|
| Trusted authorities        Practice | Real   [Practice key]  ...      [Set up my own]  |
|   Set up the certificate authority first.  (link)                              |
| ...                                                                            |
| SIGN-IN TOKENS                                                                 |
| Token signing key          Practice | Real   [Setup paused, step 3 of 8] [Continue setup]|
| ...                                                                            |
|                                              [ Use practice keys everywhere ]  |
+--------------------------------------------------------------------------------+
```

### 10.2 Wizard screen 6 of 8, read it back (section 4)

```
+------------------------------------------------------------+
| Set up: the key that signs tokens       Step 6 of 8  [x]   |
| ---------------------------------------------------------- |
| WHAT THIS IS                                               |
|  This is a summary of what you chose. Nothing is saved yet.|
| WHY IT EXISTS IN THE REAL WORLD                            |
|  Real teams read a key's details before they use it,       |
|  because a wrong key causes a failure far from the cause.  |
| WHAT YOU DO NOW                                            |
|  Check the facts. Choose Back to change one, or Continue.  |
|    Kind          Ed25519                                   |
|    Fingerprint   SHA256:Qk3...n9w=                         |
|    Public key    7c1e 9a02 ...   [Show all] [Copy]         |
|    Issuer        https://pump.training/issuer              |
|    Audience      https://pump.training/api                 |
|  This is a test key. This course shows it on screen.       |
| WHAT GOOD LOOKS LIKE                                       |
|  The fingerprint matches the one on the earlier screen.    |
| ---------------------------------------------------------- |
| [Back]                          [Cancel setup]  [Continue] |
+------------------------------------------------------------+
```

### 10.3 Prove screen with a failure (section 6)

```
+------------------------------------------------------------+
| Set up: the key that signs tokens       Step 8 of 8  [x]   |
| ---------------------------------------------------------- |
|  $ openssl pkeyutl -verify -pubin -inkey issuer.pub ...    |
|  Signature Verification Failure                            |
|  [X] OpenSSL said the signature is bad.                    |
|      The key and the token do not match.                   |
|      Choose "Back to the start" and make the key again.    |
|      Proof by an outside tool.         [Details v]         |
| ---------------------------------------------------------- |
| [Back to the start]                     [Cancel setup]     |
+------------------------------------------------------------+
```

## 11. Glossary terms to add

Each gets a `short` of 20 words or fewer at grade 8, in `app/src/glossary.json`. Every `{{term:id}}` in the copy file must resolve (the test in `ux-design.md` section 5).

`token`, `issuer`, `audience`, `pem`, `ed25519`, `rsa`, `ecdsa`, `certificate`, `ca`, `root-ca`, `chain`, `intermediate`, `leaf`, `self-signed`, `trust-store`, `subject`, `san`, `fingerprint`, `public-key`, `private-key`, `key-pair`, `pkcs12`, `known-hosts`, `host-key`, `user-key`, `openssh`, `bdk`, `dukpt`, `key-component`, `kcv`, `xor`, `hsm`, `exportable`, `vault`, `referee`, `enrolment`, `dpop`, `mutual-tls`, `eku`, `wrapping-key`.

## 12. Open questions

| # | Question | My pick | What would change it |
|---|---|---|---|
| Q1 | Jared's `docs/modes-real-world.md` was not found. Do his accuracy limits add anything beyond `modes-design.md` 1.6, 1.8, 6.3, 8.5? | Use the quoted limits now | His file lists a limit that needs a new line in section 8 |
| Q2 | Electron needs a file dialog (`dialog.showOpenDialog`) through an IPC handler in `main.cjs` and `preload.cjs`. This is Electron's own API, not a new package. May I add it? | Yes, one IPC call named `pickFile` that returns a path | A rule against new IPC channels |
| Q3 | Resume after quitting needs `openWizardId` on each type in `GET /api/security`, and the Host storing wizard state without secrets. Richard owns the contract. | Add both | Richard keeps wizards in memory only: then a quit loses the wizard and the row says `Needs setup` |
| Q4 | One decision per screen makes `dukpt.bdk` 12 screens long. Is that too long? | Keep one decision per screen, since a key ceremony is a slow, careful thing, and show a progress line | Steve finds it tedious: merge `component-1` and `component-2` into one screen with two fields |
| Q5 | `Use practice keys for this lesson` (banner button) flips types to Mock from a lesson screen. Does it need a confirmation? | One line of confirmation, no modal | Any user who flips by accident |
| Q6 | New Host codes the copy needs: `ISSUER_NAME_BAD`, and a `canGoReal`/`whyNot` text for each dependency. Richard adds them. | Add | The Host reuses an existing code |
| Q7 | The default validity (CA 5 years, certificates 90 days) are my picks. Real CAs issue 90-day leaf certificates and roots for 10 years or more. | Keep 5 years and 90 days. A learner will not wait for a 10-year expiry, and a 90-day one fits the `CERT_EXPIRED` demonstration | Steve wants real-world numbers |
| Q8 | The `Real` label means a real key. The OS-transport button must not also say "Real". Echo and I both edit `App.vue:143` area. | Rename the button to `OS transport` in the same slice that adds this screen | The button must keep "Real mode" for a clause |

No new package is needed. The design uses Vue 3, Vuetify, and the existing glossary tooltips. The Electron file dialog is part of Electron.
