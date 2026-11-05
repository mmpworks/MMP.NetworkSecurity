# MMP.NetworkSecurity: setup wizards, UX design

Author: Nancy. Date: 2026-11-05. Status: design for review, no product code. Branch `docs/wizards-ux`, off `docs/security-modes` (`d124d62`).
Inputs: `docs/modes-design.md` (sections 1, 2, 6, 8, 10), `docs/ux-design.md`, Steve's request (quoted in section 0). Jared's `docs/modes-real-world.md` (branch `docs/modes-real-world`, commit `ab12da8`) supplies the per-type limits (section 8) and the referee commands (section 6.1). Section 12 lists what to recheck if his file changes.

## Conclusion

1. **Five "make my set" flows, each with a plain goal, are the front door. The 15-row map stays as the detail view.** A flow builds a whole group of keys and certificates in one walk. The Host's step machine owns every move. The UI draws the step it is given and sends the answer back.
2. **The learner starts from a goal, not from a list of key types.** The five goal buttons are in section 1.4. "I want to run lesson 10 with my own keys" still works: the Host lists the flows that lesson needs, in dependency order.
3. **Every screen answers five questions in the same order:** what is this, why does it exist in the real world, what do I do now, what does success look like, and what do I do if it fails. One decision per screen, with a recommended default already selected.
4. **The last step of every wizard is "prove it works".** It shows the real command and the real output of a separate tool (OpenSSL, `ssh.exe`) in everyday words, and states whether the proof came from an outside tool or from this course's own code.
5. **The first slice is `token.issuer` (family F6, `modes-design.md` slice M0).** Section 4 walks `flow-my-login`, where it is one part, screen by screen with the words on each. Section 5 lists the other four flows. Section 5.5 adds a separate vault exercise of 3 screens.
6. **The wizards say true things that are easy to skip.** A public CA will not sign `localhost`. A self-signed certificate is not a chain. A key typed here is a test key, and this course shows it on screen. Section 8 lists each statement and where it appears.
7. **Labels never say "Real".** A switched-on type reads `My test key`. A green state never reads as "trusted": it reads `Checked by OpenSSL against the root you gave it`. Where no outside tool can judge (card keys, device keys), the screen says so, and the state reads `Saved, no outside check`. The course never checks its own key and calls it proof.
8. **Disposition:** ready for review by Steve, Richard, and Echo. Echo can write acceptance clauses from the test ids in section 9. Section 12 holds the open questions. The design has 36 screens in all, and 5 on the default path of any flow (section 1.4).

Steve's words, 2026-11-05: "When we are out of Mock mode for a given security type, we need wizards to walk us through the configuration and registration of the keys and certificates. When all is configured, then the training can be run with real data. The wizards need to be humanized and the UX be a logical flow so as not to assume any knowledge on the user's part." And: use test keys only, and a "Show keys" toggle.

## 1. Where it lives

### 1.1 Top bar

| Item | Place | Test id | Behavior |
|---|---|---|---|
| Security setup button | After the `host-chip`, before the mode switch | `security-setup-button` | Opens the Security setup screen. Shows a small count badge when any type uses my test key and is not ready (`security-badge`) |
| Keys chip | Beside `training-only-label` | `keys-chip` | Reads `Keys: practice` when all 15 types are practice. Reads `Keys: 3 of mine` when 3 types use my test key. Click opens the Security setup screen |
| Show keys switch | Right of the view switch | `show-keys-switch` | One switch, default ON, same for practice keys and my test keys. Label: `Show keys`. Tooltip: "On: this course shows your keys on screen and in saved files. Off: it shows a short fingerprint instead, a code that stands for the key." The same store value drives the copy on the Security setup screen |
| OS transport button | Existing `transport-switch` | `transport-switch` | The text changes from "Real mode" to "OS transport" (`modes-design.md` 7.1), so no label on screen says "Real" |

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
| Mode | Two-button switch `Practice | My test key`. `My test key` is disabled with a reason when the Host says `canGoReal` is false. The test id keeps the Host's word `real`. The label never does | `type-mode-<typeId>` |
| State | A chip with words and an icon, never color alone: `Practice key`, `Needs setup`, `Set up, not checked`, `Checked by <judge>`, `Saved, no outside check`, `Broken` | `type-state-<typeId>` |
| Used by | Lessons that read this type, for example `Lessons 4, 5, 7` | `type-usedby-<typeId>` |
| Action | One button: `Set up`, `Prove it`, `Fix it`, `Change`, or `Continue setup` | `type-action-<typeId>` |
| Why not | When `canGoReal` is false: "Set up the certificate authority first." with a link that opens that row's wizard | `type-whynot-<typeId>` |

State words map to the Host's states (`modes-design.md` 2.2):

| Host state | Chip words | Action button |
|---|---|---|
| Mode Mock | `Practice key` | `Set up my own` (switches to My test key and opens the wizard) |
| `Unconfigured` | `Needs setup` | `Set up` |
| `Configured` | `Set up, not checked` | `Check it` |
| `Verified` with an outside judge | `Checked by OpenSSL against the root you gave it` (the judge and the thing it checked against change per type) | `Change` |
| `Verified` with judge `none` (card keys, device keys) | `Saved, no outside check`, amber, never green | `Change` |
| `Broken` | `Broken: <one-sentence cause>` | `Fix it` |
| A wizard is open | `Setup paused at step 3 of 5` | `Continue setup` |

### 1.3 How a learner arrives from a lesson

A lesson that reads a type set to My test key that is not `Verified` does not start. The Host answers `session.start` with `SECURITY_TYPE_NOT_READY` or `SECURITY_TYPE_NOT_PROVEN`, naming each type. The UI shows this banner over the tour panel and the diagram, never a silent fallback:

| Part | Words (copy id `sec.refusal.*`) | Test id |
|---|---|---|
| Banner | "Lesson 10 needs 2 keys that still need setting up." | `security-needs-banner` |
| One line per type | "Server certificate: needs setup. [Set up now]" | `needs-row-<typeId>`, `needs-setup-<typeId>` |
| Second button | `Use practice keys for this lesson` (flips only the needed types to Mock, after a one-line confirmation) | `needs-use-practice` |

The lesson rail shows a small key badge on a lesson whose types are not ready (`lesson-keys-badge-<n>`, title "2 keys need setup"). Clicking it opens the same banner. The wizard opened this way returns to the lesson when it finishes (section 3.5).

### 1.4 The five flows

Steve chose five grouped "make my set" flows. Each flow has a **default path of five screens**. On the default path the Host makes the whole set with safe defaults, the learner reads what it made, and an outside tool checks it. Everything else (your own names, your own dates, your own files) sits behind one branch, `Change the defaults or use my own files`, on the second screen. The 15-row map in 1.2 stays as the detail view: its `Set up` and `Change` buttons open the flow at that row's part.

| # | Goal button (plain words) | Makes (type ids) | Lessons | Flow id |
|---|---|---|---|---|
| 1 | Make my web security set (Host flow `my-certificates`) | `pki.root-ca`, `tls.trust`, `tls13.server`, `tls13.client`, `tls11.server` | 4, 5, 7, 9, 10 | `flow-my-certificates` |
| 2 | Make my remote login set (Host flow `my-ssh`) | `ssh.host-ed25519`, `ssh.host-rsa`, `ssh.client`, `ssh.known-hosts` | 8, 9 | `flow-my-ssh` |
| 3 | Type in my card PIN keys (Host flow `my-payment`) | `dukpt.bdk`, `dukpt.pad` | 6, 9 | `flow-my-payment` |
| 4 | Make my sign-in set (Host flow `my-login`) | `token.issuer`, `device.enrolment` (named "Device key entry") | 10 | `flow-my-login` |
| 5 | Make my data keys (Host flow `my-lesson-keys`) | `lab.aes-key`, `lab.seal-key` | 1, 2 | `flow-my-lesson-keys` |

The flow ids are the Host's (`wizard-flows.json`, `modes-design.md` 8.1). Test ids add the prefix `flow-`: `flow-my-certificates-make`. The Host spine maps to the five screens: `Intro` is screen 1, `ChooseSource` and `Place` are screen 2 (`make`), `PickFiles` is the branch (`options`), `ReadBack` is screen 3, `Check` is screen 4, `Done` is screen 5.

#### The default path (the same five screens in every flow)

| # | Screen | Id | What it does |
|---|---|---|---|
| 1 | Intro | `flow-<flow>-intro` | Says what this set is, why it exists, and how long it takes. **The first line, before anything else: "This course shows every key, so use test keys. A real system keeps these hidden."** Buttons: `Continue`, `Cancel setup` |
| 2 | Make it for me | `flow-<flow>-make` | Lists every part in one line each, in words. The only decision is the recommended button `Make it for me`. A link under it reads `Change the defaults or use my own files`. The Host makes and saves every key in the set at once with its safe defaults |
| 3 | Review | `flow-<flow>-review` | Shows what was made, one block per part, in words, with each fingerprint. The Show keys switch applies. `Back` makes a new version. `Continue` goes on |
| 4 | Check | `flow-<flow>-check` | Runs the judge for each part. Shows the real command, the real output, and who judged. A part that no outside tool can judge shows an amber note and the chip `Saved, no outside check` |
| 5 | Done | `flow-<flow>-done` | Shows the chip for each part and which lessons now use the set. Buttons: `Run lesson N`, `Back to the map`, `Use practice keys again` |

The learner makes one decision on the whole path: `Make it for me`. Steve's rule of one decision per screen holds.

#### The branch (one screen per flow, except `flow-my-lesson-keys`)

`flow-<flow>-options` opens from the link on screen 2 and returns to screen 3 after it makes the set. It is one screen with two parts: `Change the defaults` (names, key kind, dates) and `Use my own files` (a file for each part, with the warnings of 3.6). Section 4 gives its fields for `flow-my-login`. Section 5 gives them for the other flows. `flow-my-lesson-keys` has no branch because its keys have no choices worth making.

#### Counts

| Group | Screens |
|---|---|
| Flows, default path | 25 (5 flows, 5 screens each) |
| Flows, branch | 4 (`flow-my-certificates`, `flow-my-ssh`, `flow-my-payment`, `flow-my-login`) |
| Vault exercise | 3 (section 5.1) |
| Shell | 4 (Security setup in flow view, the all-keys view, the refusal banner, the keep-my-place sheet) |
| **Total, all paths** | **36** |
| **Default path of one flow** | **5** |

Eleven fewer than the 15 per-type wizards would take on their shortest path, and 34 fewer than the first draft of this design.

#### Contract request for Richard

Today the Host's machine runs one wizard per type (`modes-design.md` 8.1: `POST /api/security/wizards {typeId}`). A flow needs `POST /api/security/wizards {flowId}`. The Host owns the part order, the defaults, and the shared answers. The UI must not chain per-type wizards itself, because then the UI would own the moves. Flow tables are data, as the family tables are. This is open question Q9, asked of Richard directly.

## 2. The flow

### 2.1 First time

| Step | What the learner sees | Who decides |
|---|---|---|
| 0 | Everything is Practice. Nothing needs doing. The first-run line on the Security setup screen: "Every lesson works now with built-in practice keys. Set up your own keys whenever you like." | Host: all types Mock |
| 1 | Learner opens Security setup and picks a flow card (section 1.4), or picks a lesson in the lesson picker | Learner |
| 2 | The screen lists the types that lesson needs, in order, each with its state | Host: `LabCatalog.Needs(lesson)` plus dependency order |
| 3 | `Start` opens the first wizard in that list. When it finishes, the next one opens with a `Next: <title>` button | Host: wizard machine |
| 4 | When all are `Checked` (or `Saved, no outside check`), the lesson picker shows `Run lesson 10 now` | Host: `SecurityReadiness.Decide` |

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

Two rules the Host enforces and the UI explains in words. If the types disagree, the lab refuses with `SECURITY_TYPES_DISAGREE`. Example: the server certificate uses my test key and the trust list is still the practice one. The banner says: "The server uses your own certificate. The list of trusted authorities (the groups that may vouch for a certificate) is still the practice list, so your certificate would never be trusted. Set up the trust list, or switch the server back to practice."

### 2.3 Which type first

`token.issuer` is the first slice (`modes-design.md` slice M0). It has no dependency, it runs in lesson 10, and the check is one OpenSSL command. Section 4 walks it. `pki.root-ca` is the first type a TLS learner meets, and section 5 gives its screens.

## 3. The wizard frame (all families)

### 3.1 Layout

A modal sheet over the Security setup screen, 720 px wide at most, centered. The sheet never covers the top bar.

```
+------------------------------------------------------------+
| Set up: Token signing key          Step 3 of 5     [x Close]|
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

Every flow runs the Host's spine, drawn on five default screens: `Intro` (screen 1), `ChooseSource` and `Place` together as `make` (screen 2, with `options` as the branch), `ReadBack` (screen 3), `Prove` (screen 4), and `Done` (screen 5) (`modes-design.md` 8.4). The UI never adds, skips, or reorders a step. It renders `step.kind` (`explain`, `choose`, `file`, `entry`, `generate`, `review`, `prove`, `done`) and offers only the buttons in `step.allowed`.

### 3.3 Words and reading level

1. All words live in `app/src/wizard-copy.json`, keyed by `copyId`, the way `field-gloss.json` works. `tools/tour_lint.py` holds the file to grade 8.9. The tic gate scans it. Cussler humanizes it (milestone M8).
2. One idea per sentence, 20 words at most. Active voice. Assume the reader knows nothing about this field. That includes what a key, a certificate, a signature, or trust means. The reader may be an experienced engineer, and the rule holds anyway, because Steve's rule is to assume no knowledge. No step uses a term before it explains the term. The first use of a term on a screen is a glossary term (`{{term:id}}`).
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
| Learner closes the sheet with `Keep my place` | The row says `Setup paused at step 3 of 5`. `Continue setup` reopens the same step | An open wizard survives the sheet |
| Learner quits the app mid-wizard | On the next start the row still says `Setup paused`. Answers that are not secrets are kept. A typed secret (a DUKPT component) is never kept: that step asks again | The Host stores `{wizardId, state, stepSeq, answers}` without secrets in `.security/`. **This is a contract request** (open question Q3): `GET /api/security` types need `openWizardId` |
| Learner wants practice keys again | Row action `Use practice key again`, always allowed, one click, one confirmation line: "Your key stays saved. The course stops using it." The Host's `PUT .../mode {Mock}` always works | Exists (`modes-design.md` 8.1) |
| Learner flips the mode switch to `My test key` with no binding | The wizard opens at once. Closing it with `Keep my place` leaves the mode at `My test key`, state `Needs setup`, and the banner in 1.3 appears at the next lesson start | Exists |
| A wizard finishes and a lesson sent the learner here | `Done` shows `Back to lesson 10`, which closes the sheet and starts the lesson | UI only |

### 3.6 File warnings

| Case | What the learner sees | Test id |
|---|---|---|
| The chosen path is under the user's own `.ssh` folder (`~/.ssh`, `%USERPROFILE%\\.ssh`) | An amber box before the file is read: "This file is in your own .ssh folder, so it may be a key you use every day. This course shows every key it reads on screen. Pick a test key instead." Two buttons: `Pick another file` (default) and `Use it anyway`. The Host sends the warning code `KEY_PATH_PERSONAL`. It does not block | `wizard-warning-ssh-path`, `wizard-warning-pick-another`, `wizard-warning-use-anyway` |
| The course makes a key | It writes under `.security/` in the project and never into `~/.ssh`. The Place screen says where | `wizard-file-written-to` |
| A key file is in a folder other people can read | The Host warns with `KEY_FILE_PERMISSIONS`. On Windows the wizard locks a key it made to one reader before ssh.exe uses it, and says so | `wizard-warning-permissions` |

The `~/.ssh` check runs in the Host on the path, in every SSH step that picks a file (`flow-my-ssh-file`, and `flow-my-ssh-path-warning` is its warning screen). The UI shows the warning the Host sends. It does not decide.

## 4. One full flow: Make my sign-in set (`flow-my-login`)

The first slice is `token.issuer` (`modes-design.md` slice M0). In the flows it is one part of `flow-my-login`, beside the device key. The default path is five screens. The branch is one more. Every screen uses the frame in section 3 and answers the five questions. Words are the copy-file text, and Cussler adjusts voice, not facts.

### Screen 1 of 5: Intro (`flow-my-login-intro`, state `Intro`, kind `explain`)

| Block | Words |
|---|---|
| First line | This course shows every key, so use test keys. A real system keeps these hidden. *(When Show keys is Off: "This course hides your keys on screen for now and shows short fingerprints instead. Saved files can still hold them.")* |
| What this is | This set makes two keys. The first key signs {{token}}s. A token is a small note that says who you are and what you may do, and the signature on it shows nobody changed it. The second key belongs to one device, so the device can prove who it is. |
| Why it exists | A real service signs tokens, and other services check the signature. If the signing key leaks, anyone can make tokens that pass the check. That is why real teams guard it. |
| What you do now | Read this, then choose `Continue`. The whole set takes about 2 minutes. |
| What good looks like | At the end, lesson 10 uses your keys. |
| Buttons | `Cancel setup`, `Continue` (default) |
| Fails when | Nothing here fails. |

### Screen 2 of 5: Make it for me (`flow-my-login-make`, `ChooseSource` and `Place`, kind `generate`)

| Block | Words |
|---|---|
| What this is | The course will make two keys with safe settings. Both use {{ed25519}}, a modern way to sign things, and its keys are short. |
| Why it exists | Token checks in this course read Ed25519 signatures only. So this is the kind of key that works here. |
| What you do now | Choose `Make it for me` (recommended). The course saves the keys in the `.security` folder of this project. |
| The two parts, one line each | **Token signing key.** Signs tokens for the issuer `https://pump.training/issuer`, for the audience `https://pump.training/api`. **Device key.** One device, named `pump-reader-4`, with its enrolment row, which is the record that lets the issuer recognize the device. |
| Link | `Change the defaults or use my own files` |
| What good looks like | You see `Made 2 keys`. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not save a key file. Check that you can save files in the project folder, then try again." |

### Branch: Change the defaults or use my own files (`flow-my-login-options`, kind `entry`)

One screen. Two parts. It returns to the Review screen after it makes the set.

| Part | Field | Words and default | Fails when |
|---|---|---|---|
| Change the defaults | Issuer name | "A name written inside every token. It tells the reader who signed the token. Here it is a web address." Default `https://pump.training/issuer` | `ISSUER_NAME_BAD`: "The issuer name needs to be a web address that starts with `https://`. Try `https://pump.training/issuer`." |
| Change the defaults | Audience | "Which service a token is meant for. Each service checks that its own name is in the audience." Default `https://pump.training/api` | Same as above |
| Change the defaults | Device name | "The name of the one device." Default `pump-reader-4` | none |
| Use my own files | Token key file | A {{pem}} file with an Ed25519 private key. `Choose a file` opens a window. Only the path goes to the course, meaning where the file lives on your disk | `KEY_FILE_UNREADABLE`: "The course could not open that file. Pick it again, or move it into the project folder." `KEY_FILE_FORMAT`: "The course could not read that file as a PEM key. To make one, run `openssl genpkey -algorithm ed25519 -out issuer.pem`, then pick the new file." `KEY_FILE_ENCRYPTED`: "That key is locked with a passphrase, and this course has no place to type one. For a test key, you can remove the passphrase with `openssl pkey -in issuer.pem -out issuer-open.pem`, then pick the new file." `KEY_ALGORITHM_NOT_IN_ENGINE`: "Token keys in this course must be Ed25519." |
| Use my own files | Device key file | Same as above | Same as above |

The warnings of 3.6 apply to every file pick. Nothing is saved until the learner chooses `Make it for me` or `Use these`.

### Screen 3 of 5: Review (`flow-my-login-review`, `ReadBack`, kind `review`)

| Block | Words |
|---|---|
| What this is | This shows what the course made. Read it like a receipt. |
| Why it exists | Teams read a key's details before they use it. A wrong key causes a failure far from where the mistake happened. |
| What you do now | Check the facts. Choose `Back` to make new keys, or `Continue`. |
| Token signing key | Ed25519. Fingerprint `SHA256:...`. Public key (shown when Show keys is On, a fingerprint when Off). Issuer and audience. Saved as version 1. |
| Device key | Ed25519. Fingerprint. Device `pump-reader-4`. The enrolment row the issuer will hold: the device name and its public key. |
| Line under both | These are test keys. This course shows them on screen. |
| What good looks like | The fingerprints match the ones you saw while the keys were made. |
| Fails when | Nothing fails here. The Host refused a bad key on the branch. |

### Screen 4 of 5: Check (`flow-my-login-check`, `Prove`, kind `prove`)

| Block | Words |
|---|---|
| What this is | The course asks another program to check your work. For the token key, that program is OpenSSL. It reads a token the course signed and says whether the signature is good. It checks the signature only. |
| Why it exists | If the course checked itself, a mistake could hide. A different program has no reason to agree. |
| What you do now | Choose `Check it`. |
| Token key result | The command, for example `openssl pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin`. The real output, `Signature Verified Successfully`. In words: "OpenSSL read the public half of your key and said the signature on the token is good. It checks the signature only." The chip reads `Checked by OpenSSL. It checks the signature only.` |
| Device key result | An amber note: "No outside tool can check a device key. The sign-in challenge here is modeled on a passkey's, and it is not the WebAuthn standard. Your key is saved." The chip reads `Saved, no outside check`. No green tick. |
| What good looks like | A tick for the token key, and an amber line for the device key. |
| Fails when | `REFEREE_MISSING`: "The course could not find OpenSSL on this computer. Git for Windows includes a copy. Install Git for Windows, or set `NETSEC_OPENSSL` to the path of OpenSSL, then check again. Your keys are saved." `PROOF_FAILED`: "OpenSSL said the signature is bad. The key and the token do not match. Your earlier keys are still saved. Choose `Back` and make the keys again. The output is below." |

### Screen 5 of 5: Done (`flow-my-login-done`, `Done`, kind `done`)

| Block | Words |
|---|---|
| What happened | Your sign-in keys are saved. The token key is `Checked by OpenSSL`, which means OpenSSL agreed the signature is good. The device key is `Saved, no outside check`, because no outside tool can check it. |
| Which lessons use them | Lesson 10 now signs its tokens with your token key and enrols your device key. |
| What you do now | `Run lesson 10` (when you came from a lesson), `Back to the map`, or `Use practice keys again`. |

## 5. The other four flows

Each flow runs the same five screens as section 4. This section lists what differs: what `Make it for me` makes, what the branch holds, what the Review shows, what the Check runs, and what can go wrong. Defaults: every certificate the course makes is valid from 1 January 2025 to 31 December 2049 (`TrainingCa.cs:15-16`, `modes-design.md` 3.4). The lessons run on fixed clocks: 1 January 2030 for the TLS labs and 5 November 2026 for tokens, so a default passes. The start date stays 1 January 2025, because a certificate that starts today is not yet valid on the token clock. The learner reads the reason only on the branch screen (`flow-my-certificates-options`), where dates can be changed to about 90 days. Those dates read the real clock (`LabClock.For`). The `validity` words: "The course default is long so the lessons' fixed dates pass. A real system uses about 90 days."

### 5.1 `flow-my-certificates`: Make my web security set

| Screen | Content |
|---|---|
| Make it for me makes | An {{ed25519}} certificate authority named `MMP Training Root`. A trust list that follows that root. A server certificate for `localhost`, signed by the root. A device certificate `pump-reader-4`, signed by the root. An old-style server certificate (RSA 2048, for lesson 7), signed by the root |
| Branch (`flow-my-certificates-options`) | Change the defaults: server names, device name, key kind (Ed25519, or RSA with the note "RSA runs through the OS transport"), the dates and why they are long, drop the old-style certificate. Use my own files: root PEM, server certificate and key and chain, device certificate and key with its middle authority, PKCS#12 (RSA), OS store (RSA, with "The course does not install anything in your computer's store without asking") |
| Review shows | One block per part: who it is for, who signed it, the dates, the fingerprint. A line for the trust list: "It trusts the root you made." The line "A self-signed certificate passes against itself. The check below is against the root you gave it." |
| Check runs | Chain: `openssl verify -x509_strict -CAfile root.pem -untrusted int.pem -purpose sslserver -verify_hostname localhost srv.pem`. Server: `tlspeer`, then `openssl s_client -tls1_3 ...`. Device: `tlspeer -require-client-cert`, then `openssl s_client ... -cert_chain int.pem`. Old-style: `openssl s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0`. Chips: `Checked by OpenSSL against the root you gave it`. Line after the device check: "A valid chain is not permission." Line after the old-style check: "TLS 1.1 was retired by RFC 8996. A pass does not make it safe." |
| Fails when | `CERT_NOT_A_CA` ("This certificate cannot sign other certificates, so it cannot act as an authority. Pick a certificate made for a certificate authority (CA)."). `CERT_SIGNATURE_ALG_UNSUPPORTED` ("This root uses RSA or ECDSA, and the course can check only Ed25519 signatures. Make an Ed25519 root."). `CERT_NAME_MISSING` ("This certificate does not list `localhost` as a name it answers to. Make or pick one that does."). `KEY_CERT_MISMATCH` ("This key does not go with this certificate. Pick the key that goes with it."). `CHAIN_INCOMPLETE` ("The certificate of the authority between yours and the root is missing from the file. Add it to the file. A device certificate signed by a middle authority must travel with that authority's certificate."). `PKCS12_PASSWORD` ("That file is protected by a password. Type it, or export the file again without one."). `REFEREE_MISSING` |

### 5.2 `flow-my-ssh`: Make my remote login set

| Screen | Content |
|---|---|
| Make it for me makes | An Ed25519 server identity key (modern round). An RSA 2048 server identity key (legacy round, lesson 8). An Ed25519 user key. The remembered server key (the pin), made from the modern server key |
| Branch (`flow-my-ssh-options`) | Change the defaults: drop the legacy key. Use my own files: OpenSSH files for each key (the `~/.ssh` warning of 3.6 shows first), paste a `known_hosts` line, learn the key on the first connect, "user key for the CE process" (file only) |
| Review shows | Each key's public line and `SHA256:` fingerprint. The line "Check this fingerprint a second way, for example read it from the server file. A fingerprint on this screen proves nothing." The line on the legacy key: "RSA host keys here sign with SHA-1, which is weak." |
| Check runs | `sshpeer -host-key host_key -authorized authorized_keys`, then `ssh.exe -F NUL -p <port> -i user_key -o IdentitiesOnly=yes -o UserKnownHostsFile=known_hosts -o GlobalKnownHostsFile=NUL -o StrictHostKeyChecking=yes learner@127.0.0.1 "echo hello"`, then a mismatch run that names `SSH_HOST_KEY_CHANGED`. Chips: `Checked by ssh.exe`. A user key held in the vault shows `Saved, no outside check`: no outside tool can use a vault key |
| Fails when | `KEY_FILE_FORMAT` ("That file is not an OpenSSH private key. A real one starts with `-----BEGIN OPENSSH PRIVATE KEY-----`."). `KEY_FILE_ENCRYPTED`. `KEY_ALGORITHM_NOT_IN_ENGINE` ("Sign-in keys in this course must be Ed25519."). `KNOWN_HOSTS_LINE_BAD` ("The course could not read that line. It does not accept wildcards."). `KEY_PATH_PERSONAL` (a warning) |

### 5.3 `flow-my-payment`: Type in my card PIN keys

This flow says in its name, on its first screen, and on its Check screen: **this is key entry. No outside tool can judge it.** A real key ceremony is the formal event where several people use a secure device to combine key parts. Here one person types the parts.

| Screen | Content |
|---|---|
| Make it for me makes | A test base key, 16 bytes, labeled `TEST` on screen. The PIN pad key, which comes from the base key and a key id, as a key loader would |
| Branch (`flow-my-payment-options`) | Enter my own key parts: two fields (a third if wanted), 32 hex characters each, masked while typed, each with its check value. The final check value to compare with your own paper. No choice about reading the key back: a key that cannot be read back exists only in the vault exercise (5.5), as `modes-design.md` 8 now rules |
| Review shows | The base key's fingerprint and check value. The PIN pad's key id. The line "Card numbers and PINs stay test values." |
| Check runs | The published X9.24-3 vector first, then one sale from the pad to the bank. Judge: `none`. The chip reads `Saved, no outside check`. The screen says: "The course checked the key against published test vectors. No outside system can check a base key. One person typing the parts is not dual control, which needs two people to act together." |
| Fails when | `DUKPT_COMPONENT_LENGTH` ("A component is 32 hex characters, which is 16 bytes. This one has <n> characters."). `DUKPT_KCV_MISMATCH` ("The check value does not match, which usually means a digit is wrong. Type that part again.") |

### 5.4 `flow-my-lesson-keys`: Make my data keys

| Screen | Content |
|---|---|
| Make it for me makes | One key of random bytes for lesson 1 (AES) and one for lesson 2 (seals). The Host's `my-lesson-keys` flow makes or takes bytes, with no wrapping key |
| Branch | None |
| Review shows | Each key's fingerprint and length. "A MAC is a short code that shows a message stayed the same. A password is not a MAC key. A MAC is not a signature." |
| Check runs | Judge: OpenSSL (`modes-design.md` 8.6). Seal key: `openssl mac -digest SHA256 -macopt hexkey:<hex> -in <file> HMAC`. Jared: the comparison with the engine's tag has not run yet. Chip: `Checked by OpenSSL` |
| Fails when | `VAULT_UNWRAP_FAILED` ("The key could not open what it locked. Make the keys again."). `REFEREE_MISSING` |

### 5.5 The vault exercise (separate from the flows, 3 screens)

A learner can play with the practice vault. It opens from the map footer (`sec-vault-exercise`). It changes no mode and no key in use. It runs on two throwaway keys: `exercise/signing` (signs, refuses derive) and `exercise/bdk` (derives).

| Screen | Id | Words | Learner does | Shows |
|---|---|---|---|---|
| 1 Sign and derive | `vault-sign-derive` | First line: "This course shows every key, so use test keys. A real system keeps these hidden." Then: "This is a practice vault. A real vault is a locked device called an HSM, and this is not one. It has no FIPS validation, the formal approval some real vaults hold. Refusing to export is a rule in this course's code." Sign: "A vault signs a message for you, so the key never has to leave the vault. A real vault works the same way." Derive: "A vault can make a new key from a parent key and a label. A label is any name you pick. The same label always gives the same key." | Type a message, `Sign it`, `Check it`. Type a label, `Derive` twice, then once with another label | The signature, the public key, the check result (a one-bit change fails). Each derived key's fingerprint: same label, same fingerprint |
| 2 Refuse | `vault-refuse` | "You can mark a key so it cannot be read out. To export a key is to copy it out of the vault, and a real vault then refuses every request to export it." | `Try to read this key out` on a key made non-exportable | The refusal and `VAULT_EXPORT_REFUSED`: "The vault refused. This key cannot be read out." The key view shows the fingerprint only, with the line: "The course refuses to show it. A real HSM would refuse too. These files could still open it here." |
| 3 Audit | `vault-audit` | "A vault writes down every request, so you can see who asked for what. Each row holds a short code made from the row before it, so a changed row shows up." | `Show the audit list`, `Check the chain` | Rows of time, who, what, result. Each row holds a hash of the one before. The chain check says whether any row changed |

**Routes (Q10, answered):** `POST /api/security/vault/exercise/{sign|derive|export|audit-check}`. The label typed on the Derive station is the `input` of the derive call. The Check it button on the Sign station runs `openssl pkeyutl -verify` and shows its output.

## 6. The proof step in everyday words

Every Prove screen has the same four parts, in this order: the real command in a code block, the real output in a code block, one sentence in words, and a tier line.

| Part | Rule | Test id |
|---|---|---|
| Command | The text the Host ran, with paths shortened to file names | `prove-command` |
| Output | The last 20 lines the tool printed. No editing | `prove-output` |
| In words | One sentence the copy file keeps per type: "OpenSSL read your server's certificate and said it traces to your root." | `prove-words` |
| Judge | `Judged by: OpenSSL` (or Go, or ssh.exe), or `Judged by: our own check` when no outside tool can judge. The name comes from the Host with the proof | `prove-tier` |

| Outcome | What the learner sees | Next |
|---|---|---|
| Pass | A tick and `<tool> agrees`. The chip reads `Checked by <tool> against <what it checked against>`, for example `Checked by OpenSSL against the root you gave it`. The word `trusted` never appears | `Done` |
| No outside judge | An amber note: "No outside tool can check this key, so no green check appears. Your key is saved." The chip reads `Saved, no outside check`. No green, no tick | `Done` |
| `PROOF_FAILED` | Red cross, the output, and the one-sentence cause from the copy file | `Back to the start` or `Cancel setup`. The earlier key stays saved |
| `REFEREE_MISSING` | An amber note, not a failure of the key: "The test tool is missing. Your key is saved and counts as checked once the check passes." | Fix steps in section 8 row 9. The type stays `Set up, not checked` |

### 6.1 Judge and full command for each type

The Host runs these (Jared's runs, `modes-real-world.md` section 5). Each `<...>` is a course file. Where a section 5 cell and this table differ, this table wins.

| Type | Judge | Full command or check | Words to add on the screen |
|---|---|---|---|
| `pki.root-ca`, `tls13.server` (chain) | OpenSSL | `openssl verify -x509_strict -CAfile root.pem -untrusted int.pem -purpose sslserver -verify_hostname localhost srv.pem` | "Verified means: against the root you gave it. A client trusts this root only if you told it to." |
| `tls13.server` (key) | Go and OpenSSL | `tlspeer -mode server -groups x25519 -cert chain.pem -key srv.key`, then `openssl s_client -connect 127.0.0.1:<port> -tls1_3 -CAfile root.pem -verify_return_error -verify_hostname localhost -brief` | none |
| `tls13.client` | Go | `tlspeer -mode server -groups x25519 -require-client-cert -cert chain.pem -key srv.key -ca root.pem`, then `openssl s_client ... -cert client.pem -key client.key -cert_chain int.pem -brief` | "A valid chain is not permission. The server still decides what this client may do. No outside tool judges the name check, so that part is our own check." |
| `tls11.server` | OpenSSL | `openssl s_client -connect 127.0.0.1:<port> -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile root.pem -verify_return_error -verify_hostname localhost` | "TLS 1.1 was retired by RFC 8996. A pass here does not make it safe to use." |
| `ssh.host-*`, `ssh.client` | ssh.exe and Go | `sshpeer -host-key host_key -authorized authorized_keys`, then `ssh.exe -F NUL -p <port> -i user_key -o IdentitiesOnly=yes -o UserKnownHostsFile=known_hosts -o GlobalKnownHostsFile=NUL -o StrictHostKeyChecking=yes learner@127.0.0.1 "echo hello"` | Windows only: lock `user_key` with `icacls` first. The wizard does this and says so. |
| `ssh.known-hosts` | ssh.exe | Same run. The wizard passes `-f` with a course folder and never uses the default key path | "A fingerprint on this screen proves nothing: compare it on a second channel. `accept-new` proves only that later connects match the first one." |
| `token.issuer` | OpenSSL | `openssl pkeyutl -verify -pubin -rawin -in <signing input> -sigfile <signature>` (`modes-design.md` 8.6). Lead's ruling, 2026-11-05: the product cannot depend on `acceptance/referees`, so OpenSSL judges, and clause A11 judges the rest | "This check covers the signature only, not the dates, the audience, or the algorithm name. A token can be read by anyone who sees it. The signature stops changes, and it hides nothing." |
| `device.enrolment` | none | The course's own check | `Judged by: our own check.` "Enrolling the key this client just showed is not enrolment. The sign-in challenge here is modeled on a passkey's, and it is not the WebAuthn standard." No green outside proof. |
| `dukpt.bdk`, `dukpt.pad` | none live | Published X9.24-3 vectors, then a round trip | "Checked against published vectors, no outside system. A real base key stays inside an HSM, a locked hardware device. This file is not a TR-31 file, the standard format for moving keys safely. One person typing the parts is not dual control, which needs two people to act together." |
| `lab.aes-key` | .NET library | Wrap, unwrap, compare with BCL `AesGcm` | none |
| `lab.seal-key` | OpenSSL | `openssl mac -digest SHA256 -macopt hexkey:<hex> -in <file> HMAC`. The command ran. A comparison with the engine's tag has not run yet | "A MAC is a short code that shows a message stayed the same. A password is not a MAC key. A MAC is not a signature." |

Rule for every Prove screen (Jared): show the command, its real output, and the name of who judged it. With no outside judge, say "our own check".

## 7. Show keys on every wizard screen

| Where | With the switch On | With the switch Off |
|---|---|---|
| Read-back facts | The key bytes in a `Show all` fold, copy button | `fp:` fingerprint and length, "Hidden by the Show keys switch" |
| Prove output | As the tool printed | The tool output is unchanged (it holds public data), key file paths only |
| DUKPT component fields | Masked while typed, always. The check value shows | Same |
| The setup screen header | Test-keys line says "This course shows every key, so use test keys. A real system keeps these hidden." | Says "This course hides your keys on screen for now and shows short fingerprints instead. Saved files can still hold them." |
| A non-exportable key | Shows the fingerprint only, no bytes, with the line "The course refuses to show it. A real HSM would refuse too. These files could still open it here." | Same |
| The vault itself (map footer, vault exercise) | Label: "Practice vault. Not an HSM. Not FIPS validated." Non-export is a rule in this course's code. | Same |

Flipping the switch while a wizard is open replaces the facts block from the Host. The wizard does not move.

## 8. True statements the wizards must make

| # | Statement | Where it appears | Source |
|---|---|---|---|
| 1 | A public certificate authority will not sign a certificate for `localhost`. A public CA signs only after you show you control a public name, and `localhost` belongs to nobody. So the server certificate here comes from a certificate authority you make yourself. | `flow-my-certificates-intro` and `flow-my-certificates-options` | `modes-design.md` 1.8; the course's training CA |
| 2 | A self-signed certificate is not a chain. It vouches for itself, so nothing outside it proves it. A chain ends in a root that the checker already trusts. | `pki.root-ca` Intro, `tls.trust` Intro | PRD framing; `ChainCheck` |
| 3 | The course's own engines check Ed25519 signatures only. An RSA or ECDSA certificate stops with a named error code. RSA runs through the OS transport. ECDSA is not supported in the course's engines. | `KEY_ALGORITHM_NOT_IN_ENGINE` and `CERT_SIGNATURE_ALG_UNSUPPORTED` boxes, kind choice screens | `modes-design.md` 1.8, 8.5 |
| 4 | A certificate signed by a middle authority must be sent together with that authority's certificate. This holds for a client too. Sent alone, it gets the error `certificate signed by unknown authority`. | `tls13.client` screen 4 and `CHAIN_INCOMPLETE` | Jared's finding, `modes-design.md` 8.5 |
| 5 | This course shows every key, so use test keys. A real system keeps these hidden. Nothing here can tell a test key from a production key, so the line is the whole control (Steve's ruling: no hard stop). | Every Intro, before any choice | `modes-design.md` 8.2 |
| 6 | The key store is a plain file, and anyone who holds both files can read every key. It is not a production vault. | `Place` screens | `modes-design.md` O5 |
| 7 | Card numbers and PINs stay test values. The wizard has no field for them. | `dukpt.bdk` Intro, `dukpt.pad` Intro | `modes-design.md` 1.6, O10 |
| 8 | A key you mark as non-exportable shows its fingerprint only. "The course refuses to show it. A real HSM would refuse too. These files could still open it here." The choice is one-way. | the vault exercise (5.5) | `modes-design.md` 6.3 |
| 9 | If the test tool is missing, your key is saved but not yet checked, and lessons will not run on it until it is. | Prove screen, `REFEREE_MISSING` | `modes-design.md` 2.3 |
| 10 | Where no outside tool can judge a key, the screen says so and shows no green check. The course never checks its own key and calls it proof. | `prove-tier`, `Saved, no outside check` | Steve, 2026-11-05; Jared section 5 |
| 11 | "Checked" means checked against the root you gave it. A self-signed certificate passes against itself. The check does not say a stranger would trust it. | `Checked` chip help text, every F1 Prove screen | Jared, section 3.1 |
| 12 | The wizard never installs a root in the OS store without asking, and says what it changed. | `os-pick` step | Jared, section 3.1 |
| 13 | A valid chain is not permission. | `tls13.client` Done | Jared, section 3.3 |
| 14 | A fingerprint on the same screen proves nothing. Compare it on a second channel. | `ssh.known-hosts` `compare` step | Jared, section 3.4 |
| 15 | The ssh setting `accept-new` proves nothing on the first connect. It proves only that later connects match the first one. | `ssh.known-hosts` `learn` step | Jared, section 3.5 |
| 16 | A real base key stays inside an HSM, a locked hardware device. This file is not a TR-31 file, the standard format for moving keys safely. One person is not dual control, which needs two people to act together. | `dukpt.bdk` Intro and `combine` step | Jared, section 3.7 |
| 17 | A MAC is a short code that shows a message stayed the same. A password is not a MAC key. A MAC is not a signature. | `lab.seal-key` Intro | Jared, section 3.8 |
| 18 | A token is readable by anyone who sees it. The `iss` claim, the issuer name inside the token, counts only if the code reads it. | `token.issuer` Intro and Done | Jared, section 3.9 |
| 19 | DPoP, a way to tie a token to the client that holds a key, stops token theft. Code running on the client can still make new proofs while it is online. | Lesson 10 callout, not a wizard | Jared, section 3.10 |
| 20 | Enrolling the key a client just showed is not enrolment. The sign-in challenge here is modeled on a passkey's, and it is not the WebAuthn standard. No proof screen. | `device.enrolment` Intro | Jared, sections 3.11 and 3.12 |
| 21 | The lessons run on a fixed clock. The TLS labs read 1 January 2030, and the token lab reads a fixed day in November 2026. A certificate must be valid on those dates. A 90-day certificate made today would look expired in the labs. | `flow-my-certificates-options` | `Tls13Lab.cs:40`, `Lesson07Tls11.cs:29`, `Lesson10Auth.cs:47` |
| 22 | This is key entry, and a real key ceremony is a bigger event. A real ceremony uses a secure device and several people. Here one person types the parts. No outside tool can judge the result. | `flow-my-payment-intro`, `flow-my-payment-check`, `flow-my-login-check` | Steve, 2026-11-05; Jared section 3.7 |

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

### 9.1a Flows and the map's detail view

| Area | Ids |
|---|---|
| Page | `sec-view-flows`, `sec-view-all`, `sec-flow-<flow>` for `my-certificates`, `my-ssh`, `my-payment`, `my-login`, `my-lesson-keys`, `sec-flow-start-<flow>`, `sec-vault-exercise` |
| Flow frame | `flow-sheet`, `flow-part-progress` (reads `Screen 2 of 5`), `flow-title` |
| Flow screens | `flow-<flow>-intro`, `flow-<flow>-make`, `flow-<flow>-review`, `flow-<flow>-check`, `flow-<flow>-done`, and `flow-<flow>-options` for `my-certificates`, `my-ssh`, `my-payment`, `my-login` |
| Flow controls | `flow-make-button` (`Make it for me`), `flow-options-link` (`Change the defaults or use my own files`), `flow-part-<typeId>` (one block per part on Review and Check) |
| Vault exercise | `vault-exercise`, `vault-sign-derive`, `vault-refuse`, `vault-audit` and the ids in 5.5: `vault-sign-message`, `vault-sign-run`, `vault-sign-result`, `vault-sign-check`, `vault-derive-label`, `vault-derive-run`, `vault-derive-result`, `vault-refuse-run`, `vault-refuse-result`, `vault-audit-run`, `vault-audit-row-<n>`, `vault-audit-check` |
| Warnings | `wizard-warning-ssh-path`, `wizard-warning-pick-another`, `wizard-warning-use-anyway`, `wizard-warning-permissions`, `wizard-file-written-to` |
| State chips | `type-state-<typeId>` with `data-state` one of `practice`, `needs-setup`, `not-checked`, `checked`, `no-outside-check`, `broken` |

### 9.2 Wizard frame

`wizard-sheet`, `wizard-title`, `wizard-progress`, `wizard-what`, `wizard-why`, `wizard-do`, `wizard-good`, `wizard-control`, `wizard-test-keys-line`, `wizard-error`, `wizard-error-code`, `wizard-error-fix`, `wizard-error-details`, `wizard-back`, `wizard-cancel`, `wizard-next`, `wizard-next-reason`, `wizard-cancel-sheet`, `wizard-keep-place`, `wizard-throw-away`.

Controls: `wizard-choice-<choiceId>` (radio), `wizard-field-<fieldId>` (text entry), `wizard-file-button`, `wizard-file-path`, `wizard-generate-button`, `wizard-facts`, `wizard-fact-<name>`, `wizard-show-all`, `wizard-copy`.

### 9.3 Screens and counts

The screens are the ids in 9.1 and 9.1a. A test walks the default path of every flow and asserts the Host's `step.state` on each screen.

| Group | Ids | Count |
|---|---|---|
| Default path | `flow-<flow>-intro`, `-make`, `-review`, `-check`, `-done` for 5 flows | 25 |
| Branch | `flow-my-certificates-options`, `flow-my-ssh-options`, `flow-my-payment-options`, `flow-my-login-options` | 4 |
| Vault exercise | `vault-sign-derive`, `vault-refuse`, `vault-audit` | 3 |
| Shell | Security setup (flow view), all-keys view, refusal banner, keep-my-place sheet | 4 |
| **Total, all paths** | | **36** |
| **One flow, default path** | | **5** |

### 9.4 Prove step

`prove-command`, `prove-output`, `prove-words`, `prove-tier`, `prove-run`, `prove-pass`, `prove-fail`, `prove-missing`.

### 9.5 Acceptance clauses this table supports (for Echo)

| Proposed id | Asserts |
|---|---|
| `A17.ui.map-has-15-rows` | The all-keys view shows 15 rows with the ids above |
| `A17.ui.five-flows` | The flow view shows 5 flow cards with the goals of section 1.4 |
| `A17.ui.non-export-line` | A non-exportable key shows its fingerprint only, with the line of section 7 |
| `A17.ui.first-screen-line` | Every flow's `intro` and `vault-sign-derive` show "This course shows every key, so use test keys. A real system keeps these hidden." first |
| `A17.ui.no-real-label` | No label on screen reads `Real`, and no state reads `Proven` or `trusted` |
| `A17.ui.ssh-path-warning` | Picking a file under `.ssh` shows `wizard-warning-ssh-path` and does not read the file until the learner confirms |
| `A17.ui.no-outside-judge` | Card and device key flows show `Saved, no outside check` and no green tick |
| `A17.ui.vault-exercise` | The 3 vault screens show sign, derive, refuse, and audit results, and refuse names `VAULT_EXPORT_REFUSED` |
| `A17.ui.mode-switch-undo` | `type-mode-practice-<id>` is always enabled and returns the row to Practice |
| `A17.ui.refusal-names-types` | A lesson on an unready type shows `security-needs-banner` with one `needs-row-<id>` per type |
| `A17.ui.default-path-5-screens` | Each flow's default path shows 5 screens in order: intro, make, review, check, done |
| `A17.ui.signin-walk` | `flow-my-login` shows the screens of section 4 and ends with the token key `Checked by OpenSSL` and the device key `Saved, no outside check` |
| `A17.ui.next-reason-present` | `wizard-next-reason` exists on every screen, empty when `wizard-next` is enabled |
| `A17.ui.error-names-fix` | Every `wizard-error` has a non-empty `wizard-error-fix` |
| `A17.ui.show-keys-switch` | The switch flips key bytes to fingerprints in `wizard-facts` |
| `A17.ui.resume` | After closing the sheet, `type-action-<id>` reads `Continue setup` and reopens the same step |
| `A17.copy.grade` | `wizard-copy.json` scores grade 8.9 or lower |
| `A17.copy.tic-gate` | `tic-gate.py` passes on the copy file |

## 10. Mockups

### 10.1 Security setup screen (section 1.2)

```
+-----------------------------------------------------------------------------------------------+
| Network Security Lab [TRAINING ONLY] [Keys: 2 of mine] [engine connected]                     |
|                       [Security setup (1)]  Tour|Free  Endpoints|..  Show keys (o)            |
+-----------------------------------------------------------------------------------------------+
| Security setup                                           [Back to lessons]                    |
| This course shows every key, so use test keys. A real system keeps these hidden.              |
|                                                                                               |
| +-- Run a lesson with my own keys ----------------------------------------+                   |
| |  Lesson: [ 10 Client proof and permission v ]            [ Start ]       |                  |
| +--------------------------------------------------------------------------+                  |
|                                                                                               |
| WEB SECURITY (TLS)                                                                            |
| Certificate authority      Practice | My test key [Checked]       Lessons 4,5,7,10 [Change]   |
| Server certificate (1.3)   Practice | My test key [Needs setup]   Lessons 4,5,7,9,10 [Set up] |
| Trusted authorities        Practice | My test key [Practice key]  ...      [Set up my own]    |
|   Set up the certificate authority first.  (link)                                             |
| ...                                                                                           |
| SIGN-IN TOKENS                                                                                |
| Token signing key          Practice | My test key [Setup paused, step 3 of 5] [Continue setup]|
| ...                                                                                           |
|                                              [ Use practice keys everywhere ]                 |
+-----------------------------------------------------------------------------------------------+
```

### 10.2 Flow screen 3 of 5, Review (section 4)

```
+------------------------------------------------------------+
| Make my sign-in set                    Screen 3 of 5   [x] |
| ---------------------------------------------------------- |
| WHAT THIS IS                                               |
|  This shows what the course made. Read it like a receipt.  |
| WHAT YOU DO NOW                                            |
|  Check the facts. Choose Back to make new keys, or Continue.|
|  TOKEN SIGNING KEY                                         |
|    Kind          Ed25519                                   |
|    Fingerprint   SHA256:Qk3...n9w=                         |
|    Public key    7c1e 9a02 ...   [Show all] [Copy]         |
|    Issuer        https://pump.training/issuer              |
|    Audience      https://pump.training/api                 |
|  DEVICE KEY (Device key entry)                             |
|    Device        pump-reader-4                             |
|    Fingerprint   SHA256:Zp1...c0A=                         |
|  These are test keys. This course shows them on screen.    |
| ---------------------------------------------------------- |
| [Back]                          [Cancel setup]  [Continue] |
+------------------------------------------------------------+
```

### 10.3 Flow screen 4 of 5, Check (section 6)

```
+------------------------------------------------------------+
| Make my sign-in set                    Screen 4 of 5   [x] |
| ---------------------------------------------------------- |
|  TOKEN SIGNING KEY                                         |
|  $ openssl pkeyutl -verify -pubin -inkey issuer.pub ...   |
|  Signature Verified Successfully                           |
|  [tick] OpenSSL read the public half of your key           |
|         and said the signature on the token is good.       |
|         Checked by OpenSSL. It checks the signature only.  |
|  DEVICE KEY                                                |
|  [amber] No outside tool can check a device key.           |
|          The sign-in challenge is modeled on a passkey's,  |
|          and it is not the WebAuthn standard.              |
|          Your key is saved. Saved, no outside check.       |
| ---------------------------------------------------------- |
| [Back]                                       [Continue]    |
+------------------------------------------------------------+
```

## 11. Glossary terms to add

Each gets a `short` of 20 words or fewer at grade 8, in `app/src/glossary.json`. Every `{{term:id}}` in the copy file must resolve (the test in `ux-design.md` section 5).

`token`, `issuer`, `audience`, `pem`, `ed25519`, `rsa`, `ecdsa`, `certificate`, `ca`, `root-ca`, `chain`, `intermediate`, `leaf`, `self-signed`, `trust-store`, `subject`, `san`, `fingerprint`, `public-key`, `private-key`, `key-pair`, `pkcs12`, `known-hosts`, `host-key`, `user-key`, `openssh`, `bdk`, `dukpt`, `key-component`, `kcv`, `xor`, `hsm`, `exportable`, `vault`, `referee`, `enrolment`, `dpop`, `mutual-tls`, `eku`, `wrapping-key`.

## 12. Open questions

| # | Question | My pick | What would change it |
|---|---|---|---|
| Q1 | Jared's file landed (`ab12da8`). Does it change if his referee runs change? | Sections 6.1 and 8 follow it. Recheck on any change | A command in 6.1 stops working on a learner key (TLS 1.1 has run with the training root only) |
| Q2 | Electron file dialog through one IPC call, `pickFile` | **Decided yes (lead, 2026-11-05).** Electron's own `dialog.showOpenDialog`, no package | Closed |
| Q3 | Resume after quitting needs `openWizardId` on each type in `GET /api/security`, and the Host storing wizard state without secrets | **Decided yes.** Richard adds it | Closed |
| Q4 | `dukpt.bdk` at 12 one-decision screens | **Moot.** Grouped into `flow-my-payment` (12 screens, shared with the pad) | Closed |
| Q5 | `Use practice keys for this lesson` (banner button) flips types to Mock from a lesson screen. Does it need a confirmation? | One line of confirmation, no modal | Any user who flips by accident |
| Q6 | New Host codes the copy needs: `ISSUER_NAME_BAD`, and a `canGoReal`/`whyNot` text for each dependency. Richard adds them. | Add | The Host reuses an existing code |
| Q7 | Default validity | **Changed (richard-design).** Defaults: 2025-01-01 to 2049-12-31, as `TrainingCa.cs:15-16`. Learner-picked dates on the branch read the real clock. Labs keep the fixed clock for default certificates, so golden traces do not move | `modes-design.md` 3.4 changes |
| Q8 | Rename the OS-transport button | **Decided yes:** `OS transport`, in the same slice | Closed |
| Q9 | Flows: `POST /api/security/flows/{flowId}/runs`, then `POST /api/security/runs/{id}/events`. The Host owns part order, defaults, and shared answers through `wizard-flows.json`. Flow ids are the Host's | **Answered (richard-design), owner richard-modes** | Closed |
| Q10 | Vault exercise: `POST /api/security/vault/exercise/{sign|derive|export|audit-check}`, reaching only `exercise/*` keys: `exercise/signing` and `exercise/bdk`. `export` always returns `VAULT_EXPORT_REFUSED`. A signing key refuses `derive` with `VAULT_OP_REFUSED`. `Check it` on Sign runs `openssl pkeyutl -verify` and shows its output | **Answered (richard-design), owner richard-modes** | Closed |
| Q11 | A type with no outside judge: state `Verified` with `judge: none`, and a lab may run. Two limits: the own check must still pass (a failed own check stays `Configured`), and `judge` belongs to the binding, so a file `ssh.client` keeps `ssh.exe` as its judge and only a vault-held one is `none` | **Answered (richard-design), owner richard-modes** | Closed |
| Q12 | `KEY_PATH_PERSONAL` is the code for the `~/.ssh` warning (already in `modes-design.md` 8.5). `KEY_FILE_PERMISSIONS` is new and accepted. The step payload gains `warnings[]` beside `errors[]`, each with `code` and a default choice | **Answered (richard-design), owner richard-modes** | Closed |

No new package is needed. The design uses Vue 3, Vuetify, and the existing glossary tooltips. The Electron file dialog is part of Electron.
