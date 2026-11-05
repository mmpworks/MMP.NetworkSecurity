# MMP.NetworkSecurity: setup wizards, UX design

Author: Nancy. Date: 2026-11-05. Status: design for review, no product code. Branch `docs/wizards-ux`, off `docs/security-modes` (`d124d62`).
Inputs: `docs/modes-design.md` (sections 1, 2, 6, 8, 10), `docs/ux-design.md`, Steve's request (quoted in section 0). Jared's `docs/modes-real-world.md` (branch `docs/modes-real-world`, commit `ab12da8`) supplies the per-type limits (section 8) and the referee commands (section 6.1). Section 12 lists what to recheck if his file changes.

## Conclusion

1. **Five "make my set" flows, each with a plain goal, are the front door. The 15-row map stays as the detail view.** A flow builds a whole group of keys and certificates in one walk. The Host's step machine owns every move. The UI draws the step it is given and sends the answer back.
2. **The learner starts from a goal, not from a list of key types.** The five goal buttons are in section 1.4. "I want to run lesson 10 with my own keys" still works: the Host lists the flows that lesson needs, in dependency order.
3. **Every screen answers five questions in the same order:** what is this, why does it exist in the real world, what do I do now, what does success look like, and what do I do if it fails. One decision per screen, with a recommended default already selected.
4. **The last step of every wizard is "prove it works".** It shows the real command and the real output of a separate tool (OpenSSL, `ssh.exe`) in everyday words, and states whether the proof came from an outside tool or from this course's own code.
5. **The first slice is `token.issuer` (family F6, `modes-design.md` slice M0).** Section 4 walks its eight screens with the words on each. In the flows it is one part of flow 4. Section 5 lists the other 14 types. Section 5.1 adds a separate vault exercise screen.
6. **The wizards say true things that are easy to skip.** A public CA will not sign `localhost`. A self-signed certificate is not a chain. A key typed here is a test key, and this course shows it on screen. Section 8 lists each statement and where it appears.
7. **Labels never say "Real".** A switched-on type reads `My test key`. A green state never reads as "trusted": it reads `Checked by OpenSSL against the root you gave it`. Where no outside tool can judge (card keys, device keys), the screen says so, and the state reads `Saved, no outside check`. The course never checks its own key and calls it proof.
8. **Disposition:** ready for review by Steve, Richard, and Echo. Echo can write acceptance clauses from the test ids in section 9. Section 12 holds the open questions. The design has 70 screens (section 9.3).

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
| A wizard is open | `Setup paused at step 3 of 8` | `Continue setup` |

### 1.3 How a learner arrives from a lesson

A lesson that reads a type set to My test key that is not `Verified` does not start. The Host answers `session.start` with `SECURITY_TYPE_NOT_READY` or `SECURITY_TYPE_NOT_PROVEN`, naming each type. The UI shows this banner over the tour panel and the diagram, never a silent fallback:

| Part | Words (copy id `sec.refusal.*`) | Test id |
|---|---|---|
| Banner | "Lesson 10 needs 2 keys that still need setting up." | `security-needs-banner` |
| One line per type | "Server certificate: needs setup. [Set up now]" | `needs-row-<typeId>`, `needs-setup-<typeId>` |
| Second button | `Use practice keys for this lesson` (flips only the needed types to Mock, after a one-line confirmation) | `needs-use-practice` |

The lesson rail shows a small key badge on a lesson whose types are not ready (`lesson-keys-badge-<n>`, title "2 keys need setup"). Clicking it opens the same banner. The wizard opened this way returns to the lesson when it finishes (section 3.5).

### 1.4 The five flows

Steve chose five grouped "make my set" flows over fifteen separate wizards. A flow walks the learner through one group of keys and certificates in one sitting. It asks each shared question once (names, key kind, source) and applies the answer to every part. The 15-row map in 1.2 stays as the detail view: its `Set up` and `Change` buttons open the flow at that row's part.

| # | Goal button (plain words) | Makes (type ids) | Lessons | Flow id |
|---|---|---|---|---|
| 1 | Make my web security set | `pki.root-ca`, `tls.trust`, `tls13.server`, `tls13.client`. Optional: `tls11.server` | 4, 5, 7, 9, 10 | `flow-tls` |
| 2 | Make my remote login set | `ssh.host-ed25519`, `ssh.client`, `ssh.known-hosts`. Optional: `ssh.host-rsa` | 8, 9 | `flow-ssh` |
| 3 | Enter my card PIN keys (key entry) | `dukpt.bdk`, `dukpt.pad` | 6, 9 | `flow-dukpt` |
| 4 | Make my sign-in set | `token.issuer`, `device.enrolment` (named "Device key entry") | 10 | `flow-signin` |
| 5 | Make my data keys | `lab.aes-key`, `lab.seal-key` | 1, 2 | `flow-data` |

Every flow opens with the same first screen, before any choice. The words:

> **This course shows every key, so use test keys. A real system keeps these hidden.**

It is followed by what the flow makes, how long it takes, and what the learner will have at the end. This line is the first thing on the first screen of all five flows and of the vault exercise.

#### Screens of each flow

Ids are `flow-<flow>-<step>`. "Library" means the step is the same screen as the per-type step in sections 4 and 5, shown once for the whole set. Each flow ends on a `done` screen with `Run lesson N`, `Back to the map`, and `Use practice keys again`.

| Flow | Screens in order | Count |
|---|---|---|
| `flow-tls` | `intro`, `parts` (tick which parts: all but the old-style server by default), `source` (Make it for me, default; or bring files), `kind` (Ed25519 default; RSA noted), `names` (server names, device name), `validity` (until 2032-01-01 by default, with the clock reason), `readback` (the whole set), `place`, `prove-chain`, `prove-server`, `prove-client`, `prove-tls11` (only if ticked), `done` | 13 |
| `flow-tls`, bring-your-own branch | `file`, `keyfile`, `chain`, `p12-password`, `os-pick` | 5 |
| `flow-ssh` | `intro`, `parts`, `source`, `file` (with the `~/.ssh` warning, 3.6), `path-warning`, `readback`, `place`, `compare` (check the fingerprint on a second channel), `prove-host`, `prove-client`, `prove-pin`, `done` | 12 |
| `flow-dukpt` | `intro` (says "key entry" and "no outside tool can judge this"), `why-entry`, `component-1`, `component-2`, `third-component`, `combine`, `readable`, `readback`, `place`, `pad-follows`, `checked-note` (what was checked, and against what), `done` | 12 |
| `flow-signin` | `intro`, `parts`, `source`, `file`, `issuer`, `audience`, `subject` (device), `readback`, `place`, `prove-token`, `device-entry-note` ("No outside tool can judge a device key. A passkey-shaped challenge is not WebAuthn."), `done` | 12 |
| `flow-data` | `intro`, `source`, `readback`, `place`, `prove`, `done` | 6 |

Where a flow has `prove-<part>` screens, each runs the judge from section 6.1 in turn and shows its own result. A part with no outside judge shows the amber note and the chip `Saved, no outside check`. No part ends in a green tick that the course gave itself.

#### How section 4 and 5 map into the flows

| Section 4 or 5 step | Appears in a flow as |
|---|---|
| Intro | `flow-<flow>-intro` (one per flow, with the test-keys line first) |
| ChooseSource | `flow-<flow>-source` (one answer for the whole set where possible) |
| Type-specific entry (names, kind, validity, components) | The flow's `names`, `kind`, `validity`, `issuer`, `audience`, `subject`, `component-n` steps |
| ReadBack, Place | `flow-<flow>-readback`, `flow-<flow>-place`, once for the set |
| Prove | One `prove-<part>` screen per part |
| Done | `flow-<flow>-done` |

#### Contract request for Richard

Today the Host's machine runs one wizard per type (`modes-design.md` 8.1: `POST /api/security/wizards {typeId}`). A flow needs `POST /api/security/wizards {flowId}`. The Host owns the part order and the shared answers. The UI must not chain per-type wizards itself, because then the UI would own the moves. Flow tables are data, as the family tables are. This is open question Q9.

## 2. The flow

### 2.1 First time

| Step | What the learner sees | Who decides |
|---|---|---|
| 0 | Everything is Practice. Nothing needs doing. The first-run line on the Security setup screen: "Every lesson works now with built-in practice keys. Set up your own keys whenever you like." | Host: all types Mock |
| 1 | Learner opens Security setup and picks a flow card (section 1.4), or picks a lesson in the goal card | Learner |
| 2 | The screen lists the types that lesson needs, in order, each with its state | Host: `LabCatalog.Needs(lesson)` plus dependency order |
| 3 | `Start` opens the first wizard in that list. When it finishes, the next one opens with a `Next: <title>` button | Host: wizard machine |
| 4 | When all are `Checked` (or `Saved, no outside check`), the goal card shows `Run lesson 10 now` | Host: `SecurityReadiness.Decide` |

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
2. One idea per sentence, 20 words at most. Active voice. Assume the reader knows nothing about this field: not what a key, a certificate, a signature, or trust means. The reader may be an experienced engineer, and that changes nothing. Steve's rule is to assume no knowledge. So no step uses a term before it explains the term. The first use of a term in a screen is a glossary term (`{{term:id}}`).
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
| Learner flips the mode switch to `My test key` with no binding | The wizard opens at once. Closing it with `Keep my place` leaves the mode at `My test key`, state `Needs setup`, and the banner in 1.3 appears at the next lesson start | Exists |
| A wizard finishes and a lesson sent the learner here | `Done` shows `Back to lesson 10`, which closes the sheet and starts the lesson | UI only |

### 3.6 File warnings

| Case | What the learner sees | Test id |
|---|---|---|
| The chosen path is under the user's own `.ssh` folder (`~/.ssh`, `%USERPROFILE%\\.ssh`) | An amber box before the file is read: "This file is in your own .ssh folder. It may be a key you use every day. This course shows every key it reads. Pick a test key instead." Two buttons: `Pick another file` (default) and `Use it anyway`. The Host sends the warning code `PATH_IN_USER_SSH`. It does not block | `wizard-warning-ssh-path`, `wizard-warning-pick-another`, `wizard-warning-use-anyway` |
| The course makes a key | It writes under `.security/` in the project and never into `~/.ssh`. The Place screen says where | `wizard-file-written-to` |
| A key file is in a folder other people can read | The Host warns with `KEY_FILE_PERMISSIONS`. On Windows the wizard locks a key it made to one reader before ssh.exe uses it, and says so | `wizard-warning-permissions` |

The `~/.ssh` check runs in the Host on the path, in every SSH step that picks a file (`flow-ssh-file`, and `flow-ssh-path-warning` is its warning screen). The UI shows the warning the Host sends. It does not decide.

## 4. One full wizard: the token signing key (`token.issuer`, family F6)

The first slice. Source choices in M0 are file-backed (`modes-design.md` slice M0): `Make a test key for me` writes an Ed25519 key file under `.security/`, and `Use a key file I already have` reads a PEM. The vault source (M1) adds nothing to the screens.

Eight screens. Ids are `wiz-token-issuer-<n>` with the Host's state in brackets. Words are the copy-file text; Cussler will adjust voice, not facts.

### Screen 1 of 8: Intro (`wiz-token-issuer-intro`, state `Intro`, kind `explain`)

| Block | Words |
|---|---|
| Title | Set up: the key that signs tokens |
| What this is | A {{token}} is a small note that says who you are and what you may do. The note carries a signature, and the key you set up here makes that signature. |
| Why it exists | In a real system, one service signs the tokens and every other service checks the signature. If the signing key leaks, anyone can make tokens that pass the check. That is why real teams guard it. |
| What you do now | Read this, then choose `Continue`. Next you will make or pick a key, choose two names, and test it. This takes about 3 minutes. |
| What good looks like | At the end, lesson 10 signs its tokens with your key. A separate tool called OpenSSL checks the signatures and agrees they are good. |
| Test-keys line (first, before any choice) | This course shows every key, so use test keys. A real system keeps these hidden. *(When Show keys is Off the line reads: "This course hides your keys on screen for now and shows short fingerprints instead. Saved files can still hold them.")* |
| Buttons | `Cancel setup`, `Continue` (default) |
| Fails when | Nothing here fails. |

### Screen 2 of 8: Choose a source (`wiz-token-issuer-source`, `ChooseSource`, kind `choose`)

| Block | Words |
|---|---|
| What this is | A signing key is a long secret number. The course can make a new one for you, or you can use a key file you already have. |
| Why it exists | Real teams do both. A team makes a key once, keeps it safe, and tells the service where to find it. |
| What you do now (one decision) | Choose one. **Make a test key for me** is Recommended, so pick it if you are unsure. The other choice is Use a key file I already have. |
| What good looks like | You will see the key's fingerprint on two later screens. It is a short code that stands for the key, so you can tell which key you chose. |
| Choices | `make` (default), `file` |
| Fails when | Nothing here fails. |

### Screen 3 of 8, path A: Generate (`wiz-token-issuer-generate`, kind `generate`)

| Block | Words |
|---|---|
| What this is | The course will make an {{ed25519}} key. Ed25519 is a modern way to sign things, and its keys are short. |
| Why it exists | The token checks in this course read Ed25519 signatures only. So this is the kind of key that works here. |
| What you do now | Choose `Make the key`. The key is saved in the `.security` folder of this project. |
| What good looks like | You see `Key made` and the key's fingerprint. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not save the key file. Check that you can save files in the project folder, then try again." |

### Screen 3 of 8, path B: Pick a file (`wiz-token-issuer-file`, kind `file`)

| Block | Words |
|---|---|
| What this is | A {{pem}} file is a text file. The key sits between two lines that start with five dashes. |
| Why it exists | PEM is the usual way to move a key from one tool to another. OpenSSL, a widely used tool, can make one. |
| What you do now | Choose `Choose a file`. A window opens. Pick your private key file. Only its path goes to the course, meaning where the file lives on your disk. |
| What good looks like | You see `Read it: an Ed25519 key` and its fingerprint. |
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not open that file. Pick it again, or move it into the project folder." `KEY_FILE_FORMAT`: "The course could not read that file as a PEM key. To make one, run `openssl genpkey -algorithm ed25519 -out issuer.pem`, then pick the new file." `KEY_FILE_ENCRYPTED`: "That key is locked with a passphrase, and this course has no place to type one. For a test key, you can remove the passphrase with `openssl pkey -in issuer.pem -out issuer-open.pem`, then pick the new file." `KEY_ALGORITHM_NOT_IN_ENGINE`: "That key is RSA or ECDSA, and the token checks here read Ed25519 only. Make an Ed25519 key instead." |

### Screen 4 of 8: Name the issuer (`wiz-token-issuer-issuer`, kind `entry`)

| Block | Words |
|---|---|
| What this is | The {{issuer}} is a name written inside every token. It tells the reader who signed the token. Here the name is a web address. |
| Why it exists | A service that checks a token must know whose signature to trust. The issuer name tells it which key to use. |
| What you do now | Keep the suggested name `https://pump.training/issuer`, or type another web address. |
| What good looks like | The name starts with `https://`. |
| Fails when | `ISSUER_NAME_BAD`: "The issuer name needs to be a web address that starts with `https://`. Try `https://pump.training/issuer`." *(Code to add in the Host list; open question Q6.)* |

### Screen 5 of 8: Name the audience (`wiz-token-issuer-audience`, kind `entry`)

| Block | Words |
|---|---|
| What this is | The {{audience}} is a name written inside the token that says which service the token is meant for. |
| Why it exists | A token made for the pump API must not work on the billing service. Each service checks that its own name is in the audience. |
| What you do now | Keep `https://pump.training/api`, or type another web address. |
| What good looks like | The name starts with `https://`. |
| Fails when | Same as screen 4. |

### Screen 6 of 8: Read it back (`wiz-token-issuer-readback`, `ReadBack`, kind `review`)

| Block | Words |
|---|---|
| What this is | Below is what you chose so far. Nothing is saved yet. |
| Why it exists | Real teams read a key's details before they use it. A wrong key causes a failure far from where the mistake happened. |
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
| Fails when | `KEY_FILE_UNREADABLE`: "The course could not save to the project folder. Check that the disk has free space and that you can save files in the folder, then try again. Your earlier key is unchanged." |

### Screen 8 of 8: Prove it works (`wiz-token-issuer-prove`, `Prove`, kind `prove`)

| Block | Words |
|---|---|
| What this is | The course asks OpenSSL, a separate tool written by other people, to check a token signed with your key. |
| Why it exists | If the course checked itself, a mistake could hide. A different tool has no reason to agree. |
| What you do now | Choose `Check it with OpenSSL`. |
| What good looks like | You see the real command, the real answer, and `OpenSSL agrees`. |
| Shown after the run | The command, for example `openssl pkeyutl -verify -pubin -inkey issuer.pub -rawin -in signing-input.bin -sigfile signature.bin`. The tool's output, for example `Signature Verified Successfully`. In words: "OpenSSL read the public half of your key (the half that is safe to share) and said the signature on the token is good." A tier line: `Proof by an outside tool.` |
| Fails when | `REFEREE_MISSING`: "The course could not find OpenSSL on this computer. Git for Windows includes a copy. Install Git for Windows, or set `NETSEC_OPENSSL` to the path of OpenSSL, then run the check again. Your key is saved and counts as proven once the check passes." `PROOF_FAILED`: "OpenSSL said the signature is bad. The key and the token do not match. Your earlier key is still saved. Choose `Back to the start` and make the key again. The output is below." |

### Done (`wiz-token-issuer-done`, `Done`, kind `done`)

| Block | Words |
|---|---|
| What happened | Your token signing key is `Checked by Go`. Lesson 10 now signs its tokens with your key. |
| What you do now | `Run lesson 10` (when you came from a lesson), `Set up the next key`, `Back to the map`, or `Use practice key again`. |

## 5. The other 14 types, step by step

Each row lists the Host's steps in order, with the decision on each. Every screen uses the frame in section 3 and the five-part words. The Intro and Done screens exist for each type and are not repeated. "Default" is the recommended answer. "Fix" is what the failure box tells the learner.

| Type (family) | Plain title | Source choices (default first) | Screens after Intro, one decision each | Typical failures and fix |
|---|---|---|---|---|
| `pki.root-ca` (F1) | Certificate authority | Make one for me. Import PEM. PKCS#12 (RSA). OS store (RSA) | 1 Key kind: Ed25519 (default) or RSA (note: Ed25519 runs in the course's own engines, RSA runs through the OS transport). 2 Name: `MMP Training Root`. 3 Valid until: 1 January 2036 (default). 4 Read it back (is a CA: yes). 5 Save. 6 Prove: `openssl verify -CAfile root.pem root.pem`, then a test leaf | `KEY_FILE_FORMAT`: make one with OpenSSL, command shown. `CERT_NOT_A_CA`: "This certificate cannot sign other certificates, so it cannot act as an authority. Pick a certificate made for a certificate authority (CA)." `CERT_SIGNATURE_ALG_UNSUPPORTED`: "The course can check Ed25519 signatures only, and this root uses RSA or ECDSA. Make an Ed25519 root." |
| `tls13.server` (F1) | Server certificate (TLS 1.3) | Make one for me. Import PEM. PKCS#12 (RSA). OS store (RSA) | 1 Names the server answers to: `localhost` (default). 2 Which authority signs it: my root (default). 3 Valid until: 1 January 2032 (default). The lessons run on a clock fixed at 1 January 2030, so the certificate must still be valid then. 4 Read it back. 5 Save. 6 Prove: `openssl s_client -tls1_3 -CAfile <anchors> -verify_return_error` | `CERT_NAME_MISSING`: "This certificate does not list `localhost` as a name it answers to. Make or pick one that does." `KEY_CERT_MISMATCH`: "This key does not go with this certificate. Pick the key that goes with it." `CHAIN_INCOMPLETE`: "The certificate of the authority between yours and the root is missing from the file. Add it to the file." |
| `tls.trust` (F2) | List of trusted authorities | Follow my root (default). Import certificates | 1 Source. 2 If import: pick files, read each back (name, expiry, is a CA). 3 Save. 4 Prove: `openssl verify -CAfile <anchors> <server certificate>` | `CERT_EXPIRED`: "This authority's certificate ended on <date>. Pick a newer one." `CERT_NOT_A_CA`. |
| `tls13.client` (F1) | Device certificate (mutual TLS) | Make one for me. Import PEM | 1 Device name: `pump-reader-4`. 2 Signer: my root. 3 Valid until: 1 January 2032 (default, same reason). 4 Include the middle authority? shown only when the signer is not the root (default Yes). 5 Read back. 6 Save. 7 Prove: `openssl s_server -tls1_3 -Verify 1 -CAfile <anchors>` against the course's client | `CHAIN_INCOMPLETE`: "The server cannot find who signed your certificate. A client signed by a middle authority must send that authority's certificate too. Add it." (Jared: Go refused a leaf-only client with `certificate signed by unknown authority`.) `CERT_USAGE_WRONG`: "This certificate is for servers. A device needs one for clients." |
| `tls11.server` (F1, RSA only) | Old-style server certificate (TLS 1.1) | Make one for me. Import PEM. PKCS#12 | 1 Key kind: RSA 2048, no choice, with the reason on screen ("TLS 1.1 here shares its secret using RSA, so this key has to be RSA"). 2 Names: `localhost`. 3 Signer: my root. 4 Read back. 5 Save. 6 Prove: `openssl s_client -tls1_1 -cipher AES128-SHA:@SECLEVEL=0 -CAfile <anchors>` | `PKCS12_PASSWORD`: "That file is protected by a password. Type it, or export the file again without one." `KEY_ALGORITHM_NOT_IN_ENGINE`: "TLS 1.1 in this course needs an RSA key." |
| `ssh.host-ed25519` (F3) | Server identity key (modern) | Make one for me. Import OpenSSH | 1 Source. 2 If import: pick `ssh_host_ed25519_key`. 3 Read back: public line and `SHA256:` fingerprint. 4 Save. 5 Prove: `ssh.exe -F NUL -o BatchMode=yes -o UserKnownHostsFile=<pin> ... echo hello` | `KEY_FILE_FORMAT`: "That file is not an OpenSSH private key. A real one starts with `-----BEGIN OPENSSH PRIVATE KEY-----`." `KEY_FILE_ENCRYPTED`. |
| `ssh.host-rsa` (F3) | Server identity key (legacy RSA) | Make one for me. Import OpenSSH | Same as above, with a line on screen: "RSA host keys here sign with SHA-1, which is weak. Lesson 8 uses it to show a legacy round." | Same as above |
| `ssh.client` (F3) | User key for signing in | Make one for me. Import OpenSSH. Add "for the CE process": file only | 1 Source. 2 Who uses it: the course's own client (default) or the CE process (file only). 3 Read back. 4 Save. 5 Prove: `ssh.exe` with the key file for a file key. A vault key has no outside tool that can use it, so the screen says "No outside tool can check this key" and the chip reads `Saved, no outside check`. | `KEY_ALGORITHM_NOT_IN_ENGINE`: "Sign-in keys in this course must be Ed25519." |
| `ssh.known-hosts` (F4) | Remembered server key (pin) | Follow my host key (default). Paste a `known_hosts` line. Learn on first connect | 1 Source. 2 Show the fingerprint, ask the learner to compare it by another way, for example read it back from the server file (decision: `It matches` or `It does not match`). 3 Save. 4 Prove: connect to the host key type's server. Then a mismatch demonstration that names `SSH_HOST_KEY_CHANGED` | `KNOWN_HOSTS_LINE_BAD`: "The course could not read that line. It does not accept wildcards. Write the line as `host key-type base64`." |
| `dukpt.bdk` (F5) | Card base key entry (key entry, not a ceremony) | Enter components (default). Import a vendor test key | 1 Say what this is: "This is key entry. A real ceremony uses a secure device and several people. Here one person types the parts. No outside tool can judge this. The course shows the steps and claims nothing more." 2 Component 1 (masked field, 32 hex characters), shows its check value. 3 Component 2, check value. 4 A third component? (Yes or No; default No). 5 Combine: the key is the XOR of the parts, made inside the box. Learner compares the final check value with the one on their own paper. 6 Can the key be read back later? `Yes, so I can see it` (default) or `No, like a real HSM` (one-way, with the line "This key cannot be read. A real HSM would refuse too."). 7 Read back. 8 Save. 9 Prove: a control first (the published X9 test base key must give the published vector), then a round trip with your key | `DUKPT_COMPONENT_LENGTH`: "A component is 32 hex characters, which is 16 bytes. This one has <n> characters." `DUKPT_KCV_MISMATCH`: "The check value does not match. That usually means a digit was mistyped. Retype that component." |
| `dukpt.pad` (F5, derived) | PIN pad key (key entry) | Follows the base key. No other choice | 1 Explain: the pad gets its key from the base key and a key id, as a key loader would. 2 Read back: a new key id each run. 3 Prove: one sale, pad to bank | `VAULT_KEY_UNKNOWN`: "The PIN pad gets its key from the base key. Set up the base key first." (with a link) |
| `device.enrolment` (F7) | Device key entry (passkey-shaped) | Make one for me. Import PEM | 1 Subject name: `pump-reader-4`. 2 Source. 3 Read back: the enrolment row the issuer will hold (subject, public key). 4 Save. 5 Prove: OpenSSL checks a challenge answer signed with the device key | `KEY_ALGORITHM_NOT_IN_ENGINE`: "Device keys in this course must be Ed25519." |
| `lab.aes-key` (F8) | Data key for lesson 1 | Make a wrapping key for me | 1 One screen: make the key. 2 Prove: wrap, unwrap, compare with the .NET library | `VAULT_UNWRAP_FAILED` |
| `lab.seal-key` (F8) | Data key for lesson 2 | Make a wrapping key for me | Same as above | `VAULT_UNWRAP_FAILED` |

`token.issuer` is the 15th type and is walked in section 4. The Prove cells above name the family of check. Section 6.1 holds the full commands and the judge for each type.

### 5.1 The vault exercise (separate from the flows)

A learner can play with the practice vault on its own screen, `vault-exercise`, opened from the map footer (`sec-vault-exercise`). It is an exercise, not a setup. Nothing here changes a mode or a key in use. It runs on a throwaway key named `exercise-key`.

First screen, before any choice: "This course shows every key, so use test keys. A real system keeps these hidden." and the label "Practice vault. Not an HSM. Not FIPS validated. Refusing to export is a rule in this course's code."

| Station | Words (what this is, why, what you do) | What the learner does | What the screen shows | Test ids |
|---|---|---|---|---|
| 1 Sign | "A vault signs for you, so the key never leaves the vault. A real vault works the same way." | Type a short message. Choose `Sign it` | The signature in hex, the public key, and a `Check it` button that verifies with the public key. A one-bit change in the message gives a failed check | `vault-sign`, `vault-sign-message`, `vault-sign-run`, `vault-sign-result`, `vault-sign-check` |
| 2 Derive | "A vault can make a new key from a parent key and a label. The same label always gives the same key. A different label gives a different key." | Type a label. Choose `Derive` twice, then once with another label | The child key's fingerprint each time. The two with the same label match | `vault-derive`, `vault-derive-label`, `vault-derive-run`, `vault-derive-result` |
| 3 Refuse | "You can mark a key so it cannot be read out. A real vault then refuses every request to export it." | Choose `Try to read this key out` on a key made non-exportable | The refusal in words, with the code `VAULT_EXPORT_REFUSED`: "The vault refused. This key cannot be read out. A real vault would refuse too." | `vault-refuse`, `vault-refuse-run`, `vault-refuse-result` |
| 4 Audit | "A vault writes down every request. You can see who asked for what, and the list is chained so a changed row shows." | Choose `Show the audit list` | Rows: time, who, what, result. Each row holds a hash of the one before. A `Check the chain` button says whether any row changed | `vault-audit`, `vault-audit-run`, `vault-audit-row-<n>`, `vault-audit-check` |

Label on any key view inside the exercise: "A real vault never shows you this." The Show keys switch applies as everywhere.

**Contract request (Q10):** the routes in `modes-design.md` 8.1 cover keys, audit, and export. The exercise also needs `POST /api/security/vault/exercise/sign`, `.../derive`, and `.../audit-check`, or the Host's `vault.sign` events used directly.

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
| No outside judge | An amber note: "No outside tool can check this. Your key is saved." The chip reads `Saved, no outside check`. No green, no tick | `Done` |
| `PROOF_FAILED` | Red cross, the output, and the one-sentence cause from the copy file | `Back to the start` or `Cancel setup`. The earlier key stays saved |
| `REFEREE_MISSING` | An amber note, not a failure of the key: "The test tool is missing. Your key is saved and counts as proven once the check passes." | Fix steps in section 8 row 9. The type stays `Set up, not proven` |

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
| `token.issuer` | Go | `tokenverify -pub iss.jwk -token <jws>`. (Section 4 shows an OpenSSL form, `modes-design.md` 8.6. Use whichever the Host reports.) | "A token can be read by anyone who sees it. The signature stops changes, and it hides nothing." |
| `device.enrolment` | none | The course's own check | `Judged by: our own check.` "Enrolling the key this client just showed is not enrolment. A passkey-shaped challenge is not WebAuthn." No green outside proof. |
| `dukpt.bdk`, `dukpt.pad` | none live | Published X9.24-3 vectors, then a round trip | "Checked against published vectors, no outside system. A real base key stays inside an HSM. This file is not a TR-31 file. One person typing the parts is not dual control." |
| `lab.aes-key` | .NET library | Wrap, unwrap, compare with BCL `AesGcm` | none |
| `lab.seal-key` | OpenSSL | `openssl mac -digest SHA256 -macopt hexkey:<hex> -in <file> HMAC`. The command ran. A comparison with the engine's tag has not run yet | "A password is not a MAC key. A MAC is not a signature." |

Rule for every Prove screen (Jared): show the command, its real output, and the name of who judged it. With no outside judge, say "our own check".

## 7. Show keys on every wizard screen

| Where | With the switch On | With the switch Off |
|---|---|---|
| Read-back facts | The key bytes in a `Show all` fold, copy button | `fp:` fingerprint and length, "Hidden by the Show keys switch" |
| Prove output | As the tool printed | The tool output is unchanged (it holds public data), key file paths only |
| DUKPT component fields | Masked while typed, always. The check value shows | Same |
| The setup screen header | Test-keys line says "This course shows every key, so use test keys. A real system keeps these hidden." | Says "This course hides your keys on screen for now and shows short fingerprints instead. Saved files can still hold them." |
| A non-exportable key | Shows the fingerprint and the line "This key cannot be read. A real HSM would refuse too." | Same |
| Any view of a vault key | Label: "A real vault never shows you this." | Same |
| The vault itself (map footer, Place screens) | Label: "Practice vault. Not an HSM. Not FIPS validated." Non-export is a rule in this course's code. | Same |

Flipping the switch while a wizard is open replaces the facts block from the Host. The wizard does not move.

## 8. True statements the wizards must make

| # | Statement | Where it appears | Source |
|---|---|---|---|
| 1 | A public certificate authority will not sign a certificate for `localhost`. A public CA signs only after you show you control a public name, and `localhost` belongs to nobody. So the server certificate here comes from a certificate authority you make yourself. | `pki.root-ca` Intro and `tls13.server` screen 2 | `modes-design.md` 1.8; the course's training CA |
| 2 | A self-signed certificate is not a chain. It vouches for itself, so nothing outside it proves it. A chain ends in a root that the checker already trusts. | `pki.root-ca` Intro, `tls.trust` Intro | PRD framing; `ChainCheck` |
| 3 | The course's own engines check Ed25519 signatures only. An RSA or ECDSA certificate stops with a named error code. RSA runs through the OS transport. ECDSA is not supported in the course's engines. | `KEY_ALGORITHM_NOT_IN_ENGINE` and `CERT_SIGNATURE_ALG_UNSUPPORTED` boxes, kind choice screens | `modes-design.md` 1.8, 8.5 |
| 4 | A certificate signed by a middle authority must be sent together with that authority's certificate. This holds for a client too. Sent alone, it gets the error `certificate signed by unknown authority`. | `tls13.client` screen 4 and `CHAIN_INCOMPLETE` | Jared's finding, `modes-design.md` 8.5 |
| 5 | This course shows every key, so use test keys. A real system keeps these hidden. Nothing here can tell a test key from a production key, so the line is the whole control (Steve's ruling: no hard stop). | Every Intro, before any choice | `modes-design.md` 8.2 |
| 6 | The key store is a plain file, and anyone who holds both files can read every key. It is not a production vault. | `Place` screens | `modes-design.md` O5 |
| 7 | Card numbers and PINs stay test values. The wizard has no field for them. | `dukpt.bdk` Intro, `dukpt.pad` Intro | `modes-design.md` 1.6, O10 |
| 8 | A key you mark as non-exportable cannot be read back. This is a one-way step, as in a real HSM. | `dukpt.bdk` screen 6, vault key choices | `modes-design.md` 6.3 |
| 9 | If the test tool is missing, your key is saved but not yet proven, and lessons will not run on it until it is. | Prove screen, `REFEREE_MISSING` | `modes-design.md` 2.3 |
| 10 | Where no outside tool can judge a key, the screen says so and shows no green check. The course never checks its own key and calls it proof. | `prove-tier`, `Saved, no outside check` | Steve, 2026-11-05; Jared section 5 |
| 11 | "Checked" means checked against the root you gave it. A self-signed certificate passes against itself. The check does not say a stranger would trust it. | `Checked` chip help text, every F1 Prove screen | Jared, section 3.1 |
| 12 | The wizard never installs a root in the OS store without asking, and says what it changed. | `os-pick` step | Jared, section 3.1 |
| 13 | A valid chain is not permission. | `tls13.client` Done | Jared, section 3.3 |
| 14 | A fingerprint on the same screen proves nothing. Compare it on a second channel. | `ssh.known-hosts` `compare` step | Jared, section 3.4 |
| 15 | `accept-new` proves nothing on the first connect, only that later connects match. | `ssh.known-hosts` `learn` step | Jared, section 3.5 |
| 16 | A real base key stays in an HSM. This file is not TR-31. One person is not dual control. | `dukpt.bdk` Intro and `combine` step | Jared, section 3.7 |
| 17 | A password is not a MAC key. A MAC is not a signature. | `lab.seal-key` Intro | Jared, section 3.8 |
| 18 | A token is readable by anyone who sees it. The `iss` claim counts only if the code reads it. | `token.issuer` Intro and Done | Jared, section 3.9 |
| 19 | DPoP stops token theft. Code running on the client can still make new proofs while it is online. | Lesson 10 callout, not a wizard | Jared, section 3.10 |
| 20 | Enrolling the key a client just showed is not enrolment. A passkey-shaped challenge is not WebAuthn. No proof screen. | `device.enrolment` Intro | Jared, sections 3.11 and 3.12 |
| 21 | The lessons run on a fixed clock: 1 January 2030 for the TLS labs, and a fixed day in November 2026 for tokens. A certificate must be valid on those dates. A 90-day certificate made today would read as expired in the labs. | `flow-tls-validity` | `Tls13Lab.cs:40`, `Lesson07Tls11.cs:29`, `Lesson10Auth.cs:47` |
| 22 | Key entry is not a key ceremony. A real ceremony uses a secure device and several people. Here one person types the parts. No outside tool can judge it. | `flow-dukpt-intro`, `flow-signin-device-entry-note` | Steve, 2026-11-05; Jared section 3.7 |

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
| Page | `sec-view-flows`, `sec-view-all`, `sec-flow-<flow>` for `tls`, `ssh`, `dukpt`, `signin`, `data`, `sec-flow-start-<flow>`, `sec-vault-exercise` |
| Flow frame | `flow-sheet`, `flow-part-progress` (reads `Part 2 of 4: Server certificate`), `flow-title` |
| Flow screens | `flow-<flow>-<step>` for each step in 1.4 |
| Vault exercise | `vault-exercise`, `vault-sign`, `vault-derive`, `vault-refuse`, `vault-audit` and the ids in 5.1 |
| Warnings | `wizard-warning-ssh-path`, `wizard-warning-pick-another`, `wizard-warning-use-anyway`, `wizard-warning-permissions`, `wizard-file-written-to` |
| State chips | `type-state-<typeId>` with `data-state` one of `practice`, `needs-setup`, `not-checked`, `checked`, `no-outside-check`, `broken` |

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

**Screen count: 70.** Flows 60 (`flow-tls` 13 plus 5 for bringing your own files, `flow-ssh` 12, `flow-dukpt` 12, `flow-signin` 12, `flow-data` 6), the vault exercise 5 (intro and four stations), and the shell 5 (Security setup in flow view, the all-keys detail view, the refusal banner, the cancel sheet, the resume sheet). The per-type step ids listed above are the step library that the flow screens draw from. One flow takes between 6 screens (`flow-data`) and 18 (`flow-tls` with its own files)."

### 9.4 Prove step

`prove-command`, `prove-output`, `prove-words`, `prove-tier`, `prove-run`, `prove-pass`, `prove-fail`, `prove-missing`.

### 9.5 Acceptance clauses this table supports (for Echo)

| Proposed id | Asserts |
|---|---|
| `A17.ui.map-has-15-rows` | The all-keys view shows 15 rows with the ids above |
| `A17.ui.five-flows` | The flow view shows 5 flow cards with the goals of section 1.4 |
| `A17.ui.first-screen-line` | Every flow's `intro` and the vault exercise show the test-keys line first |
| `A17.ui.no-real-label` | No label on screen reads `Real`, and no state reads `Proven` or `trusted` |
| `A17.ui.ssh-path-warning` | Picking a file under `.ssh` shows `wizard-warning-ssh-path` and does not read the file until the learner confirms |
| `A17.ui.no-outside-judge` | Card and device key flows show `Saved, no outside check` and no green tick |
| `A17.ui.vault-exercise` | Sign, derive, refuse, and audit each show their result, and refuse names `VAULT_EXPORT_REFUSED` |
| `A17.ui.mode-switch-undo` | `type-mode-practice-<id>` is always enabled and returns the row to Practice |
| `A17.ui.refusal-names-types` | A lesson on an unready type shows `security-needs-banner` with one `needs-row-<id>` per type |
| `A17.ui.wizard-token-issuer-walk` | The token part of flow 4 shows the screens of section 4 in order and ends `Checked by Go` |
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
| Network Security Lab [TRAINING ONLY] [Keys: 2 of mine] [engine connected]         |
|                       [Security setup (1)]  Tour|Free  Endpoints|..  Show keys (o)|
+--------------------------------------------------------------------------------+
| Security setup                                           [Back to lessons]     |
| This course shows every key, so use test keys. A real system keeps these hidden. |
|                                                                                |
| +-- Run a lesson with my own keys ----------------------------------------+  |
| |  Lesson: [ 10 Client proof and permission v ]            [ Start ]       |  |
| +--------------------------------------------------------------------------+  |
|                                                                                |
| WEB SECURITY (TLS)                                                             |
| Certificate authority      Practice | My test key [Checked]       Lessons 4,5,7,10 [Change]|
| Server certificate (1.3)   Practice | My test key [Needs setup]   Lessons 4,5,7,9,10 [Set up]|
| Trusted authorities        Practice | My test key [Practice key]  ...      [Set up my own]  |
|   Set up the certificate authority first.  (link)                              |
| ...                                                                            |
| SIGN-IN TOKENS                                                                 |
| Token signing key          Practice | My test key [Setup paused, step 3 of 8] [Continue setup]|
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
|  Below is what you chose so far. Nothing is saved yet.     |
| WHY IT EXISTS IN THE REAL WORLD                            |
|  Real teams read a key's details before they use it.       |
|  A wrong key causes a failure far from where the mistake   |
|  happened.                                                 |
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
|      Your earlier key is still saved.                      |
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
| Q1 | Jared's file landed (`ab12da8`). Does it change if his referee runs change? | Sections 6.1 and 8 follow it. Recheck on any change | A command in 6.1 stops working on a learner key (TLS 1.1 has run with the training root only) |
| Q2 | Electron file dialog through one IPC call, `pickFile` | **Decided yes (lead, 2026-11-05).** Electron's own `dialog.showOpenDialog`, no package | Closed |
| Q3 | Resume after quitting needs `openWizardId` on each type in `GET /api/security`, and the Host storing wizard state without secrets | **Decided yes.** Richard adds it | Closed |
| Q4 | `dukpt.bdk` at 12 one-decision screens | **Moot.** Grouped into `flow-dukpt` (12 screens, shared with the pad) | Closed |
| Q5 | `Use practice keys for this lesson` (banner button) flips types to Mock from a lesson screen. Does it need a confirmation? | One line of confirmation, no modal | Any user who flips by accident |
| Q6 | New Host codes the copy needs: `ISSUER_NAME_BAD`, and a `canGoReal`/`whyNot` text for each dependency. Richard adds them. | Add | The Host reuses an existing code |
| Q7 | Default validity | **Changed.** The lab clock reads 2030-01-01, so a 90-day certificate expires before the lab runs. Defaults: CA until 2036-01-01, certificates until 2032-01-01. A real system uses 90 days. The `validity` screen says why we differ | Richard changes the labs to read the real clock for certificates made by a wizard: then 90 days works |
| Q8 | Rename the OS-transport button | **Decided yes:** `OS transport`, in the same slice | Closed |
| Q9 | Flows need `POST /api/security/wizards {flowId}`, with the Host owning part order and shared answers | Add flow tables as data beside the family tables | Richard prefers per-type wizards: then the UI cannot make a flow, and the five goals become five lists of buttons |
| Q10 | The vault exercise needs sign, derive, and audit-check routes | Add `POST /api/security/vault/exercise/{op}` | Richard exposes the existing `vault.sign` events instead |
| Q11 | A type with no outside judge: may a lab run on it? | Yes. State `Verified` with `judge: none`, chip `Saved, no outside check`. The lab shows the same chip | Readiness refuses until an outside judge exists: then card and device keys can never go live |
| Q12 | The `~/.ssh` warning code `PATH_IN_USER_SSH` and `KEY_FILE_PERMISSIONS` are new Host codes | Add both as warnings, not errors | The Host reuses an existing code |

No new package is needed. The design uses Vue 3, Vuetify, and the existing glossary tooltips. The Electron file dialog is part of Electron.
