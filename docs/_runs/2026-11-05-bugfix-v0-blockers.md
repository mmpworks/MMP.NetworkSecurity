# Bugfix: Jared's five blockers on PR #118

Date: 2026-11-05. Author: Richard. Branch `feat/v0`. Red `5e9004e`. Source: Jared's verdict on `cc572f6`, in PR #118.

Past finding: `2026-11-05-bugfix-fork-order.md`. A test that passes without the fix proves nothing, so each test here was run on the old code first and the run was read.

## Red run, on the old code, at `5e9004e`

```
lesson 7 on own keys shows these built-in keys: server-tls-ed25519
Failed!  - Failed:     1, Passed:    16, Skipped:     0, Total:    17 - NetSec.Tests.dll (net10.0)
Failed!  - Failed:    21, Passed:    23, Skipped:     0, Total:    44 - NetSec.Host.Tests.dll (net10.0)
```

## Each blocker

| # | Cause | Fix | Test |
|---|---|---|---|
| 1 | `Lesson07Tls11.Race` built a second `LabContext` with no `Credentials` | One field copied | `A_lab_on_own_keys_shows_no_built_in_key` |
| 2 | `Credentials()` opened every `Mine` type, and an open failure was unhandled in the socket | It opens only the types the lesson reads. A failure is a named refusal. The key route and flow steps also answer by name | `A_broken_key_stops_only_the_lessons_that_read_it_and_by_name`, `A_key_route_on_a_broken_key_answers_by_name` |
| 3 | `ReadOne` never compared the key's algorithm with the type | `KEY_ALGORITHM_NOT_IN_ENGINE`, and nothing is placed. Review reads the algorithm from the key | `An_rsa_key_for_an_ed25519_type_...`, `Review_reads_the_algorithm_from_the_key` |
| 4 | `WriteChain` read through `store.Credentials()`, which follows the mode | It reads the placed keys. A type with none refuses by name, and no check can fall back | `A_check_judges_the_placed_keys_when_the_types_sit_on_built_in` |
| 5 | `secret_guard.py` read the working copy, quoted paths, and a body class that broke on four shapes | It reads the index by `git cat-file --batch`, takes paths from `ls-files -z`, and removes NUL bytes, escapes, and header lines before it tests the body | `SecretGuardTests`, 9 cases, with prose and a public key as controls |

## Class sweep for blocker 1

Closed. The class is a lab that reaches a key by some route other than the run's `CredentialSet`.

| Check | Result |
|---|---|
| `new LabContext` in `src/NetSec.Core/Labs` | One site, the one fixed. Enumerated by search |
| Byte scan of built-in public keys, labs 4, 5, 7, 8, 9, 10 on own keys | 0 hits after the fix, beside a control that finds them on built-in keys |
| A spy `ITrainingKeySource`, labs 1 to 10 | Each key a lab asks for belongs to a type in `LabCatalog.Needs`, so the narrower open in blocker 2 cannot drop a key a lab reads |
| `tools/layer_check.py` | A new rule fails on `new TrainingKeySource()` in any lab file but `Labs.cs`. It ran on a planted line, and it failed |

Limits: the scan covers public keys that reach the trace. `dukpt-bdk-128` and `token-issuer` do not travel in a trace, so the spy and the Go referee clause cover them. Lesson 6 and lesson 9's constant pad key on an own BDK wait for V6.

## Should-fix

| Item | Disposition |
|---|---|
| 1. The negative control took any non-zero exit | Fixed. It needs OpenSSL's own refusal words, and a timeout never counts. The fact now carries `controlCommand` and `controlOutput` for the learner |
| 2. A 3 GiB file gave a 500 | Fixed. `KEY_FILE_FORMAT` above 1 MiB |
| 3. Four chain types had no control | Fixed. All five run the other-root control |
| 4. A tool that cannot start gave a 500 | Fixed. `REFEREE_MISSING` |
| 5. A corrupt `modes.json` stopped the Host with no name | Fixed. `HOST_SECURITY_FILE_BAD` on stderr, exit 2 |
| 6. A file for a type outside the flow was dropped, and empty `paths` made all keys | Fixed. `WIZARD_TYPE_NOT_IN_FLOW`, and `KEY_FILE_UNREADABLE` for empty paths |
| 7. A `\\?\` path got no warning | Fixed |
| 8. `key.public` holds a public key in `secrets`, so a Show keys filter would hide it | **Left for V3,** because the filter does not exist yet. V3 must keep public values shown, and Echo has noted it |

Also found while fixing: `HostFixture` had no `NETSEC_SECURITY_DIR`, so `HostLiveTests` ran on the repository's own `.security/` folder. It now has its own.

Open, for V4: Jared's limit 1, whether lesson 10's attack rows end the same on own keys. He read his second pass as a probe fault and did not prove it.

## Scope

Cue: Jared's byte scan of the frames. No test here looked at key bytes, and the shape-based clause could not see a mixed run.

Lane: this touches many files, so the skill names the `bugfix-graph` workflow. The lead asked for these fixes on this branch, with Jared as the outside check, so I walked the steps inline.

Reviewer: Jared re-checks at the new head.
