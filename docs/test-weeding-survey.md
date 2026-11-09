# Test weeding survey (garden plan step 1)

Author: Echo. Date: 2026-11-09. Base: main f8e2004; follow-ups (section 9, the class sweep in section 6, one row moved to delete) on main 974e46e. Plan: `docs/test-garden-plan.md`, step 1.

Conclusion: **40 candidates of 1,172 tests** in six suites. 3 are "delete" (two tests, and 8 rows of one Theory) and 37 are "fix". No suite has a large set of tests that check nothing. The biggest group is 9 lesson specs that skip, so a lesson that stops being built reads as a skip and never as a fail.

Echo proposes. The builder who owns each suite makes the change in its own PR, with the reason from this file. Echo deleted nothing.

## 1. Method

1. Passes: `test-anti-patterns` over every test, and `test-gap-analysis` on the C# suites to find assertions too weak to catch a likely bug.
2. Read-only. Nothing was built or run.
3. A test is listed only when a line shows it cannot fail, or it can fail for a reason that is not the product. A test with a real failure mode stays, however old or slow.
4. Counting rule for M:
   - C#: one per method with `[Fact]` or `[Theory]`. A Theory counts once, whatever its row count.
   - Playwright: one per `test(...)` call. A `test()` inside a loop counts once. So M is 216 here, and the app gate reports 270 run tests.
   - Python: one per `def test_` method.
5. Review: four survey agents read the suites. Echo checked every "delete" row against the source, and overruled 3 of them (section 6).

## 2. Totals

| Suite | M (tests) | Candidates | Delete | Fix |
|---|---|---|---|---|
| `tests/NetSec.Tests` | 591 | 10 | 1 | 9 |
| `tests/NetSec.Host.Tests` | 173 | 7 | 1 | 6 |
| `app/e2e` | 216 | 14 | 0 | 14 |
| `tools/test_*.py` | 155 | 7 | 1 | 6 |
| `tools/githooks/test_pre_push_guard.py` | 23 | 2 | 0 | 2 |
| `acceptance/tools/test_pin.py` | 14 | 0 | 0 | 0 |
| **All** | **1,172** | **40** | **3** | **37** |

The Host "delete" row removes 8 rows from one Theory and leaves the method, so it counts as 1 candidate. The 9 lesson skips count as 9 candidates (3 specs of 3 tests). The lesson 11 guess test has a second row in section 5, and it counts once.

## 3. `tests/NetSec.Tests` (10 of 591)

| Test id | Anti-pattern | Evidence | Action | Why |
|---|---|---|---|---|
| `TokenTests.Junk_is_refused_with_no_exception` | duplicate (twin `AuthReviewFindingTests.Junk_is_named_malformed_and_never_a_failed_signature`) | `AuthTests.cs:140-148`, twin `AuthBlockerTests.cs:105-115` | delete | The same four inputs. The twin also asserts `TOKEN_MALFORMED` and `token format`. This one asserts only `Allowed == false` |
| `BridgeCoreTests.A_flip_at_any_byte_of_the_envelope_is_refused_and_records_no_ksn` | weak-assertion | `BridgeTests.cs:274-278` | fix | The test builds `ledger` and never reads it, so a refusal that records the KSN still passes. Assert the ledger lacks the KSN |
| `Lesson09Tests.Arrows_on_each_hop_name_the_lanes_of_that_hop` | weak-assertion | `Lesson09Tests.cs:69-70` | fix | `Assert.All` over a filtered list passes when the list is empty. Add `Assert.NotEmpty` on each filtered set |
| `CfBinaryTests.The_relay_mode_reports_a_named_code_until_it_is_built` | other (pins a stub) | `CfBinaryTests.cs:78-80` | fix | It passes only while the relay mode is missing. Replace it with a relay test when the mode ships |
| `Tls13MutualServerTests.A_client_certificate_with_a_bad_date_is_named_at_the_server_and_never_a_throw` | other (checks the wrong thing), near-duplicate of `Tls13BadInputTests.A_certificate_with_an_invalid_month_is_the_parse_code_and_never_an_exception` | `Tls13HardeningTests.cs:656-668`, twin `:260-268` | fix | The name says "at the server". The body only calls `Certificate.Parse`. Feed the certificate to a server, or delete it as the twin's duplicate |
| `Tls13BadInputTests.A_short_server_name_extension_is_a_named_parse_failure` | weak-assertion | `Tls13HardeningTests.cs:242` | fix | `Assert.NotNull(CheckName)` passes for any check. Pin `ErrorCodes.ParseTruncated` as the sibling test does |
| `ProbeCredentialsTests.The_training_keys_do_not_reach_a_server_on_the_learners_keys` | weak-assertion | `ProbeCredentialsTests.cs:54-55` | fix | Only `Completed == false`. A timeout or port clash also passes. Assert the named refusal code |
| `MlKem768Tests.Key_and_sealed_properties_hand_out_copies` | weak-assertion | `PublicKeyTests.cs:489-494` | fix | Only `pair.Ek` is changed. `Ciphertext` and `SharedSecret`, which the name covers, are never checked |
| `NativeLiveTests.Interleaved_managed_times_every_sample` | weak-assertion | `NativeTests.cs:234-241` | fix | Lengths and `TickFrequency > 0` only. A timer that records all zeros passes |
| `NativeLiveTests.A_sample_reports_a_clock_and_one_value_per_sample` | weak-assertion | `NativeTests.cs:244-250` | fix | The same shape as the row above |

## 4. `tests/NetSec.Host.Tests` (7 of 173)

| Test id | Anti-pattern | Evidence | Action | Why |
|---|---|---|---|---|
| `SecretGuardShapeTests.Each_key_shape_is_caught`, rows `plain`, `enc-trad`, `non-ascii-name`, `escaped-string`, `utf16`, `prose-then-key`, `placeholder-then-key`, `over-8mib` | duplicate (8 `SecretGuardTests` methods) | `SecretGuardShapeTests.cs:70-73`, twins `SecretGuardTests.cs:96, 113, 122, 131, 139, 147, 155, 163` | delete the 8 rows | The twins also assert that the output names the file (`SecretGuardTests.cs:82`). This also drops one 9 MiB `git add` run |
| `ElectronOriginsPinTests.Electron_blanks_NETSEC_ORIGINS_for_the_Host_it_spawns` | other (source-text check) | `ExtraOriginsTests.cs:199-200` | fix | It finds the text `NETSEC_ORIGINS: ''` in `main.cjs`. A comment holding that text passes it. Check the spawned Host's environment |
| `OsTransportLiveTests.The_app_names_the_os_transport_os_and_never_real` | other (source-text check) | `OsTransportLiveTests.cs:145-151` | fix | A grep of `app/src`. `HostLiveTests.Unbuilt_lesson_and_real_mode_answer_by_code` (`HostLiveTests.cs:368-371`) checks the runtime refusal. Move the grep to a lint rule |
| `BridgeLiveTests.The_pad_role_reads_no_base_key` | other (source-text check) | `BridgeLiveTests.cs:198-204` | fix | It slices `Program.cs` from `int PinPad()`. A helper call or a moved method passes it. The wire checks in the same file hold the real claim |
| `SecurityLiveTests.A_key_broken_after_the_flow_stops_its_own_flow_step_by_name_and_not_with_a_server_error` | weak-assertion | `SecurityLiveTests.cs:186-194` | fix | Status 200 and `Contains("Broken", body)` on the whole body. Parse the JSON and assert the `tls13.server` step's state and code |
| `OsTransportTrustTests.Lesson_5_trusts_a_server_only_as_windows_would`, row `via-non-ca-issuer-sent` | weak-assertion | `OsTransportTrustTests.cs:58, 97-101` | fix | The row's `Status` is null, so any trust refusal passes. Name the expected chain status |
| `SecurityRootTests.With_no_git_above_it_the_folder_sits_beside_the_app` | other (fails for a reason that is not the product) | `SecurityRootTests.cs:12, 34` | fix | It uses the machine temp folder. It fails when `TMP` sits inside a git checkout. Give it a temp root with no `.git` |

## 5. `app/e2e` (14 of 216) and `tools/test_*.py` (7 of 155)

| Test id | Anti-pattern | Evidence | Action | Why |
|---|---|---|---|---|
| `lesson-9.spec.ts`, its 3 tests | swallowed-failure | `lesson-9.spec.ts:6`, `walk.ts:81-86` | fix | `test.skip(!(await isBuilt(9)))`. A change that stops building lesson 9 reads as 3 skips. Assert `isBuilt(9)` |
| `lesson-10.spec.ts`, its 3 tests | swallowed-failure | `lesson-10.spec.ts:6` | fix | The same skip for lesson 10 |
| `lesson-11.spec.ts`, its 3 tests | swallowed-failure | `lesson-11.spec.ts:6` | fix | The same skip for lesson 11 |
| `lesson-11.spec.ts` "guess against the constant-time compare stops, and the leaky guess finds bytes" | weak-assertion | `lesson-11.spec.ts:377-381` | fix | Only the constant-time half is asserted. Assert the leaky guess too (this test is also one of the 3 skips above) |
| `theme-switch.spec.ts` "the Security setup screen and a tour step in the {light,dark} theme" | no-assertion | `theme-switch.spec.ts:421-437` | fix | Visibility and screenshots only. Assert the theme applied, or delete it, since the other tests in the file cover the switch |
| `security-v0.spec.ts` "the Show keys switch is on by default and can be used" | duplicate (first test, `:28`) | `security-v0.spec.ts:35-37` | fix | It repeats `toBeChecked`. "Can be used" is only `toBeEnabled`. Click the switch, or keep only lines 38-40 |
| `glossary.spec.ts` "real Electron opens a glossary source in the outside browser, refuses an unlisted link, and keeps one window" | duplicate (part) | `glossary.spec.ts:85-90`, twin `links.spec.ts:49-58` | fix | The link-refusal half repeats `links.spec.ts`. Keep the glossary-source click (`:82-84`) |
| `eavesdropper-sweep.spec.ts` "lesson 7: the TLS 1.1 certificate crosses in the clear..." | swallowed-failure | `eavesdropper-sweep.spec.ts:279` | fix | `.click().catch(() => {})` hides a missing Bytes tab |
| `contrast-sweep.spec.ts`, the test that visits the refusal banner | swallowed-failure | `contrast-sweep.spec.ts:97` | fix | The Close click always has a target on a healthy build: `NeedsBanner.vue:12` renders on `sec.needs`, `needs-confirm-no` only sets `confirm = false`, and only `dismissNeeds` (`security.ts:211`) or the Yes button clears it. The catch hides only a real fault. Drop the catch and assert the banner is hidden |
| `test_dist_stamp.py::WiredIn.test_the_playwright_config_checks_the_stamp` | other (source-text check) | `test_dist_stamp.py:165-166` | fix | `assertIn("dist-stamp", text)` passes on a comment. Assert the call |
| `test_dist_stamp.py::WiredIn.test_the_electron_main_process_checks_the_stamp` | other (source-text check) | `test_dist_stamp.py:168-169` | fix | The same check on `main.cjs` |
| `test_dist_stamp.py::WiredIn.test_the_launcher_rebuilds_a_stale_dist` | other (source-text check) | `test_dist_stamp.py:171-172` | fix | The same check on `open-app.ps1`. The name says "rebuilds". The body checks a name only |
| `test_gate_lock.py::GateLock.test_the_gate_script_passes_its_own_parameters_to_the_locked_run` | other (source-text check) | `test_gate_lock.py:63-68` | fix | Four substring checks on `gate.ps1`. The two run tests above it (`:44`, `:54`) prove the lock |
| `test_run_status.py::RunStatus.test_a_gate_head_line_is_not_mistaken_for_the_summary` | duplicate (twin `test_a_running_gate_log_prints_the_commit_too`) | `test_run_status.py:161-163`, twin `:146-149` | delete | The same input. Move its `startswith("RUNNING")` assertion into the twin, then delete it |
| `test_run_status.py::RunStatus.test_playwright_running_counts_finished_specs` | weak-assertion | `test_run_status.py:81` | fix | `assertIn("2", out)` matches any 2. Assert the full phrase |
| `test_heavy_lock.py::HeavyLock.test_a_cmd_shim_such_as_npm_runs` | swallowed-failure | `test_heavy_lock.py:249` | fix | `skipUnless(shutil.which("npm"))`. A machine with no npm on PATH skips the `.cmd` path. Fail when npm is missing, or plant a test `.cmd` |

## 6. Delete proposals overruled, and a class sweep

| Test id | Proposed as | Kept because |
|---|---|---|
| `KeysTests.Key_ids_are_the_contract_strings` (`KeysTests.cs:17-26`) | constant re-assertion | The ids are a contract that saved files and routes read. The test fails on an accidental rename |
| `VaultStoreTests.The_audit_check_names_the_three_changes_it_cannot_see` (`VaultStoreTests.cs:101-108`) | constant re-assertion | Its neighbour pins the field to the app copy file. This test pins the meaning, so an edit of both that drops one limit still fails |
| `test_dist_stamp.py::DistStamp.test_a_commit_that_adds_a_file_outside_app_does_not_make_dist_stale` (`:127-131`) | duplicate of `:121-125` | It adds a new file in a new folder. The twin edits a tracked file. A stamp that counts new paths fails only this one |

Class sweep of `.catch(() => {})` in `app/e2e` (after Jared on #356). There are 3 sites:

| Site | Disposition | Why |
|---|---|---|
| `eavesdropper-sweep.spec.ts:279` (Bytes tab click) | candidate, section 5 | The next assertion reads the tab that the click may have failed to open |
| `contrast-sweep.spec.ts:97` (Close on `security-needs-banner`) | candidate, section 5 | Jared on #357: nothing between `:96` and `:97` clears `sec.needs`, so the Close button is always there on a healthy build |
| `bytes-fit.spec.ts:96` (screenshot on failure) | kept | A diagnostic in a failure path. The test has already failed when it runs |

## 7. Not candidates, but the garden needs them

1. These tests need a tool at a fixed path or on PATH, and they fail when the tool is missing: `OpenSsl_and_the_engine_verify_each_others_signatures` (`EcdsaWalksTests.cs:183`), `Files_from_ssh_keygen_read_and_an_encrypted_one_is_refused_by_name` (`OpenSshKeyReaderTests.cs:100`), `OpenSsl_default_client_verifies_the_glass_server_and_sends_data` (`Tls11Tests.cs:314`), `OpenSsl_decrypts_the_same_premaster_and_derives_the_same_master_secret_and_key_block` (`Tls11KeyScheduleWalkTests.cs:25`), `The_go_tap_sees_the_wire_sent_bytes_each_way_and_two_runs_draw_different_randoms` (`Tls13Tests.cs:678`). The `CfBinaryTests` that need the built `net35` CE binary are the same kind. A nightly machine that lacks one of these tools would read a red with no product fault. The nightly script should check for the tools first.
2. Each "walks every step of lesson N" spec ends with `expect(visited).toEqual(tourIds(n))`. That line is always true, because `walkTour` builds `visited` from the same ids. The per-step checks in `walk.ts:54-64` still fail on a real fault, so the specs stay. The last line can go.

## 8. Not judged

1. The layout and contrast specs depend on Chromium rendering. Whether a threshold was tuned so the spec passes needs a run, and this survey ran nothing.
2. `ToyCurveWalkTests` has two "lie on their lines" tests (`:167-180`, `:190-207`). They overlap only if `Chord` and `Tangent` repeat the `Samples` entries, which the files do not show.
3. `test_heavy_lock.py::test_a_lock_file_that_cannot_be_opened_fails_closed` (`:337`) depends on `chmod 0o444` blocking an open on Windows. That needs a run.

## 9. Two suites outside the first four

Both are gate steps. Echo read both in full.

| Test id | Anti-pattern | Evidence | Action | Why |
|---|---|---|---|---|
| `test_pre_push_guard.py::PrePushGuard.test_closed_pr_refuses` | weak-assertion | `tools/githooks/test_pre_push_guard.py:103-106` | fix | It checks only a non-zero exit and no remote branch. A hook that crashes also passes. Assert `CLOSED` in stderr, as the MERGED twin does |
| `test_pre_push_guard.py::PrePushGuard.test_gh_failure_refuses` | weak-assertion | `tools/githooks/test_pre_push_guard.py:129-134` | fix | `assertIn("gh", stderr)` matches any word that holds "gh", for example "through". Assert the guard's own message for a failed `gh` |

`acceptance/tools/test_pin.py`: 0 candidates of 14. Echo wrote these tests, so this review is not independent. Jared ran them and read the changed tests on #353; no independent anti-pattern pass yet.

Disposition: the lead routes each suite's rows to its builder. Each builder makes the deletes and fixes in its own PR, red first where a fix makes an assertion stronger. Step 2 (the covers-map spike) can start, because nothing here changes which test units exist.
