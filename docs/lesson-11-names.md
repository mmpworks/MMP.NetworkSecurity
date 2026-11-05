# Lesson 11: names for the tour and UI lanes

Conclusion: the lab, the native library and the attack rows exist, and lesson 11 is released. The tour and UI lanes bind to the names below. Source of truth for the JSON: `src/NetSec.Core/Native/TimingReport.cs`. Source of truth for the events: `src/NetSec.Core/Labs/Lesson11Timing.cs`.

## 1. Lanes

| Lane | Role |
|---|---|
| `attacker` | Runs the guess loop. Emits `timing.guess.finished` |
| `target` | Holds the secret and the compares. Emits every other event |

`GET /api/lessons/11` returns these lanes today.

## 2. Events

A timing event has no wire bytes. Its numbers are UTF-8 JSON text in `Plain`, which the trace carries as hex.

A control run (no attack) emits these events in this order. Each attack row emits `timing.lab.started`, then one `timing.guess.finished`.

| Order | `type` | Lane | `step` | Count | `Plain` | `check` |
|---|---|---|---|---|---|---|
| 1 | `timing.lab.started` | target | `start` | 1 | Machine | None. `secrets[0]` is `{holder: target, name: lab-secret}` |
| 2 | `timing.samples` | target | `measure` | 4 | Case: leaky first byte, leaky last byte, constant-time first byte, constant-time last byte | None |
| 3 | `timing.managed` | target | `measure` | 2 | Case: managed first byte, managed last byte | None. `message` holds the managed statement |
| 4 | `timing.verdict` | target | `measure` | 1 | Verdict | `leaky compare separates` |
| 5 | `timing.guess.finished` | attacker | `guess-leaky` | 1 | Guess | `guess loop reads the leak` |
| 6 | `timing.guess.finished` | attacker | `guess-constant-time` | 1 | Guess | None in a control run |
| Any | `timing.failed` | target | The current step | 0 or 1 | None | Names the failed step, for example `native library load` |

The lab measures 100,000 samples per case for leaky and constant-time, and 20,000 per case for managed. The histogram spread uses nanoseconds from the same run.

### JSON in `Plain`

```
Machine: {"clr":"10.0.14","pointerBytes":8}

Case:    {"compare":"leaky","bufferSize":4096,"diffPosition":4095,"samples":100000,"tickFrequency":10000000,
          "meanNs":1350.2,"medianNs":1300,"p99Ns":1700,
          "histogram":[{"ns":1200,"count":40000},{"ns":1300,"count":30000}],"aboveP99":980}

Verdict: {"leakyT":-824.881,"constantTimeT":-2.277,"controlT":3.438,"managedT":0.916,"minT":4.5,"factor":3,
          "constantTimeOverMinT":false,"separated":true}

Guess:   {"compare":"leaky","correctBytes":4,"totalBytes":4,"blockBytes":1024,"samplesPerGuess":500,
          "bytes":[{"value":198,"marginNs":210.5}]}
```

The values above show the shape. They are not results. `compare` is `leaky`, `constant-time` or `managed`. A number is `null` when it is infinite. `controlT` is the constant-time compare against itself, so it shows this machine's noise floor for one run.

## 3. Attack rows

These rows are `TimingAttackLab.AttackRows`. They enter `AttackCatalog.All` at release (section 6).

| `attackId` | `kind` | Option | `expect` | Result |
|---|---|---|---|---|
| `L11-guess-leaky` | `timing-guess` | `guess-target = leaky` | `NoCheck` | The run completes with no failed check. The attack works |
| `L11-guess-constant-time` | `timing-guess` | `guess-target = constant-time` | `Rejected` | The run stops. Code `TIMING_GUESS_STOPPED`, check `constant-time compare` |

## 4. Named errors

| Code | Means | What the UI says |
|---|---|---|
| `NATIVE_LIB_MISSING` | `netsec_ct.dll` did not load | Run `native\build.cmd`, then rebuild the Host |
| `NATIVE_SAMPLE_FAILED` | `nsct_sample` returned an error | Show the code |
| `TIMING_NOT_SEPARATED` | The run could not show the leak, or the guess recovered the whole secret from the constant-time compare | This machine was too noisy for this run. Run again |
| `TIMING_GUESS_STOPPED` | The constant-time attack row did not recover the secret | The expected result of that row |

## 5. Statements the tour must make

Accuracy rule 5 and the `A12.tour` clause bind the first two. The rest come from the measurements in `docs/learnings.md`, section S7, and from the review of PR #10. Each statement needs a `claims` entry with a source section (A15a).

| # | The tour states | Why |
|---|---|---|
| 1 | Managed code has no constant-time guarantee | PRD rule 5, CONTRACT.md section 4 |
| 2 | C++ results depend on the optimizer. The constant-time result was measured only for this source, this compiler, these flags and this CPU | PRD rule 5 |
| 3 | Each secret byte is stretched to 1,024 bytes, and the timer runs in the same process | The lab reads one loop pass of about 0.33 ns with a 100 ns clock. A remote attacker sees more noise |
| 4 | A failed guess shows only that this loop failed in 500 samples per candidate | The code knows nothing more |
| 5 | The label: `Built to show the parts. Do not copy.` | PRD rule 7 |

Do not write these claims:

1. "Constant-time |t| stays under 4.5". Identical cases also go over 4.5 on this machine (1 of 20 and 3 of 20 runs).
2. "Flat timing", as a result of the lab. Say what the run measured: the constant-time |t| beside the control |t|.
3. "The constant-time compare has no leak". Say that this run shows no effect that its control lacks.

## 6. Release steps

Do these in one PR, after the tour and the UI land.

1. In `LabCatalog.Find`, return `new TimingAttackLab()` for lesson 11.
2. In `AttackCatalog.All`, add `TimingAttackLab.AttackRows`.
3. In `NativeTests.cs`, replace `Lesson_11_stays_unbuilt_until_its_tour_and_ui_land` with a test that lesson 11 is built.
4. In `HostLiveTests.cs`:
   1. Change the `built` assertion of `Lessons_list_holds_1_to_11...` to expect lesson 11.
   2. Replace `Lesson_11_is_refused_until_its_tour_lands...` with the live run test from commit `bdd0288`, `Lesson_11_loads_the_native_library_in_the_host_and_finishes_with_measured_numbers`.
5. Run `pwsh acceptance/run.ps1 -Clauses A11,A12,A13,A14,A15,A15a`. `A11.catalog.every-row-beside-control` then runs both rows beside a control.
