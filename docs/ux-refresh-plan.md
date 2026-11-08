# UX refresh plan

Owner: Nancy. Decision owner: Steve. Date: 2026-11-06.

## Conclusion

1. The refresh ships in 5 small slices. Each slice is one PR with its own pictures.
2. Slices 1 and 2 land the shell, the top bar and the Tour panel first. Richard's spec cards (SC) and walk screens (W1b) build on that shell.
3. No design doc from Richard is needed for the shell. The drawing is the design. Section 3 names the walk's root element, and Richard has confirmed it.
4. No test id changes. Specs change only where a control moves into Settings.
5. The lead approved fonts on conditions (section 7). Slice 1 is #184.

## 1. Goal and approved direction

| Item | Source |
|---|---|
| Look: layout, cells, chips, tabs, colors | Steve approved the AES walk mock in dark: "this looks great" |
| Top bar and Tour panel | Drawing: `https://claude.ai/artifact/SL8oXcudtkyrsMVMCovvJZ` |
| Speed, theme and keyboard keys move into Settings | Steve: "yes and yes" |
| Dark is the first theme | Steve: "yes and yes" |
| A visible "Target device" label | Lead, because the course assumes no knowledge |

## 2. Kill condition

The work ends when all of these are true, by 2026-11-13:

1. All 5 slices are merged.
2. `node node_modules/@playwright/test/cli.js test` (in `app/`) passes every spec on one head, and `acceptance/run.ps1 -Clauses All` has no new failure against main. The real-Electron fit test failed 2 times in 33 runs, then 0 times in 67, with no cause found (#181). Steve waived it on 2026-11-06 until it happens again. The catch stays in the test, and a next failure goes down the `/bugfix` path.
3. Real Electron at 1440 x 770 and 1280 x 640 shows 0 cut panels, 0 cut lesson names, and 1 row of top-bar controls.
4. Steve has seen slice 2 and slice 3 in the app and reacted.

## 3. Shell shape, and the walk's root

`App.vue` gets 3 named regions. The current panels keep their contents.

| Region | Test id | Holds |
|---|---|---|
| Top bar | `top-bar` | The groups in section 5, slice 2 |
| Lesson rail | `lesson-rail` | Unchanged test id |
| Workspace | `workspace` | The diagram, bytes, tour and secrets panels, or the walk |

**The walk mounts in the workspace.** The element is `<section data-testid="walk-root" class="walk-root">`. It replaces the diagram, bytes, tour and secrets panels while the AES walk is open, and the rail and top bar stay. `.walk-root` has `position: relative` and `overflow: clip`, so Pause and flying bytes stay inside it (`walkthrough-design.md` section 2.2a).

Richard confirmed this on 2026-11-06, with 4 conditions:

1. The control that opens the walk keeps `aes-walk-tab`. It stays visible while the walk is open, and it is also the way back. `aes-walk-panel` is Richard's, inside the root.
2. `workspace` scrolls, and `walk-root` grows with its content.
3. Tips and spec cards mount in one overlay layer outside `walk-root`, so the clip cannot cut them. The shell provides that layer.
4. `walk-root` stays mounted with Show keys OFF, because the closed line shows inside it.

The tour panel hides while the walk is open. A tour step says to open the walk, and the learner returns by the same control.

Reason: the approved mock needs about 1180 px of width. The bottom panel has about 700 px at 1440 wide.

## 4. Boundaries

| Item | Rule |
|---|---|
| May do without asking | Change `app/src`, `app/e2e` and this doc. Push my own branches. Open PRs |
| Needs approval | A new package (section 7). Any write under `acceptance/`: Echo owns it, so I send her the change |
| Removals | None. Steve approves each removal from a checklist |
| A gate refuses | Stop and report the command and the refusal text |
| A spec fails after a move | Fix the code or the spec in that slice. Never skip a spec |
| Two sources disagree | The approved mock wins on look. `ux-design.md` wins on behaviour. Report the conflict |
| Port use | Only at a turn from the lead. Side ports 5173 and 5193 serve short runs. Other agents use 5173 too, so check it first: the side run's renderer refuses a busy port |

## 5. Slices

| # | Slice | What changes on screen | Specs that move |
|---|---|---|---|
| 1 | Tokens and type | The mock's palette and the 3 type roles reach every panel. `--readable`, `--encrypted`, `--pass` and `--fail` keep their meaning, because lessons teach with them. Dark is the first theme | `theme-switch.spec.ts`: a first run reads dark, and an unknown saved value falls back to dark. `contrast-sweep` stays as is and must pass |
| 2 | Shell and top bar | Groups by job: the course, the mode and view, where it runs, your keys. Settings holds speed, theme and keyboard keys. "Target device" has its label | `contrast.ts` `setTheme` and `theme-switch.spec.ts` open Settings first. `lesson-0.spec.ts` keeps `target-select`. `bytes-fit.spec.ts` keeps its 1-row check |
| 3 | Tour panel | A step bar. The try-it is the one action to do. Next says why it is off, beside it | Test ids stay: `tour-next`, `next-reason`, `tour-try-it-action`, `tour-progress`. New check: the footer stays on screen for every lesson 1 step |
| 4 | Rail, diagram, bytes, secrets | Fixed column widths, so 1280 x 640 stops scrolling. Binary hover on hex, on every hex surface | `bytes-fit.spec.ts` adds 1280 x 640. `bytes-grid.spec.ts` stays. New check: every hex byte has binary hover |
| 5 | Other screens | Free play, Security setup, vault and wizard reach the same tokens and controls | `security-v0`, `vault-v1` and `contrast-sweep` stay as they are and must pass |

Order across the team, from Richard: slice 2 lands the shell, then SC, then W1b.

## 6. Standing rules each slice keeps

1. **Spec names are hover cards.** Richard's SC builds the card, `specs.json` and the Electron link rule. The shell adds no links. Any slice that adds one before SC lands adds `setWindowOpenHandler` first: it always denies a new window, and it calls `shell.openExternal` only for hosts in `specs.json`. Rule text: `ux-design.md`.
2. **Hex has binary hover,** from slice 4.
3. **"Target device" stays visible.** It has a label at every width.
4. **OS transport stays in the top bar at every width.** Clause `A16.ui.os-transport-label-and-hidden-secrets` clicks `transport-switch`, and I do not write under `acceptance/`. This differs from the drawing at 1280 wide, where it moved into Settings.
5. **Contrast and motion.** Every slice passes the 4.5 to 1 sweep in both themes. Every motion respects `prefers-reduced-motion`.
6. **Pictures.** Each PR body shows before and after, in both themes.

## 7. Fonts

The mock uses Familjen Grotesk, Atkinson Hyperlegible and JetBrains Mono. The app works offline, so the fonts ship inside it. The lead approved 3 `@fontsource` packages on conditions: pinned versions at least 2 weeks old, the license and install scripts read first, only the weights in use, the licenses recorded, and a spec that fails if a font request leaves the app. #184 reports each condition.

## 8. Not in this plan

1. W1b and the walk screens, which are Richard's.
2. TLS 1.3 record fields, which need engine data (#182).
3. A window that resizes its pane shares live. The share is set when the window opens.

## 9. Prior art checked

1. `MMP.ProgrammingGems/INDEX.md`: no gem covers a shell or a theme. `bands-fill-viewport` is the nearest, and it is about page width, so it does not apply.
2. System-design catalog: not relevant. This plan has no server, queue or data store.

## 10. Disposition

Slice 1 is #184. Slice 2 follows when #182 and #184 land. OS transport stays in the top bar at every width, and the slice 2 picture tells Steve why.
