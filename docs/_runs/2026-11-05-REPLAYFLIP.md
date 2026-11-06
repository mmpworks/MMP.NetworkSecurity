# REPLAYFLIP, 2026-11-05: a replay picks each line by the toggle as it goes out

Result: the fix runs. Based on PR #140's branch, because it uses `ShowKeysFence`.

## Steps

| Step | Result |
|---|---|
| Red test at `4167237`, 5 runs | 5 of 5 FAIL. 20 to 34 secrets with hex reached the socket after the flip frame, with 480 to 837 trace frames still to go |
| `dotnet test tests/NetSec.Host.Tests` after the fix | 160 of 160 |
| The replay test alone after the fix, 5 runs | 5 of 5 pass |

## Limit of the test

The test needs the flip to land while the replay runs. On this machine 480 to 837 of 3,000 frames were still to go when it landed. A much slower machine could finish the replay first. The test then fails with "the replay ended before the flip", and it never passes in that case.
