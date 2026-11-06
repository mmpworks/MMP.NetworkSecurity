# FLIPORDER, 2026-11-05: a line picked while ON goes out ahead of the flip to OFF

Result: the fix runs. The red test passes, 5 of 5 repeat runs.

## Steps

| Step | Result |
|---|---|
| Red test at `8cd0ace` | FAIL: "a line with key bytes reached the socket after the flip to OFF", on `<sessionId>/keys#1` (`key.in-use`) |
| `dotnet test tests/NetSec.Host.Tests` after the fix | 159 of 159 |
| `ShowKeysFlipOrderTests` run alone, 5 times | 5 of 5 |
| `run.ps1 -Clauses A17.show-keys` | 4 of 5. `off-holds-no-secret` fails on `auth.issued-challenge` in lesson 10, as on `main`. PR #139 moves that name to state |

## Same class, not fixed here

`Program.cs:329-332`, the `session.load` replay, reads the toggle once and then sends every line of the file. A flip during a replay can put shown lines after the flip frame. The window is the whole file, wider than the one-line window this PR closes. It needs its own red test over the WebSocket.
