# Gate show-keys-not-saved, 2026-11-08

Result: 27 of 27 steps passed. Skipped: 2.

| Step | Status | Exit |
|---|---|---|
| layer_check | PASS | 0 |
| secret_guard | PASS | 0 |
| no package-runner calls in tools and app scripts | PASS | 0 |
| no package-runner check tests | PASS | 0 |
| pre-push guard tests | PASS | 0 |
| pre-push hook installed and current | PASS | 0 |
| A19.repo.walk-routes-listed | PASS | 0 |
| dotnet build src/NetSec.Core | PASS | 0 |
| dotnet build src/NetSec.Core.NetCF | PASS | 0 |
| dotnet test net10.0 | PASS | 0 |
| dotnet test net48 (CF binaries) | PASS | 0 |
| dotnet test Host (live process) | PASS | 0 |
| acceptance A9 | PASS | 0 |
| tour_lint | PASS | 0 |
| tic-gate lesson-00.json | PASS | 0 |
| tic-gate lesson-01.json | PASS | 0 |
| tic-gate lesson-02.json | PASS | 0 |
| tic-gate lesson-03.json | PASS | 0 |
| tic-gate lesson-04.json | PASS | 0 |
| tic-gate lesson-05.json | PASS | 0 |
| tic-gate lesson-06.json | PASS | 0 |
| tic-gate lesson-07.json | PASS | 0 |
| tic-gate lesson-08.json | PASS | 0 |
| tic-gate lesson-09.json | PASS | 0 |
| tic-gate lesson-10.json | PASS | 0 |
| tic-gate lesson-11.json | PASS | 0 |
| typecheck (app/src and app/e2e) | SKIPPED |  |
| playwright lesson spec | SKIPPED |  |
| lessons_status | PASS | 0 |

## layer_check

```
layer_check: 139 files, 0 problems
```

## secret_guard

```

```

## no package-runner calls in tools and app scripts

```
no npx in tools/, acceptance/, app/scripts, app/package.json or app/*.config.*
```

## no package-runner check tests

```
test_the_check_and_its_test_may_name_the_tool (__main__.NoNpx.test_the_check_and_its_test_may_name_the_tool) ... ok

----------------------------------------------------------------------
Ran 10 tests in 1.368s

OK
```

## pre-push guard tests

```
test_reused_name_with_a_new_open_pr_allows (__main__.PrePushGuard.test_reused_name_with_a_new_open_pr_allows) ... ok

----------------------------------------------------------------------
Ran 23 tests in 118.042s

OK
```

## pre-push hook installed and current

```
pre-push hook installed and current with origin/main (E:/dev/MMP.NetworkSecurity/.git/netsec-hooks)
```

## A19.repo.walk-routes-listed

```
16 walk routes in the Host, each listed with its Show keys OFF rule
```

## dotnet build src/NetSec.Core

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:06.91
```

## dotnet build src/NetSec.Core.NetCF

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:02.62
```

## dotnet test net10.0

```
Test run for E:\dev\ns-vaultfix\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-vaultfix\docs\_runs\trx\show-keys-not-saved-net10\Steve_BEAST_2026-11-08_05_56_49.trx

Passed!  - Failed:     0, Passed:   836, Skipped:     0, Total:   836, Duration: 1 m 55 s - NetSec.Tests.dll (net10.0)
```

## dotnet test net48 (CF binaries)

```
Test run for E:\dev\ns-vaultfix\tests\NetSec.Tests\bin\Release\net48\NetSec.Tests.dll (.NETFramework,Version=v4.8)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-vaultfix\docs\_runs\trx\show-keys-not-saved-cf\Steve_BEAST_2026-11-08_05_58_52.trx

Passed!  - Failed:     0, Passed:   836, Skipped:     0, Total:   836, Duration: 2 m 43 s - NetSec.Tests.dll (net48)
```

## dotnet test Host (live process)

```
Test run for E:\dev\ns-vaultfix\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-vaultfix\docs\_runs\trx\show-keys-not-saved-host\Steve_BEAST_2026-11-08_06_01_51.trx

Passed!  - Failed:     0, Passed:   286, Skipped:     0, Total:   286, Duration: 1 m 34 s - NetSec.Host.Tests.dll (net10.0)
```

## acceptance A9

```
[acceptance] 4 clauses selected of M = 404 (+ 44 self-checks in the file)
[acceptance] preparing: MMP.AsyncProxy builds, product builds
[acceptance] group binproof (net10): 4 clauses
[acceptance] 4 of 4 clauses PASS (0 FAIL, 0 NOT RUN); M = 404
[acceptance] report: E:\dev\ns-vaultfix\docs\_runs\acceptance-20261108-060326.md
[acceptance] json:   E:\dev\ns-vaultfix\docs\_runs\acceptance-20261108-060326.json
```

## tour_lint

```
lesson-07.json: 10 steps, grade 3.71, concept share 0.20
lesson-08.json: 14 steps, grade 4.09, concept share 0.14
lesson-09.json: 12 steps, grade 3.38, concept share 0.17
lesson-10.json: 21 steps, grade 4.54, concept share 0.14
lesson-11.json: 8 steps, grade 4.33, concept share 0.25
tour_lint: 12 files, 0 problems
```

## tic-gate lesson-00.json

```
clean
```

## tic-gate lesson-01.json

```
clean
```

## tic-gate lesson-02.json

```
clean
```

## tic-gate lesson-03.json

```
clean
```

## tic-gate lesson-04.json

```
clean
```

## tic-gate lesson-05.json

```
clean
```

## tic-gate lesson-06.json

```
clean
```

## tic-gate lesson-07.json

```
clean
```

## tic-gate lesson-08.json

```
clean
```

## tic-gate lesson-09.json

```
clean
```

## tic-gate lesson-10.json

```
clean
```

## tic-gate lesson-11.json

```
clean
```

## typecheck (app/src and app/e2e)

```
the -SkipApp switch
```

## playwright lesson spec

```
the -SkipApp switch
```

## lessons_status

```
lessons_status: 12 tours of 12 lessons; wrote docs/_runs\lessons.json
```

