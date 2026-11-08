# Gate p8a-toy-curve, 2026-11-07

Result: 22 of 22 steps passed. Skipped: 1.

| Step | Status | Exit |
|---|---|---|
| layer_check | PASS | 0 |
| secret_guard | PASS | 0 |
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
| playwright lesson spec | SKIPPED |  |
| lessons_status | PASS | 0 |

## layer_check

```
layer_check: 133 files, 0 problems
```

## secret_guard

```

```

## dotnet build src/NetSec.Core

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:02.13
```

## dotnet build src/NetSec.Core.NetCF

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:01.61
```

## dotnet test net10.0

```
Test run for E:\dev\ns-p8a\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-p8a\docs\_runs\trx\p8a-toy-curve-net10\Steve_BEAST_2026-11-07_20_57_13.trx

Passed!  - Failed:     0, Passed:   801, Skipped:     0, Total:   801, Duration: 1 m 53 s - NetSec.Tests.dll (net10.0)
```

## dotnet test net48 (CF binaries)

```
Test run for E:\dev\ns-p8a\tests\NetSec.Tests\bin\Release\net48\NetSec.Tests.dll (.NETFramework,Version=v4.8)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-p8a\docs\_runs\trx\p8a-toy-curve-cf\Steve_BEAST_2026-11-07_20_59_14.trx

Passed!  - Failed:     0, Passed:   801, Skipped:     0, Total:   801, Duration: 2 m 39 s - NetSec.Tests.dll (net48)
```

## dotnet test Host (live process)

```
Test run for E:\dev\ns-p8a\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Data collector 'Blame' message: All tests finished running, Sequence file will not be generated.
Results File: E:\dev\ns-p8a\docs\_runs\trx\p8a-toy-curve-host\Steve_BEAST_2026-11-07_21_02_02.trx

Passed!  - Failed:     0, Passed:   222, Skipped:     0, Total:   222, Duration: 1 m 12 s - NetSec.Host.Tests.dll (net10.0)
```

## acceptance A9

```
[acceptance] 4 clauses selected of M = 385 (+ 44 self-checks in the file)
[acceptance] preparing: MMP.AsyncProxy builds, product builds
[acceptance] group binproof (net10): 4 clauses
[acceptance] 4 of 4 clauses PASS (0 FAIL, 0 NOT RUN); M = 385
[acceptance] report: E:\dev\ns-p8a\docs\_runs\acceptance-20261107-210315.md
[acceptance] json:   E:\dev\ns-p8a\docs\_runs\acceptance-20261107-210315.json
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

## playwright lesson spec

```
the -SkipApp switch
```

## lessons_status

```
lessons_status: 12 tours of 12 lessons; wrote docs/_runs\lessons.json
```

