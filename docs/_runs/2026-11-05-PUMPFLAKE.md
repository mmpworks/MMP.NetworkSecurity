# Gate PUMPFLAKE, 2026-11-05

Result: 20 of 20 steps passed. Skipped: 1.

| Step | Status | Exit |
|---|---|---|
| layer_check | PASS | 0 |
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
| tic-gate lesson-10.json | PASS | 0 |
| tic-gate lesson-11.json | PASS | 0 |
| playwright lesson spec | SKIPPED |  |
| lessons_status | PASS | 0 |

## layer_check

```
layer_check: 108 files, 0 problems
```

## dotnet build src/NetSec.Core

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:03.41
```

## dotnet build src/NetSec.Core.NetCF

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:02.05
```

## dotnet test net10.0

```
  NetSec.Tests -> E:\dev\ns-s7\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll
Test run for E:\dev\ns-s7\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Results File: E:\dev\ns-s7\docs\_runs\trx\PUMPFLAKE-net10\Steve_BEAST_2026-11-05_06_25_34.trx

Passed!  - Failed:     0, Passed:   452, Skipped:     0, Total:   452, Duration: 15 s - NetSec.Tests.dll (net10.0)
```

## dotnet test net48 (CF binaries)

```
  NetSec.Tests -> E:\dev\ns-s7\tests\NetSec.Tests\bin\Release\net48\NetSec.Tests.dll
Test run for E:\dev\ns-s7\tests\NetSec.Tests\bin\Release\net48\NetSec.Tests.dll (.NETFramework,Version=v4.8)
A total of 1 test files matched the specified pattern.
Results File: E:\dev\ns-s7\docs\_runs\trx\PUMPFLAKE-cf\Steve_BEAST_2026-11-05_06_25_59.trx

Passed!  - Failed:     0, Passed:   452, Skipped:     0, Total:   452, Duration: 16 s - NetSec.Tests.dll (net48)
```

## dotnet test Host (live process)

```
  NetSec.Host.Tests -> E:\dev\ns-s7\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll
Test run for E:\dev\ns-s7\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Results File: E:\dev\ns-s7\docs\_runs\trx\PUMPFLAKE-host\Steve_BEAST_2026-11-05_06_26_29.trx

Passed!  - Failed:     0, Passed:    23, Skipped:     0, Total:    23, Duration: 1 s - NetSec.Host.Tests.dll (net10.0)
```

## acceptance A9

```
[acceptance] 4 clauses selected of M = 204 (+ 22 self-checks in the file)
[acceptance] preparing: MMP.AsyncProxy builds, product builds
[acceptance] group binproof (net10): 4 clauses
[acceptance] 4 of 4 clauses PASS (0 FAIL, 0 NOT RUN); M = 204
[acceptance] report: E:\dev\ns-s7\docs\_runs\acceptance-20261105-062631.md
[acceptance] json:   E:\dev\ns-s7\docs\_runs\acceptance-20261105-062631.json
```

## tour_lint

```
lesson-06.json: 13 steps, grade 3.33, concept share 0.15
lesson-07.json: 10 steps, grade 3.60, concept share 0.20
lesson-08.json: 13 steps, grade 3.95, concept share 0.15
lesson-10.json: 20 steps, grade 4.49, concept share 0.10
lesson-11.json: 8 steps, grade 4.33, concept share 0.25
tour_lint: 11 files, 0 problems
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
no -Lesson given
```

## lessons_status

```
lessons_status: 11 tours of 12 lessons; wrote docs/_runs\lessons.json
```

