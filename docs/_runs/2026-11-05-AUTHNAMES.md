# Gate AUTHNAMES, 2026-11-05

Result: 18 of 20 steps passed. Skipped: 1.

| Step | Status | Exit |
|---|---|---|
| layer_check | PASS | 0 |
| dotnet build src/NetSec.Core | PASS | 0 |
| dotnet build src/NetSec.Core.NetCF | PASS | 0 |
| dotnet test net10.0 | PASS | 0 |
| dotnet test net48 (CF binaries) | FAIL | 1 |
| dotnet test Host (live process) | PASS | 0 |
| acceptance A9,A11 | FAIL | 1 |
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

Time Elapsed 00:00:02.95
```

## dotnet build src/NetSec.Core.NetCF

```

Build succeeded.
    0 Warning(s)
    0 Error(s)

Time Elapsed 00:00:02.45
```

## dotnet test net10.0

```
  NetSec.Tests -> E:\dev\ns-authnames\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll
Test run for E:\dev\ns-authnames\tests\NetSec.Tests\bin\Release\net10.0\NetSec.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Results File: E:\dev\ns-authnames\docs\_runs\trx\AUTHNAMES-net10\Steve_BEAST_2026-11-05_06_39_38.trx

Passed!  - Failed:     0, Passed:   457, Skipped:     0, Total:   457, Duration: 15 s - NetSec.Tests.dll (net10.0)
```

## dotnet test net48 (CF binaries)

```
  Determining projects to restore...
  All projects are up-to-date for restore.
  MMP.AsyncProxy.NetCF -> E:\dev\MMP.AsyncProxy\src\MMP.AsyncProxy.NetCF\bin\Release\net35\MMP.AsyncProxy.dll
  NetSec.Core.NetCF -> E:\dev\ns-authnames\src\NetSec.Core.NetCF\bin\Release\net35\NetSec.Core.dll
CSC : error CS2012: Cannot open 'E:\dev\ns-authnames\src\NetSec.Core.NetCF\obj\Release\net35\NetSec.Core.dll' for writing -- The process cannot access the file 'E:\dev\ns-authnames\src\NetSec.Core.NetCF\obj\Release\net35\NetSec.Core.dll' because it is being used by another process. [E:\dev\ns-authnames\src\NetSec.Core.NetCF\NetSec.Core.NetCF.csproj]
```

## dotnet test Host (live process)

```
  NetSec.Host.Tests -> E:\dev\ns-authnames\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll
Test run for E:\dev\ns-authnames\tests\NetSec.Host.Tests\bin\Release\net10.0\NetSec.Host.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.
Results File: E:\dev\ns-authnames\docs\_runs\trx\AUTHNAMES-host\Steve_BEAST_2026-11-05_06_40_11.trx

Passed!  - Failed:     0, Passed:    23, Skipped:     0, Total:    23, Duration: 2 s - NetSec.Host.Tests.dll (net10.0)
```

## acceptance A9,A11

```
[acceptance] preparing: MMP.AsyncProxy builds, product builds
[acceptance] group auth (net10): 9 clauses
[acceptance] group binproof (net10): 4 clauses
[acceptance] 6 of 13 clauses PASS (7 FAIL, 0 NOT RUN); M = 204
[acceptance] report: E:\dev\ns-authnames\docs\_runs\acceptance-20261105-064015.md
[acceptance] json:   E:\dev\ns-authnames\docs\_runs\acceptance-20261105-064015.json
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
the -SkipApp switch
```

## lessons_status

```
lessons_status: 11 tours of 12 lessons; wrote docs/_runs\lessons.json
```

