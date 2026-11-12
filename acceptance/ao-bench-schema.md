# AO bench report: the file the S0 benchmark writes

Owner: Echo (the anchor sets the shape; the benchmark conforms). Writer: the S0 benchmark project (Richard). Reader: `acceptance/run.ps1 -AoBenchReport PATH`.

The anchor does not judge a hard claim from numbers that the builder's code writes (Jared on #405, B1). So the suite measures AO-5 allocation and computes AO-9 output equality itself. The bench report holds the AO-6 and AO-9 timing, and a second record of AO-5 bytes and AO-9 equality. A status in the file is not read.

## Shape

One JSON object, UTF-8.

```json
{
  "schema": 1,
  "commit": "full SHA of the head the benchmark ran on",
  "runtime": ".NET 10.0.x, as RuntimeInformation.FrameworkDescription prints it",
  "machine": "CPU name and core count",
  "rows": [
    { "id": "AO-5.aes-block.net10", "bytesPerOp": 80.0, "op": "one 16-byte block" },
    { "id": "AO-6.aes-block.net10", "baselineNsPerOp": 812.5, "newNsPerOp": 160.1, "op": "one 16-byte block" },
    { "id": "AO-9.gcm.net10.time", "outputsEqual": true, "originalNsPerOp": 91234.5, "newNsPerOp": 18001.2, "files": 7, "op": "seal + open, sum of medians over 7 files" }
  ]
}
```

## Rules

1. Each AO-6 id and each AO-9 `.time` id is one line of `acceptance/ao-rows.tsv` with source `bench`. Every such line has one row in the file.
2. AO-5 is a suite row (`groups/algo/AoAlloc.Product.cs`, measured with `GC.GetAllocatedBytesForCurrentThread`). The bench AO-5 row (`bytesPerOp`) is a second record. When the suite row ran, a bench value of 0 against a suite FAIL, or above 0 against a suite PASS, makes AO-0 red with `AO5_BENCH_DISAGREES`.
3. An AO-6 row has `baselineNsPerOp` (the 5c5d4a4 code) and `newNsPerOp` (the head), from the same run on the same machine. The suite reads PASS when both are numbers greater than 0. From slice S1, `AO-6.aes-block.net10` also needs `baselineNsPerOp / newNsPerOp` of 5 or more, else FAIL with reason `AO6_BELOW_TARGET`.
4. An AO-9 `.time` row (PRD 3.3, the file benchmark; "original" is the frozen copy in `acceptance/groups/algo/Frozen`) has `outputsEqual` (a JSON boolean), `originalNsPerOp`, `newNsPerOp` and `files` (a whole number). The suite reads PASS when both numbers are greater than 0 and `files` is 7 for gcm, cbc, ctr, sha256 and hmac (the lines of `acceptance/ao9-files.tsv`); pool-25 and small-message give the count they use. Output equality is the suite's own AO-9 row (`groups/algo/AoFiles9.cs`, `groups/algothreads/AoPool9.cs`): when that row ran, a bench `outputsEqual` that differs from it makes AO-0 red with `AO9_BENCH_DISAGREES`. AO-9 timing is record-only at S0.
   The numbers, as agreed with the benchmark owner on 2026-11-11: gcm, cbc and ctr give the sum over the 7 files of the median ns for each call in both directions (seal and open, encrypt and decrypt); sha256 and hmac give the sum of one call per file. small-message is one key setup and one 64-byte GCM seal, as one call. pool-25 is the wall time of 25 workers x 8 seals of `sample.csv` on one shared key, and `outputsEqual` is false on any difference from the one-thread output.
5. A row that is missing, or has a missing or non-numeric field, reads FAIL with reason `AO_BENCH_ROW_BAD`.
6. The report is valid on a head that has the measured code and data of `commit` (a full or short id). The suite compares git object ids between `commit` and the head for: `src/NetSec.Core`, `src/NetSec.Core.NetCF`, `src/AsyncProxy.Local`, `src/AsyncProxy.Local.NetCF`, `acceptance/groups/algo/Frozen`, the build files `Directory.Build.props`, `Directory.Build.targets`, `src/Directory.Build.props`, `src/Directory.Build.targets`, `Directory.Packages.props`, `global.json` and `NuGet.config` (a file that both sides lack is equal), and each entry of `bench/` but `bench/files`. `bench/files` is data, matched one to one: a file that `acceptance/ao9-files.tsv` names and that `commit` has under the same name must have the same bytes; a listed name that is new must have the bytes of a file that `commit` has and the head lacks, and each such file is used one time (so a new name is allowed, and other bytes, a trade of bytes and a copy are not). An uncommitted change or an untracked file in these paths counts as a difference. On a difference every bench row reads FAIL with reason `AO_BENCH_OTHER_COMMIT`, and the detail names the path. When the repository does not hold `commit`, every bench row reads FAIL with reason `AO_BENCH_COMMIT_UNKNOWN`: keep a pushed tag on the measured commit. A commit that adds the report, a rebase, and a change under `acceptance/` (but the frozen folder), `docs/`, `app/`, `tests/` or `tools/` do not make the report stale.
7. The report line "CF ARM speed: UNMEASURED" stays in the benchmark write-up until a run on a CE device exists. No row stands for it.

## Rows

- AO-5 (second record, net10): aes-block, aes-ecb, aes-cbc, aes-ctr, aes-gcm, aes-cmac, md5, sha1, sha256, sha512, keccak, hmac, tdes, dukpt-derive.
- AO-6 (net10): the same, and aes-key-setup.
- AO-9 timing: `AO-9.<op>.<build>.time` for op gcm, cbc, ctr, sha256, hmac, small-message, pool-25 and build net10, cf.

## The AO-9 file set

`acceptance/ao9-files.tsv` holds the name, size and SHA-256 of each file in `bench/files`. The suite checks the files on disk against it. A missing file reads NOT RUN `AO9_FILES_ABSENT`, and a changed size or SHA-256 reads FAIL `AO9_FILE_CHANGED`.
