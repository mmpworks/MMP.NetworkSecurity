# AO bench report: the file the S0 benchmark writes

Owner: Echo (the anchor sets the shape; the benchmark conforms). Writer: the S0 benchmark project (Richard). Reader: `acceptance/run.ps1 -AoBenchReport PATH`.

The file gives the AO-5 and AO-6 rows of `acceptance/ao-rows.tsv`. The suite judges each row from the numbers in the file. A status in the file is not read.

## Shape

One JSON object, UTF-8.

```json
{
  "schema": 1,
  "commit": "full SHA of the head the benchmark ran on",
  "runtime": ".NET 10.0.x, as RuntimeInformation.FrameworkDescription prints it",
  "machine": "CPU name and core count",
  "rows": [
    { "id": "AO-5.aes-block.net10", "bytesPerOp": 64.0, "op": "one 16-byte block" },
    { "id": "AO-6.aes-block.net10", "baselineNsPerOp": 812.5, "newNsPerOp": 160.1, "op": "one 16-byte block" }
  ]
}
```

## Rules

1. Each `id` is one line of `acceptance/ao-rows.tsv` with source `bench`. Every such line has one row in the file.
2. An AO-5 row has `bytesPerOp`: bytes allocated for each operation after warm-up, on .NET 10. The suite reads PASS when `bytesPerOp` is 0, else FAIL with reason `AO5_ALLOCATES`.
3. An AO-6 row has `baselineNsPerOp` (the 5c5d4a4 code) and `newNsPerOp` (the head), from the same run on the same machine. The suite reads PASS when both are numbers greater than 0. From slice S1, `AO-6.aes-block.net10` also needs `baselineNsPerOp / newNsPerOp` of 5 or more, else FAIL with reason `AO6_BELOW_TARGET`.
4. An AO-9 row (PRD 3.3, the file benchmark; "original" is the frozen copy in `acceptance/groups/algo/Frozen`) has `outputsEqual` (a JSON boolean), `originalNsPerOp`, `newNsPerOp` and `files` (a whole number). The suite reads PASS when `outputsEqual` is true and both numbers are greater than 0. A false `outputsEqual` reads FAIL with reason `AO9_OUTPUT_DIFFERS`. `files` is 7 for gcm, cbc, ctr, sha256 and hmac (the lines of `bench/files/files.tsv`); pool-25 and small-message give the count they use. AO-9 is record-only at S0.
   The numbers, as agreed with the benchmark owner on 2026-11-11: gcm, cbc and ctr give the sum over the 7 files of the median ns for each call in both directions (seal and open, encrypt and decrypt); sha256 and hmac give the sum of one call per file. small-message is one key setup and one 64-byte GCM seal, as one call. pool-25 is the wall time of 25 workers x 8 seals of `sample.csv` on one shared key, and `outputsEqual` is false on any difference from the one-thread output.
5. A row that is missing, or has a missing or non-numeric field, reads FAIL with reason `AO_BENCH_ROW_BAD`.
6. `commit` must equal the head of the run that reads the file, else every bench row reads FAIL with reason `AO_BENCH_OTHER_COMMIT`.
7. The report line "CF ARM speed: UNMEASURED" stays in the benchmark write-up until a run on a CE device exists. No row stands for it.

## Rows

The AO-5, AO-6 and AO-9 lines of `acceptance/ao-rows.tsv` are the list. AO-5: aes-block, aes-ecb, aes-cbc, aes-ctr, aes-gcm, aes-cmac, md5, sha1, sha256, sha512, keccak, hmac, tdes, dukpt-derive (net10). AO-6: the same, and aes-key-setup (net10). AO-9: gcm, cbc, ctr, sha256, hmac, small-message, pool-25, each on net10 and cf.

```json
{ "id": "AO-9.gcm.net10", "outputsEqual": true, "originalNsPerOp": 91234.5, "newNsPerOp": 18001.2, "files": 7, "op": "seal + open, sum of medians over 7 files" }
```
