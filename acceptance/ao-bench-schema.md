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
4. A row that is missing, or has a missing or non-numeric field, reads FAIL with reason `AO_BENCH_ROW_BAD`.
5. `commit` must equal the head of the run that reads the file, else every bench row reads FAIL with reason `AO_BENCH_OTHER_COMMIT`.
6. The report line "CF ARM speed: UNMEASURED" stays in the benchmark write-up until a run on a CE device exists. No row stands for it.

## Rows

The AO-5 and AO-6 lines of `acceptance/ao-rows.tsv` are the list. AO-5: aes-block, aes-ecb, aes-cbc, aes-ctr, aes-gcm, aes-cmac, md5, sha1, sha256, sha512, keccak, hmac, tdes, dukpt-derive. AO-6: the same, and aes-key-setup.
