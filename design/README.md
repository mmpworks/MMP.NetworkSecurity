# Design mock: the AES walk and the technique tabs

This folder saves the approved design mock and the script that builds it. The published copy is a private artifact page: https://claude.ai/artifact/Gh3NMKk3kbgtyfvk5JZEhT

## What is here

| Path | What it is |
|---|---|
| `mock/aes-walk-mock.html` | The built mock page, version 27 |
| `mock/template.html` | The page source. `build_mock.py` puts the data into it |
| `mock/build_mock.py` | Makes every byte the page shows, and checks each against published test values |
| `mock/*_view.js`, `mock/keys_anim.js` | View code for each tab, as inserted into the template |
| `mock/patch_*.py` | The edits made to the template, in order. Kept as a record |
| `mock/tests/mock_*.cjs` | Playwright checks used while building the mock |
| `facts-sheet.md` | The fact sheet the reviewer kept while checking the course and the mock. It was checked against main 7b569a1. For the status of each method, `app/src/glossary.json` is the newer source |
| `evidence/sealed-sample/` | The sealed-sample runs the fact sheet cites as `sealed-sample/...`: commands, cases and output. `ikm.bin` and the key files are throwaway test material, made for these runs only |
| `evidence/r182/decrypt.py` | The decrypt check the fact sheet cites as `r182/decrypt.py` |

## The rule the mock follows

The page computes no byte. `build_mock.py` makes every value and checks it against published values: FIPS 197 appendices A and C, SP 800-38A, GCM test cases 1 and 3, RFC 4231, RFC 5869, RFC 7748 section 6.1, and the Chain of Custody spec's case 002. Only test keys and made-up keys appear.

## Rebuild

```
python -I mock/build_mock.py
```

`build_mock.py` reads the Chain of Custody spec's vector 002 from `E:/dev/ffiec-public/spec/test-vectors/002-multi-event-same-run`. On another machine, clone the public spec repo (mmpworks/SR-26.2-Model-Risk-Management) and change that path.

The tests take two arguments: a folder that holds `node_modules/playwright`, and the folder that holds the built page. They were written for a scratch folder, so some paths in them need editing before reuse.
