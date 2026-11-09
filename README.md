# MMP.NetworkSecurity

A private teaching course. A learner watches a client prove who it is to a server, one message at a time, on live traffic.

- **What it teaches.** How data is locked (AES), sealed (hash, HMAC, CMAC) and agreed on in public (X25519, ML-KEM, the hybrid). How a server and a client prove who they are (certificates, signatures, mutual TLS, tokens). How TLS 1.3, TLS 1.1 and SSH work, how a PIN gets a new key for each sale (DUKPT), and why a compare must take the same time.
- **How.** Twelve lessons (a toy lesson 0 and lessons 1 to 11). Each lesson runs a real lab, shows every message and key, and has attack buttons that break one thing and name the check that catches it.
- **The old-device story.** Lessons 7 to 9 put an old device (TLS 1.1 or SSH) beside a modern TLS 1.3 server, and show what a gateway protects and what stays exposed.

## Open it

```
pwsh tools/open-app.ps1
```

The script builds what is missing, checks the Electron binary, and opens the app. `pwsh tools/open-app.ps1 -Check` builds and stops before the launch.

## You need

1. .NET 10 and PowerShell 7.
2. Node (the app is Electron 33 with Vue 3).
3. MMP.AsyncProxy in a folder beside this repo (or set `AsyncProxyRoot`).
4. The .NET Compact Framework 3.5 reference assemblies at `E:\dev\tools\netcf35-ref`. They are never committed.
5. Visual Studio 2022 (the C++ tools) for lesson 11's native DLL. Without it lesson 11 shows a named error and every other lesson opens.

## Run the test suite

```
pwsh acceptance/run.ps1 -Clauses All
```

It writes a report under `docs/_runs/`. The suite also uses OpenSSL and Go as referees (see `acceptance/README.md`).

## A fresh worktree

A new worktree has no build output and no `app/node_modules`. Before the app suite (`npm.cmd run e2e` in `app/`) run, from the repo root:

```
dotnet build src/NetSec.Host -c Release
```

Without it the suite stops at once with `HOST_DLL_STALE: no Release Host at ...`. That stop is intended: the suite runs the Release Host and never builds one. Run `npm install` in `app/` first (`tools/gate.ps1` never installs and stops with `TOOL_MISSING`).

## Read this first

1. All keys are made-up training keys. Anyone can read them in the source. Never use this engine with a real secret.
2. Built to show the parts. Do not copy.
3. The code is CF-compiled, run on the desktop CLR, never run on CE.
4. The repository is private. Third-party licences are in `THIRD-PARTY-NOTICES.md`.
