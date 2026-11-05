# Third-party notices

Conclusion: this repository commits no third-party binary. The app, when built, ships Electron 33.2.1 (which carries Chromium) and four npm packages. The Go referees use two Go modules. The Host's practice vault uses six NuGet packages (section 6). Each licence below was read from the file named, on 2026-11-05.

## 1. What was read

1. Electron and Chromium: `node_modules/electron/dist/LICENSE` and `dist/LICENSES.chromium.html` in an installed tree (`E:\dev\ns-s0-app\app`, Electron 33.2.1, `dist/version` reads 33.2.1). Another tree (`E:\dev\ns-ui13\app`) holds an Electron folder without those files, so it was not used for them.
2. Direct npm dependencies: the `license` field of each package's own `package.json`, and the licence file in each package folder, in `E:\dev\ns-ui13\app\node_modules`.
3. All 188 installed npm packages: the `license` field of each `package.json`. The count by licence is in section 4.
4. Go: the `LICENSE` file of each module in the Go module cache, at the versions `acceptance/referees/go/go.mod` names.
5. NuGet: the `<license>` and `<copyright>` fields of each package's `.nuspec`, and `LICENSE.txt` where the package carries one, in the NuGet cache (`%USERPROFILE%\.nuget\packages`), at the versions `src/NetSec.Vault/obj/project.assets.json` resolves.

## 2. Electron and Chromium (shipped with the app)

| Part | Licence | Read from |
|---|---|---|
| Electron 33.2.1 | MIT. "Copyright (c) Electron contributors" and "Copyright (c) 2013-2020 GitHub Inc." | `dist/LICENSE` |
| Chromium and its bundled components | Many licences. The file is titled "Credits", is 9,099,045 bytes, and holds 377 entries marked `class="product"` (counted by string match) | `dist/LICENSES.chromium.html` |

A packaged app must carry both files beside `electron.exe`. This repository does not package the app. `tools/open-app.ps1` runs Electron from `node_modules`, where both files already sit.

## 3. npm dependencies named in `app/package.json`

| Package | Version | Licence | Ships in the app | Licence file read |
|---|---|---|---|---|
| `vue` | 3.5.13 | MIT | yes | `LICENSE` |
| `vuetify` | 3.13.7 | MIT | yes | `LICENSE.md` |
| `splitpanes` | 4.1.2 | MIT | yes | `LICENSE` |
| `@mdi/font` | 7.4.47 | Apache-2.0 by `package.json`. Its `LICENSE` is the Pictogrammers Free License: icons and fonts under Apache 2.0, code under MIT | yes | `LICENSE` |
| `electron` | 33.2.1 | MIT | yes (section 2) | `LICENSE` |
| `@playwright/test` | 1.64.1 | Apache-2.0. Its `NOTICE` says it contains code derived from Puppeteer, Apache 2.0 | tests only | `LICENSE`, `NOTICE` |
| `@vitejs/plugin-vue` | 5.2.1 | MIT | build tool | `LICENSE` |
| `vite` | 6.0.7 | MIT | build tool | `LICENSE.md` |
| `vue-tsc` | 2.2.0 | MIT | build tool | `LICENSE` |
| `typescript` | 5.7.2 | Apache-2.0 | build tool | `LICENSE.txt` |
| `concurrently` | 9.1.2 | MIT | dev script | `LICENSE` |
| `cross-env` | 7.0.3 | MIT | dev script | `LICENSE` |
| `wait-on` | 8.0.1 | MIT | dev script | `LICENSE` |

"Ships in the app" follows `dependencies` and `devDependencies` in `app/package.json`. A bundler can also inline code from a build tool. That was not checked.

## 4. All installed npm packages

188 packages were read from `E:\dev\ns-ui13\app\node_modules`. `package-lock.json` lists 242 entries under `packages`. The 54 entries that are not installed on this machine were not read, and the reason for the gap was not investigated.

| Licence (`license` field) | Packages |
|---|---|
| MIT | 153 |
| ISC | 13 |
| BSD-3-Clause | 10 |
| Apache-2.0 | 7 |
| BSD-2-Clause | 3 |
| 0BSD | 1 |
| (MIT OR CC0-1.0) | 1 (`type-fest` 0.13.1) |

No package declared a copyleft licence. This table reads the declared field only. It does not replace a scan of the licence files.

## 5. Go modules (the referees under `acceptance/referees/go`)

| Module | Version | Licence | Read from |
|---|---|---|---|
| `golang.org/x/crypto` | v0.58.0 | BSD-3-Clause | `LICENSE` in the module |
| `golang.org/x/sys` | v0.49.0 (indirect) | BSD-3-Clause. The file is identical to the x/crypto file (checked with `diff`) | `LICENSE` in the module |

The x/crypto module also carries a `PATENTS` file (the Go additional patent grant); the x/sys module's `PATENTS` file was not checked. The text of the `LICENSE` file:

```
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

## 6. NuGet packages (the Host's practice vault)

`src/NetSec.Vault` names two packages. NuGet resolves four more under them. The build copies their DLLs and `runtimes/win-x64/native/e_sqlite3.dll` into the Host's output folder. Git holds none of them.

| Package | Version | Licence | Copyright | Read from |
|---|---|---|---|---|
| `Microsoft.Data.Sqlite.Core` | 10.0.9 | MIT | © Microsoft Corporation | `.nuspec` |
| `SQLitePCLRaw.bundle_e_sqlite3` | 3.0.3 | Apache-2.0 | Copyright 2014-2026 SourceGear, LLC | `.nuspec` |
| `SQLitePCLRaw.config.e_sqlite3` | 3.0.3 | Apache-2.0 | Copyright 2014-2026 SourceGear, LLC | `.nuspec` |
| `SQLitePCLRaw.core` | 3.0.3 | Apache-2.0 | Copyright 2014-2025 SourceGear, LLC | `.nuspec` |
| `SQLitePCLRaw.provider.e_sqlite3` | 3.0.3 | Apache-2.0 | Copyright 2014-2025 SourceGear, LLC | `.nuspec` |
| `SourceGear.sqlite3` | 3.50.4.5 | SQLite is public domain. The file reads "SQLite is Public Domain" and links https://sqlite.org/copyright.html | | `LICENSE.txt`, 61 bytes |

`Microsoft.Data.Sqlite` 10.0.9 is not used. It pulls a SQLite older than 3.50.2, which carries advisory GHSA-2m69-gcr7-jv3q (`docs/modes-design.md` section 4.4).

## 7. Not in this repository

1. The .NET Compact Framework 3.5 reference assemblies (`E:\dev\tools\netcf35-ref`). They are Microsoft files, kept out of the repository, and the acceptance suite checks that no CF binary is committed.
2. The X9.24-3 test vectors. The PRD licence checklist keeps them behind a fetch script and out of the repository.
3. MMP.AsyncProxy. It is a sibling project of the same owner, referenced by path.
4. OpenSSL and the Go toolchain. The referee tests run them from the machine. They are not copied here.

Licences not read: the installed tools themselves (.NET, Node, PowerShell, Visual Studio) are not redistributed by this repository, and their licences were not read.
