'use strict'
// app/dist remembers the commit it was built from, so no entry point serves another branch's build (Nancy lost a probe run to that).
//   node scripts/dist-stamp.cjs write   run by `npm run build` after vite: records HEAD and a hash of uncommitted edits under app/
//   node scripts/dist-stamp.cjs check   exit 1 with DIST_STALE / DIST_MISSING / DIST_UNSTAMPED and the command to run
// Used by playwright.config.ts, electron/main.cjs and tools/open-app.ps1. A tree with no git cannot be judged: the check says "unchecked" and passes.
// Not detected: an UNTRACKED file added under app/ after the build (git diff does not list it). Edits to tracked files are.
const { execFileSync } = require('node:child_process')
const crypto = require('node:crypto')
const fs = require('node:fs')
const path = require('node:path')

const STAMP_FILE = '.build-commit.json'

function git(root, args) {
  try {
    return execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], maxBuffer: 64 * 1024 * 1024 }).trim()
  } catch { return null }
}

/** The commit this tree is on, plus a hash of its uncommitted edits to tracked files under app/ ('' when there are none). */
function current(root) {
  const commit = git(root, ['rev-parse', 'HEAD'])
  if (!commit) return { commit: 'unknown', diff: '' }
  const diff = git(root, ['diff', 'HEAD', '--no-renames', '--', 'app']) ?? ''
  return { commit, diff: diff ? crypto.createHash('sha1').update(diff).digest('hex') : '' }
}

const label = s => `${s.commit === 'unknown' ? 'unknown' : s.commit.slice(0, 7)}${s.diff ? ` + edits ${s.diff.slice(0, 8)}` : ''}`

function write(root, dist) {
  fs.mkdirSync(dist, { recursive: true })
  fs.writeFileSync(path.join(dist, STAMP_FILE), JSON.stringify(current(root)) + '\n', 'utf8')
}

/** { ok, message }. ok is false only for a stale, missing or unstamped build. */
function check(root, dist) {
  const fix = 'Run: cd app; npm run build'
  if (!fs.existsSync(dist)) return { ok: false, message: `DIST_MISSING: ${dist} does not exist. ${fix}` }
  let stamped
  try { stamped = JSON.parse(fs.readFileSync(path.join(dist, STAMP_FILE), 'utf8')) } catch {
    return { ok: false, message: `DIST_UNSTAMPED: ${dist} has no build stamp, so it may come from another branch. ${fix}` }
  }
  const now = current(root)
  if (stamped.commit === 'unknown' || now.commit === 'unknown') {
    return { ok: true, message: 'dist build unchecked: git cannot say which commit this tree or the build is on' }
  }
  if (stamped.commit !== now.commit || (stamped.diff || '') !== now.diff) {
    return { ok: false, message: `DIST_STALE: ${dist} was built from ${label(stamped)} and this tree is ${label(now)}. ${fix}` }
  }
  return { ok: true, message: `dist build matches ${label(now)}` }
}

module.exports = { check, write, current, STAMP_FILE }

if (require.main === module) {
  const args = process.argv.slice(2)
  const flag = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
  const root = path.resolve(flag('--root') ?? path.join(__dirname, '..', '..'))
  const dist = path.resolve(flag('--dist') ?? path.join(__dirname, '..', 'dist'))
  if (args[0] === 'write') { write(root, dist); console.log(`dist stamped: ${label(current(root))}`); process.exit(0) }
  if (args[0] === 'check') { const r = check(root, dist); console.log(r.message); process.exit(r.ok ? 0 : 1) }
  console.error('usage: node scripts/dist-stamp.cjs write|check [--root REPO] [--dist DIR]')
  process.exit(2)
}
