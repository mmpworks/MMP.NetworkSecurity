import { execFileSync } from 'node:child_process'
import * as path from 'node:path'

// Playwright globalSetup: the first line of every suite run names the commit it ran on, "run @ <sha>" or "run @ <sha>+dirty" (a tracked file
// differs from the commit). tools/run_status.py reads it. Untracked files do not count.
function git(args: string[]): string | null {
  try {
    return execFileSync('git', args, { cwd: path.resolve(__dirname, '..', '..'), encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim()
  } catch { return null }
}

export default function commitLine(): void {
  const sha = git(['rev-parse', '--short', 'HEAD'])
  const dirty = (git(['status', '--porcelain', '--untracked-files=no']) ?? '') !== ''
  console.log(`run @ ${sha ? sha + (dirty ? '+dirty' : '') : 'unknown'}`)
}
