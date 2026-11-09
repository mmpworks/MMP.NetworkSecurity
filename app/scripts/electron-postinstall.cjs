// npm postinstall: repair a half-installed Electron from the local cache (tools/electron_dist.py repair --soft).
// Launched with node, which npm always has, so a missing python can never fail an install: it prints a warning and exits 0.
// Reads the local Electron cache only; it never downloads anything.
const { spawnSync } = require('node:child_process')
const path = require('node:path')

const appDir = path.resolve(__dirname, '..')
const tool = path.resolve(appDir, '..', 'tools', 'electron_dist.py')
const run = spawnSync('python', ['-I', tool, 'repair', '--soft', '--app-dir', appDir], { stdio: 'inherit' })
if (run.error) {
  console.warn(`electron postinstall: could not run python (${run.error.code ?? run.error.message}). Check the Electron binary yourself: python -I tools/electron_dist.py check --app-dir app`)
}
process.exit(0)
