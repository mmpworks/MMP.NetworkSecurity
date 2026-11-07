// Proof that two e2e runs share a machine: starts N Playwright runs at once, each with its own NETSEC_PORT_BASE block, and exits 0
// only when every run passes. Usage: node scripts/concurrent-e2e.mjs [base ...] -- [playwright args]
// Default: bases 36200 and 36300, and the specs that start a preview, both Hosts and a real Electron Host.
import { spawn } from 'node:child_process'

const sep = process.argv.indexOf('--')
const bases = process.argv.slice(2, sep < 0 ? undefined : sep).map(Number).filter(Number.isInteger)
const specs = sep < 0 ? ['e2e/vault-v1.spec.ts', 'e2e/start.spec.ts', 'e2e/origins-electron.spec.ts'] : process.argv.slice(sep + 1)
const runs = bases.length ? bases : [36200, 36300]

function run(base) {
  return new Promise(resolve => {
    const started = Date.now()
    const child = spawn('npx', ['playwright', 'test', `--output=test-results/concurrent-${base}`, ...specs], {
      stdio: ['ignore', 'pipe', 'pipe'], shell: true,
      env: { ...process.env, NETSEC_PORT_BASE: String(base) },
    })
    let tail = ''
    for (const stream of [child.stdout, child.stderr]) stream.on('data', d => { tail = (tail + d).slice(-600) })
    child.on('exit', code => resolve({ base, code, seconds: Math.round((Date.now() - started) / 1000), tail }))
  })
}

const results = await Promise.all(runs.map(run))
for (const r of results) console.log(`base ${r.base}: exit ${r.code} in ${r.seconds}s\n${r.tail.trim().split('\n').slice(-2).join('\n')}`)
const failed = results.filter(r => r.code !== 0)
console.log(failed.length ? `FAIL ${failed.length} of ${results.length} runs` : `PASS ${results.length} of ${results.length} runs ran at once`)
process.exit(failed.length ? 1 : 0)
