// Starts a Host whose vault folder holds a damaged master.key (10 bytes, not 32), for the VAULT_MASTER_KEY_BAD spec.
// It runs as a Playwright webServer on the port in NETSEC_PORT (5191 when unset) with its own NETSEC_SECURITY_DIR, so the main Host and the repo's .security folder stay untouched.
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const dll = process.env.NETSEC_HOST_DLL || path.resolve(__dirname, '..', '..', 'src', 'NetSec.Host', 'bin', 'Release', 'net10.0', 'NetSec.Host.dll')
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-bad-key-'))
fs.mkdirSync(path.join(dir, 'vault'), { recursive: true })
fs.writeFileSync(path.join(dir, 'vault', 'master.key'), Buffer.alloc(10))

const child = spawn('dotnet', [dll], { stdio: 'inherit', env: { ...process.env, NETSEC_SECURITY_DIR: dir, NETSEC_PORT: process.env.NETSEC_PORT || '5191', NETSEC_TOKEN: 'badkey-token' } })
child.on('exit', code => process.exit(code ?? 0))
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => child.kill())
