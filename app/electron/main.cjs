// Electron's main process. It starts NetSec.Host with a fresh session token, opens one window, and ends the Host on exit.
// Set NETSEC_HOST=external to skip spawning and use a Host you started yourself (then set NETSEC_PORT and NETSEC_TOKEN too).
const { app, BrowserWindow, screen, shell } = require('electron')
const { isAllowedLink } = require('./link-hosts.cjs')
const { fitWindow } = require('./window-size.cjs')
const { spawn, execFileSync } = require('node:child_process')
const crypto = require('node:crypto')
const fs = require('node:fs')
const http = require('node:http')
const path = require('node:path')

const PORT = Number(process.env.NETSEC_PORT) || 5180
const TOKEN = process.env.NETSEC_TOKEN || crypto.randomBytes(24).toString('hex')
const HOST_DLL = process.env.NETSEC_HOST_DLL || path.resolve(__dirname, '..', '..', 'src', 'NetSec.Host', 'bin', 'Release', 'net10.0', 'NetSec.Host.dll')
let host = null

// A dead stdout pipe throws EPIPE from the main process. Swallow the stream error and skip the write (same fix as the pump simulator).
function say(stream, text) {
  if (stream.destroyed) return
  try { stream.write(text) } catch (e) { /* a dead pipe: nothing to tell */ }
}
for (const s of [process.stdout, process.stderr]) s.on('error', () => {})

function startHost() {
  if (process.env.NETSEC_HOST === 'external') return
  if (!fs.existsSync(HOST_DLL)) { say(process.stderr, `[host] not built: ${HOST_DLL}\n`); return }
  host = spawn('dotnet', [HOST_DLL], {
    detached: true, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    env: { ...process.env, NETSEC_PORT: String(PORT), NETSEC_TOKEN: TOKEN },
  })
  host.stdout.on('data', d => say(process.stdout, `[host] ${d}`))
  host.stderr.on('data', d => say(process.stderr, `[host] ${d}`))
  host.on('exit', code => { say(process.stdout, `[host] exited ${code}\n`); host = null })
}

// taskkill /T ends the Host and every child it spawned.
function stopHost() {
  if (!host || !host.pid) return
  const pid = host.pid
  host = null
  // Synchronous, because Electron can exit before an async taskkill starts and leave the Host running.
  try { execFileSync('taskkill', ['/PID', String(pid), '/T', '/F'], { stdio: 'ignore' }) } catch (e) { /* already gone */ }
}

function waitForHost(timeoutMs = 60000) {
  const started = Date.now()
  return new Promise((resolve, reject) => {
    const tick = () => {
      const req = http.get({ host: '127.0.0.1', port: PORT, path: '/api/health', headers: { Authorization: `Bearer ${TOKEN}` } }, res => { res.resume(); resolve() })
      req.on('error', () => (Date.now() - started > timeoutMs ? reject(new Error('host did not start')) : setTimeout(tick, 400)))
    }
    tick()
  })
}

async function createWindow() {
  const win = new BrowserWindow({
    ...fitWindow(screen.getPrimaryDisplay().workArea), title: 'Network Security Lab', backgroundColor: '#10141f',
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, additionalArguments: [`--netsec-port=${PORT}`, `--netsec-token=${TOKEN}`] },
  })
  // Links: the app never opens a second window. A link to a listed host opens in the learner's own browser, and any other link does nothing.
  win.webContents.setWindowOpenHandler(({ url }) => {
    // The OS gets the URL in the form the rule parsed and checked, never the raw string.
    if (isAllowedLink(url)) void shell.openExternal(new URL(url).href)
    return { action: 'deny' }
  })
  // The window stays on the app's own page: a link clicked without a new-window target cannot carry it away.
  // A URL that does not parse is refused too, so the guard fails closed.
  win.webContents.on('will-navigate', (event, url) => {
    try {
      const here = new URL(win.webContents.getURL())
      const next = new URL(url)
      if (next.protocol !== here.protocol || next.host !== here.host || next.pathname !== here.pathname) event.preventDefault()
    } catch {
      event.preventDefault()
    }
  })
  const devUrl = process.env.VITE_DEV_SERVER_URL
  if (devUrl) await win.loadURL(devUrl)
  else await win.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
}

app.whenReady().then(async () => {
  startHost()
  try { await waitForHost() } catch (e) { say(process.stderr, `${e.message}\n`) }
  await createWindow()
})
app.on('window-all-closed', () => { stopHost(); app.quit() })
app.on('before-quit', stopHost)
