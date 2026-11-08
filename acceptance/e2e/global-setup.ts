import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { HOST_PORT, ORIGINS, OUT, PREVIEW_PORT, ROOT, TOKEN, stateFile } from './support';

function waitPort(port: number, ms: number, host = '127.0.0.1'): Promise<boolean> {
  const end = Date.now() + ms;
  return new Promise(resolve => {
    const tryOnce = () => {
      const s = net.connect(port, host);
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => { s.destroy(); if (Date.now() > end) resolve(false); else setTimeout(tryOnce, 250); });
    };
    tryOnce();
  });
}

/** True when something already answers on the port. A port like that belongs to another tree, so a spec there would judge that tree's screens. */
function answers(port: number, host: string): Promise<boolean> {
  return new Promise(resolve => {
    const s = net.connect(port, host);
    const done = (open: boolean) => { s.destroy(); resolve(open); };
    s.setTimeout(1_000, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

/** Waits for the child's own words: vite prints the address it bound, and the Host prints HOST-READY. A port that answers proves nothing, since another tree can hold it. */
async function childSaid(log: string, words: string, exited: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (exited()) return false;
    const text = (fs.existsSync(log) ? fs.readFileSync(log, 'utf8') : '').replace(/\x1b\[[0-9;]*m/g, '');   // vite colours the port number
    if (text.includes(words)) return true;
    await new Promise(r => setTimeout(r, 250));
  }
  return false;
}

/**
 * Starts the Host and `vite preview` from the product tree, the way program-design.md section 9 says lesson walks run:
 * vite preview on 4180, a live Host, one worker. If the product is not there yet it records why and the specs report NOT RUN.
 * Nothing is mocked: a spec that finds no live Host does not pass.
 */
export default async function globalSetup(): Promise<void> {
  fs.mkdirSync(OUT, { recursive: true });
  // startedAt (Unix ms, before anything starts) lets the teardown tell this run's processes from a later run's on a reused port or pid.
  const state = { hostUp: false, previewUp: false, note: '', reason: 'PRODUCT_MISSING', pids: [] as number[], startedAt: Date.now() };
  const hostDll = process.env.ACC_HOST ?? '';
  const appDir = path.join(ROOT, 'app');
  if (!hostDll || !fs.existsSync(hostDll)) { state.note = `NetSec.Host is not built (ACC_HOST=${hostDll})`; fs.writeFileSync(stateFile(), JSON.stringify(state)); return; }
  if (!fs.existsSync(path.join(appDir, 'dist', 'index.html'))) { state.note = `app/dist is not built in ${appDir}`; fs.writeFileSync(stateFile(), JSON.stringify(state)); return; }

  // A busy port stops the group by name, before anything starts. Without this check a run reads another tree's renderer and reports it as its own.
  for (const [port, host, what] of [[HOST_PORT, '127.0.0.1', 'Host'], [PREVIEW_PORT, 'localhost', 'preview']] as [number, string, string][]) {
    if (await answers(port, host)) {
      state.reason = 'PORT_BUSY';
      state.note = `the ${what} port ${port} already answers, and this run did not start it. A spec there would judge another tree`;
      fs.writeFileSync(stateFile(), JSON.stringify(state));
      return;
    }
  }

  const localAppData = path.join(OUT, 'localappdata');
  fs.mkdirSync(localAppData, { recursive: true });
  // A fresh folder each run. Without it the Host uses the repository's .security/, so a run that stops with Show keys OFF starts the next run OFF.
  const securityDir = path.join(OUT, 'security');
  fs.rmSync(securityDir, { recursive: true, force: true });
  fs.mkdirSync(securityDir, { recursive: true });
  // Design section 11 gives --port and --token. Design section 5 gives NETSEC_PORT and NETSEC_TOKEN. The suite passes both. A .dll path runs under dotnet.
  const hostArgs = ['--port', String(HOST_PORT), '--token', TOKEN];
  const hostLogPath = path.join(OUT, 'host.log');
  fs.rmSync(hostLogPath, { force: true });
  const hostLog = fs.openSync(hostLogPath, 'a');
  // NETSEC_ORIGINS (design D14 amendment) makes the Host trust this run's preview port. It is always written, empty when unset, so a value
  // in the shell that runs the suite cannot leak in.
  const hostEnv = { ...process.env, NETSEC_PORT: String(HOST_PORT), NETSEC_TOKEN: TOKEN, LOCALAPPDATA: localAppData, NETSEC_SECURITY_DIR: securityDir, NETSEC_ORIGINS: ORIGINS };
  const host = hostDll.toLowerCase().endsWith('.dll')
    ? spawn('dotnet', [hostDll, ...hostArgs], { cwd: path.dirname(hostDll), detached: false, stdio: ['ignore', hostLog, hostLog], env: hostEnv })
    : spawn(hostDll, hostArgs, { cwd: path.dirname(hostDll), detached: false, stdio: ['ignore', hostLog, hostLog], env: hostEnv });
  let hostGone = false;
  host.on('exit', () => { hostGone = true; });
  host.on('error', () => { /* a start failure shows as hostUp false */ });
  if (host.pid) state.pids.push(host.pid);
  state.hostUp = await childSaid(hostLogPath, `HOST-READY port=${HOST_PORT}`, () => hostGone, 60_000);
  if (!state.hostUp && hostGone) { state.reason = 'PORT_BUSY'; state.note = `this run's Host exited before it bound port ${HOST_PORT}. See host.log`; }

  const previewLogPath = path.join(OUT, 'preview.log');
  fs.rmSync(previewLogPath, { force: true });
  let previewGone = false;
  const previewLog = fs.openSync(previewLogPath, 'a');   // vite's own words, kept so a dead preview can be explained
  // vite runs under node directly, so the pid kept for the teardown is the process that listens. Under npx and a shell, the teardown's
  // taskkill /T ended the shell and, on 2026-11-07, left the vite process listening on the preview port.
  const viteBin = path.join(appDir, 'node_modules', 'vite', 'bin', 'vite.js');
  const viteArgs = ['preview', '--port', String(PREVIEW_PORT), '--strictPort', '--host', 'localhost'];
  const preview = fs.existsSync(viteBin)
    ? spawn(process.execPath, [viteBin, ...viteArgs], { cwd: appDir, detached: false, stdio: ['ignore', previewLog, previewLog] })
    : spawn('npx', ['vite', ...viteArgs], { cwd: appDir, shell: true, detached: false, stdio: ['ignore', previewLog, previewLog] });
  preview.on('exit', (code, sig) => { previewGone = true; try { fs.appendFileSync(path.join(OUT, 'preview.log'), `\n[preview exited code=${code} signal=${sig} at ${new Date().toISOString()}]\n`); } catch { /* ignore */ } });
  preview.on('error', () => { /* a start failure shows as previewUp false */ });
  if (preview.pid) state.pids.push(preview.pid);
  state.previewUp = await childSaid(previewLogPath, `localhost:${PREVIEW_PORT}`, () => previewGone, 60_000) && await waitPort(PREVIEW_PORT, 60_000, 'localhost');   // vite preview listens on localhost, which can be ::1 only
  if (!state.previewUp && previewGone) { state.reason = 'PORT_BUSY'; state.note = `this run's preview exited before it bound port ${PREVIEW_PORT}. See preview.log`; }
  if (!state.note) state.note = state.hostUp && state.previewUp ? 'live' : `host up: ${state.hostUp}, preview up: ${state.previewUp}`;
  fs.writeFileSync(stateFile(), JSON.stringify(state));
}
