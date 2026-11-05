import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { HOST_PORT, OUT, PREVIEW_PORT, ROOT, TOKEN, stateFile } from './support';

function waitPort(port: number, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  return new Promise(resolve => {
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(true); });
      s.once('error', () => { s.destroy(); if (Date.now() > end) resolve(false); else setTimeout(tryOnce, 250); });
    };
    tryOnce();
  });
}

/**
 * Starts the Host and `vite preview` from the product tree, the way program-design.md section 9 says lesson walks run:
 * vite preview on 4180, a live Host, one worker. If the product is not there yet it records why and the specs report NOT RUN.
 * Nothing is mocked: a spec that finds no live Host does not pass.
 */
export default async function globalSetup(): Promise<void> {
  fs.mkdirSync(OUT, { recursive: true });
  const state = { hostUp: false, previewUp: false, note: '', pids: [] as number[] };
  const hostDll = process.env.ACC_HOST ?? '';
  const appDir = path.join(ROOT, 'app');
  if (!hostDll || !fs.existsSync(hostDll)) { state.note = `NetSec.Host is not built (ACC_HOST=${hostDll})`; fs.writeFileSync(stateFile(), JSON.stringify(state)); return; }
  if (!fs.existsSync(path.join(appDir, 'dist', 'index.html'))) { state.note = `app/dist is not built in ${appDir}`; fs.writeFileSync(stateFile(), JSON.stringify(state)); return; }

  const localAppData = path.join(OUT, 'localappdata');
  fs.mkdirSync(localAppData, { recursive: true });
  // Design section 11, "Processes" item 3: NetSec.Host.exe --port P --token T. A .dll path runs under dotnet.
  const hostArgs = ['--port', String(HOST_PORT), '--token', TOKEN];
  const host = hostDll.toLowerCase().endsWith('.dll')
    ? spawn('dotnet', [hostDll, ...hostArgs], { cwd: path.dirname(hostDll), detached: false, stdio: 'ignore', env: { ...process.env, LOCALAPPDATA: localAppData } })
    : spawn(hostDll, hostArgs, { cwd: path.dirname(hostDll), detached: false, stdio: 'ignore', env: { ...process.env, LOCALAPPDATA: localAppData } });
  host.on('error', () => { /* a start failure shows as hostUp false */ });
  if (host.pid) state.pids.push(host.pid);
  state.hostUp = await waitPort(HOST_PORT, 60_000);

  const preview = spawn('npx', ['vite', 'preview', '--port', String(PREVIEW_PORT), '--strictPort', '--host', 'localhost'], { cwd: appDir, shell: true, detached: false, stdio: 'ignore' });
  preview.on('error', () => { /* a start failure shows as previewUp false */ });
  if (preview.pid) state.pids.push(preview.pid);
  state.previewUp = await waitPort(PREVIEW_PORT, 60_000);
  state.note = state.hostUp && state.previewUp ? 'live' : `host up: ${state.hostUp}, preview up: ${state.previewUp}`;
  fs.writeFileSync(stateFile(), JSON.stringify(state));
}
