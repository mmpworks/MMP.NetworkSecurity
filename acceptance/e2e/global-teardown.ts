import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { HOST_PORT, OUT, PREVIEW_PORT, stateFile } from './support';

function answers(port: number, host: string): Promise<boolean> {
  return new Promise(resolve => {
    const s = net.connect(port, host);
    const done = (open: boolean) => { s.destroy(); resolve(open); };
    s.setTimeout(1_000, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

/** The pids that listen on a port, from Windows. Empty when none does. */
function listeners(port: number): number[] {
  const r = spawnSync('powershell', ['-NoProfile', '-Command', `Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.OwningProcess }`], { encoding: 'utf8' });
  return (r.stdout ?? '').split(/\s+/).map(Number).filter(n => Number.isInteger(n) && n > 0);
}

/**
 * Ends the Host and the preview server with their children (taskkill /T), as the product's own Electron main does. Then it checks that both
 * ports are closed. The global setup refused to start when either port already answered, so a listener left on a port this run opened is this
 * run's own: it is ended too, and teardown.log in the run folder names it. On 2026-11-07 a preview outlived its teardown and blocked another agent.
 */
export default async function globalTeardown(): Promise<void> {
  let s: { pids?: number[]; hostUp?: boolean; previewUp?: boolean };
  try { s = JSON.parse(fs.readFileSync(stateFile(), 'utf8')); } catch { return; /* nothing was started */ }
  for (const pid of s.pids ?? []) spawnSync('taskkill', ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore' });
  const mine: [number, string, boolean | undefined][] = [[HOST_PORT, '127.0.0.1', s.hostUp], [PREVIEW_PORT, 'localhost', s.previewUp]];
  for (const [port, host, started] of mine) {
    if (!started) continue;
    for (let i = 0; i < 10 && await answers(port, host); i++) await new Promise(r => setTimeout(r, 300));
    if (!(await answers(port, host))) continue;
    const left = listeners(port);
    for (const pid of left) spawnSync('taskkill', ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore' });
    const line = `TEARDOWN_LEFT_LISTENER port=${port} pids=[${left.join(', ')}] ended at ${new Date().toISOString()}; closed now: ${!(await answers(port, host))}\n`;
    try { fs.appendFileSync(path.join(OUT, 'teardown.log'), line); } catch { /* the line also goes to the console */ }
    console.error(line.trim());
  }
}
