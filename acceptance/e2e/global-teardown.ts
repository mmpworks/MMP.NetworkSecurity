import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as path from 'node:path';
import { HOST_PORT, OUT, PREVIEW_PORT, ROOT, stateFile } from './support';

function answers(port: number, host: string): Promise<boolean> {
  return new Promise(resolve => {
    const s = net.connect(port, host);
    const done = (open: boolean) => { s.destroy(); resolve(open); };
    s.setTimeout(1_000, () => done(false));
    s.once('connect', () => done(true));
    s.once('error', () => done(false));
  });
}

type Listener = { pid: number; cmd: string; ancestors: number[]; createdMs: number };

/** Each process that listens on a port, with its command line, its parent chain and its start time (Unix ms), from Windows. Empty when none does. */
function listeners(port: number): Listener[] {
  const script = `Get-NetTCPConnection -LocalPort ${port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object {
    $p = Get-CimInstance Win32_Process -Filter "ProcessId=$_"; $chain = @(); $q = $p
    for ($i = 0; $q -and $i -lt 8; $i++) { $chain += $q.ParentProcessId; $q = Get-CimInstance Win32_Process -Filter "ProcessId=$($q.ParentProcessId)" }
    $created = if ($p.CreationDate) { ([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds() } else { 0 }
    [pscustomobject]@{ pid = [int]$_; cmd = [string]$p.CommandLine; ancestors = $chain; createdMs = $created } } | ConvertTo-Json -Compress -Depth 3`;
  const r = spawnSync('powershell', ['-NoProfile', '-Command', script], { encoding: 'utf8' });
  try {
    const j = JSON.parse((r.stdout ?? '').trim() || '[]');
    return (Array.isArray(j) ? j : [j]).map((l: Listener) => ({ pid: l.pid, cmd: l.cmd ?? '', ancestors: [].concat((l.ancestors ?? []) as never), createdMs: Number(l.createdMs) || 0 }));
  }
  catch { return []; }
}

/** Slack for the two clocks' rounding: a process the setup started cannot have started before the setup did. */
const CLOCK_SLACK_MS = 1_000;

/**
 * True only for a process this run started. It must have started after this run's setup began, so a pid or port that a later run reused
 * never matches. Then it must be one of the pids the setup kept, a child of one, or a command line that names this run's own program and
 * port (the Host's dll with --port, or this tree's vite with --port). Anything else may be another agent's server.
 */
function startedByThisRun(l: Listener, pids: number[], port: number, setupMs: number | undefined): boolean {
  if (!setupMs || l.createdMs < setupMs - CLOCK_SLACK_MS) return false;
  if (pids.includes(l.pid) || l.ancestors.some(a => pids.includes(a))) return true;
  const cmd = l.cmd.toLowerCase().replace(/\\/g, '/');
  const ownProgram = [process.env.ACC_HOST ?? '', ROOT ? path.join(ROOT, 'app', 'node_modules', 'vite') : '']
    .filter(p => p.length > 0).map(p => p.toLowerCase().replace(/\\/g, '/'));
  return cmd.includes(`--port ${port}`) && ownProgram.some(p => cmd.includes(p));
}

/**
 * Ends the Host and the preview server with their children (taskkill /T), as the product's own Electron main does. Then it checks that both
 * ports are closed. A listener left on a port is ended only when this run started it (see startedByThisRun). Any other listener is logged
 * by pid and command line and left running. Each case writes a line to teardown.log in the run folder and to the console.
 * On 2026-11-07 a preview outlived its teardown and blocked another agent.
 */
export default async function globalTeardown(): Promise<void> {
  let s: { pids?: number[]; hostUp?: boolean; previewUp?: boolean; startedAt?: number };
  try { s = JSON.parse(fs.readFileSync(stateFile(), 'utf8')); } catch { return; /* nothing was started */ }
  for (const pid of s.pids ?? []) spawnSync('taskkill', ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore' });
  const mine: [number, string, boolean | undefined][] = [[HOST_PORT, '127.0.0.1', s.hostUp], [PREVIEW_PORT, 'localhost', s.previewUp]];
  for (const [port, host, started] of mine) {
    if (!started) continue;
    for (let i = 0; i < 10 && await answers(port, host); i++) await new Promise(r => setTimeout(r, 300));
    if (!(await answers(port, host))) continue;
    for (const l of listeners(port)) {
      const ours = startedByThisRun(l, s.pids ?? [], port, s.startedAt);
      if (ours) spawnSync('taskkill', ['/T', '/F', '/PID', String(l.pid)], { stdio: 'ignore' });
      const what = ours ? 'TEARDOWN_ENDED_OWN_LISTENER' : 'TEARDOWN_FOREIGN_LISTENER_LEFT_RUNNING';
      const started = l.createdMs ? new Date(l.createdMs).toISOString() : 'unknown';
      const setup = s.startedAt ? new Date(s.startedAt).toISOString() : 'unknown';
      const line = `${what} port=${port} pid=${l.pid} started=${started} setup=${setup} cmd=${JSON.stringify(l.cmd)} at ${new Date().toISOString()}\n`;
      try { fs.appendFileSync(path.join(OUT, 'teardown.log'), line); } catch { /* the line also goes to the console */ }
      console.error(line.trim());
    }
  }
}
