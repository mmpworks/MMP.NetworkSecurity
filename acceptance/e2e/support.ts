import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * A process's start time (Unix ms) from Windows, or 0 when no process has that pid. A pid and its start time name one process: Windows can
 * give a pid to a new process once the old one ends, but the new process has a later start time. The setup records it, and the teardown compares.
 */
export function createdMsOf(pid: number): number {
  const r = spawnSync('powershell', ['-NoProfile', '-Command', `$p = Get-CimInstance Win32_Process -Filter "ProcessId=${pid}"; if ($p -and $p.CreationDate) { ([DateTimeOffset]$p.CreationDate).ToUnixTimeMilliseconds() } else { 0 }`], { encoding: 'utf8' });
  return Number((r.stdout ?? '').trim()) || 0;
}

export const HOST_PORT = Number(process.env.ACC_HOST_PORT ?? 5180);
export const PREVIEW_PORT = Number(process.env.ACC_PREVIEW_PORT ?? 4180);   // run.ps1 picks a free port in the acceptance block, 36800 up (4180 or 5173 on a tree from before #225)
/** NETSEC_ORIGINS for this run's Host: the preview's origin when it is not a built-in one. Empty means unset, as Electron writes it. */
export const ORIGINS = process.env.ACC_ORIGINS ?? '';
export const TOKEN = process.env.ACC_TOKEN ?? 'acceptance-token';
export const ROOT = process.env.ACC_ROOT ?? '';
export const OUT = process.env.ACC_OUT ?? path.join(__dirname, 'test-results');

/** Marker the pwsh runner turns into NOT RUN. A spec calls this when the product is not there yet. */
export class NotRun extends Error {
  constructor(public reason: string, detail: string) { super(`NOTRUN ${reason}: ${detail}`); }
}

/** The committed not-yet-built list: "unbuilt" in acceptance/settings.json. Each entry names one control key. Empty by default (#372). */
export function unbuiltControls(): string[] {
  const f = path.join(__dirname, '..', 'settings.json');
  const list = JSON.parse(fs.readFileSync(f, 'utf8')).unbuilt ?? [];
  if (!Array.isArray(list) || list.some(x => typeof x !== 'string')) throw new Error(`UNBUILT_SETTING_BAD: "unbuilt" in ${f} must be a list of control keys`);
  return list;
}

/**
 * The error for a missing control on a screen. NOT RUN UI_CONTROL_MISSING only when the committed list names the control key;
 * every other missing control is a FAIL with the same detail, because a shipped screen that loses a control is a defect (#372).
 */
export function controlMissing(control: string, detail: string): Error {
  if (unbuiltControls().includes(control)) return new NotRun('UI_CONTROL_MISSING', `${detail} [${control} is on the unbuilt list]`);
  return new Error(`UI_CONTROL_MISSING_ON_SHIPPED_SCREEN: ${detail} [${control} is not on the unbuilt list in acceptance/settings.json]`);
}

export function stateFile(): string { return path.join(OUT, 'state.json'); }

export function readState(): { hostUp: boolean; previewUp: boolean; note: string; reason?: string } {
  try { return JSON.parse(fs.readFileSync(stateFile(), 'utf8')); } catch { return { hostUp: false, previewUp: false, note: 'no state file: global setup did not run' }; }
}

/** The renderer gets the Host address and token the way the Electron preload hands them over (ASSUMED shape, see CONTRACT.md). */
export async function openApp(page: import('@playwright/test').Page): Promise<void> {
  await page.addInitScript(({ port, token }) => {
    (window as any).netsec = { host: { port, token } };
  }, { port: HOST_PORT, token: TOKEN });
  await page.goto(`/?port=${HOST_PORT}&token=${TOKEN}`);
}

export async function hostGet(pathname: string): Promise<{ status: number; body: any }> {
  const r = await fetch(`http://127.0.0.1:${HOST_PORT}${pathname}`, { headers: { Authorization: `Bearer ${TOKEN}`, Origin: `http://localhost:${PREVIEW_PORT}` } });
  let body: any = null;
  try { body = await r.json(); } catch { body = null; }
  return { status: r.status, body };
}

export function requireLive(): void {
  const s = readState();
  if (!s.hostUp || !s.previewUp) throw new NotRun(s.reason ?? 'PRODUCT_MISSING', s.note);
}

/** Tour steps of a lesson, from the tour file. Array of steps, or { steps: [] }. */
export function tourSteps(lesson: number): any[] {
  const f = path.join(ROOT, 'app', 'src', 'tours', `lesson-${String(lesson).padStart(2, '0')}.json`);
  if (!fs.existsSync(f)) return [];
  const j = JSON.parse(fs.readFileSync(f, 'utf8'));
  return Array.isArray(j) ? j : j.steps ?? [];
}
