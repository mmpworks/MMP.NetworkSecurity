import * as fs from 'node:fs';
import * as path from 'node:path';

export const HOST_PORT = Number(process.env.ACC_HOST_PORT ?? 5180);
export const PREVIEW_PORT = 4180;
export const TOKEN = process.env.ACC_TOKEN ?? 'acceptance-token';
export const ROOT = process.env.ACC_ROOT ?? '';
export const OUT = process.env.ACC_OUT ?? path.join(__dirname, 'test-results');

/** Marker the pwsh runner turns into NOT RUN. A spec calls this when the product is not there yet. */
export class NotRun extends Error {
  constructor(public reason: string, detail: string) { super(`NOTRUN ${reason}: ${detail}`); }
}

export function stateFile(): string { return path.join(OUT, 'state.json'); }

export function readState(): { hostUp: boolean; previewUp: boolean; note: string } {
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
  if (!s.hostUp || !s.previewUp) throw new NotRun('PRODUCT_MISSING', s.note);
}

/** Tour steps of a lesson, from the tour file. Array of steps, or { steps: [] }. */
export function tourSteps(lesson: number): any[] {
  const f = path.join(ROOT, 'app', 'src', 'tours', `lesson-${String(lesson).padStart(2, '0')}.json`);
  if (!fs.existsSync(f)) return [];
  const j = JSON.parse(fs.readFileSync(f, 'utf8'));
  return Array.isArray(j) ? j : j.steps ?? [];
}
