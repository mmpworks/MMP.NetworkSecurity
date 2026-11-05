import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { stateFile } from './support';

/** Ends the Host and the preview server with their children (taskkill /T), as the product's own Electron main does. */
export default async function globalTeardown(): Promise<void> {
  try {
    const s = JSON.parse(fs.readFileSync(stateFile(), 'utf8'));
    for (const pid of s.pids ?? []) spawnSync('taskkill', ['/T', '/F', '/PID', String(pid)], { stdio: 'ignore' });
  } catch { /* nothing was started */ }
}
