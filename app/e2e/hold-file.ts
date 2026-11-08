import { spawn } from 'node:child_process'

// Holds a file open the way an antivirus scan can: read access, read and write sharing, and no delete sharing. On Windows a replacing
// move over the file then fails (issue #292). Node always opens with delete sharing, so a PowerShell child holds the handle instead.
const SCRIPT = [
  "$f = [System.IO.File]::Open($env:NETSEC_HOLD_FILE, 'Open', 'Read', 'ReadWrite')",
  "[Console]::Out.WriteLine('held')",
  '[Console]::Out.Flush()',
  '[void][Console]::In.ReadLine()',
  '$f.Dispose()',
].join('; ')

export interface FileHold { release(): Promise<void> }

export function holdWithoutDeleteSharing(file: string, timeoutMs = 15_000): Promise<FileHold> {
  const child = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', SCRIPT], { env: { ...process.env, NETSEC_HOLD_FILE: file } })
  const release = () => new Promise<void>(resolve => {
    if (child.exitCode !== null) { resolve(); return }
    child.once('exit', () => resolve())
    child.stdin.end('\n')
  })
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill(); reject(new Error(`the hold on ${file} did not start in ${timeoutMs} ms`)) }, timeoutMs)
    let err = ''
    child.stderr.on('data', d => { err += String(d) })
    child.stdout.on('data', d => { if (String(d).includes('held')) { clearTimeout(timer); resolve({ release }) } })
    child.once('exit', code => { clearTimeout(timer); reject(new Error(`the hold on ${file} ended with code ${code}: ${err.trim()}`)) })
  })
}
