import specsFile from './specs.json'
import glossaryFile from './glossary.json'

// Spec cards (docs/walkthrough-design.md section 2.2h). Pure: no Vue, so a test can call every function here.
// A row names a spec as it appears on screen. Its title and URL come from the glossary source it names, so each URL is written once,
// and the Electron link list (electron/link-hosts.cjs) already holds every host a card can link to.

export interface SpecRow { id: string; name: string; aliases: string[]; source: string; synopsis: string }
export interface Source { title: string; url: string }
export interface Spec { id: string; name: string; synopsis: string; title: string; url: string }
export type SpecSegment = { kind: 'text'; text: string } | { kind: 'spec'; id: string; text: string }

/** Joins each row to its source. A row whose source is missing is a data fault, so it throws and names the row. */
export function buildSpecs(rows: readonly SpecRow[], sources: Readonly<Record<string, Source>>): Map<string, Spec> {
  const out = new Map<string, Spec>()
  for (const r of rows) {
    const s = sources[r.source]
    if (!s) throw new Error(`specs.json row ${r.id} names source ${r.source}, which glossary.json does not hold`)
    out.set(r.id, { id: r.id, name: r.name, synopsis: r.synopsis, title: s.title, url: s.url })
  }
  return out
}

const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')

/**
 * Returns a splitter that cuts text into plain parts and spec names. Names and aliases are tried longest first, so X9.24-3-2017 wins over X9.24-3.
 * A name matches only as a whole: no letter or digit may touch either end, so RFC 8446 does not match inside RFC 84460.
 */
export function specSplitter(rows: readonly SpecRow[]): (text: string) => SpecSegment[] {
  const idOf = new Map<string, string>()
  for (const r of rows) for (const n of [r.name, ...r.aliases]) idOf.set(n, r.id)
  const names = [...idOf.keys()].sort((a, b) => b.length - a.length).map(escape)
  if (names.length === 0) return text => (text ? [{ kind: 'text', text }] : [])
  const re = new RegExp(`(?<![A-Za-z0-9])(?<name>${names.join('|')})(?![A-Za-z0-9])`, 'g')
  return text => {
    const out: SpecSegment[] = []
    let last = 0
    for (const m of text.matchAll(re)) {
      const at = m.index ?? 0
      if (at > last) out.push({ kind: 'text', text: text.slice(last, at) })
      out.push({ kind: 'spec', id: idOf.get(m.groups!.name)!, text: m.groups!.name })
      last = at + m[0].length
    }
    if (last < text.length) out.push({ kind: 'text', text: text.slice(last) })
    return out
  }
}

const rows = (specsFile as { specs: SpecRow[] }).specs
export const SPECS = buildSpecs(rows, (glossaryFile as { sources: Record<string, Source> }).sources)
export const specParts = specSplitter(rows)
