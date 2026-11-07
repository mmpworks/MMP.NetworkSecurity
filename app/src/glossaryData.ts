// The glossary as typed data, from src/glossary.json. Pure: no Vue, so a spec can test the search and the source labels.

export type MethodStatus = 'current' | 'legacy' | 'broken'

export interface Source { title: string; url: string; draft?: boolean }

export interface Term { id: string; term: string; short: string }

export interface Method extends Term {
  kind: string
  does: string[]
  keySizes?: string
  strength?: string
  strengthNote?: string
  status: MethodStatus
  statusBasis: 'final' | 'draft'
  statusNote?: string
  reasoning?: string
  unsourced?: string
  sources: string[]
  lessons: number[]
  namedIn?: number[]
}

/** One claim in the comparison: it cites sources, or it carries basis "reasoning" and cites none. */
export interface Claim { text: string; sources?: string[]; basis?: 'reasoning' }

export interface Side { meaning: string; strengths: Claim[]; weaknesses: Claim[]; notAllEncrypt?: string }

export interface Comparison {
  title: string
  symmetric: Side
  asymmetric: Side
  myth: { claim: string; truth: string; sources: string[] }
  tlsUsesBoth: { steps: string[]; why: string; sources: string[]; lessons: number[] }
}

export interface Glossary { terms: (Term | Method)[]; comparison: Comparison; sources: Record<string, Source>; sourcesRead: string }

export const isMethod = (t: Term | Method): t is Method => 'kind' in t && 'status' in t

/** A short link label from a source title: the text before its first comma, such as "NIST SP 800-57 Part 1 Rev. 5". */
export const sourceLabel = (s: Source): string => s.title.split(',')[0].trim()

/** True when the query is empty, or appears in the term, its short text, or a method's kind or uses. Case does not matter. */
export function matches(t: Term | Method, query: string): boolean {
  const q = query.trim().toLowerCase()
  if (!q) return true
  const words = [t.term, t.short, ...(isMethod(t) ? [t.kind, ...t.does] : [])]
  return words.some(w => w.toLowerCase().includes(q))
}

