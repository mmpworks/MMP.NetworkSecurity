// The app's 3 sections (docs/sections-plan.md, section 2). Pure data, so a spec can read the order and the slices.
// Lessons holds today's 12 lessons. Handshake and Techniques list their walks, and a walk's slice says when its screen arrives.

export type SectionId = 'handshake' | 'techniques' | 'lessons'

/** `slice` is the plan's name for the work that brings the screen (specs read it). `status` is the line the learner sees. */
export interface WalkItem { id: string; label: string; slice: string; status?: string }

export interface Section { id: SectionId; label: string; items: readonly WalkItem[] }

export const SECTIONS: readonly Section[] = [
  {
    id: 'handshake', label: 'Handshake', items: [
      { id: 'wire', label: 'The wire and the eavesdropper', slice: 'P4' },
      { id: 'tls13', label: 'TLS 1.3 messages and key schedule', slice: 'P4' },
      { id: 'chain', label: 'The certificate chain', slice: 'P4' },
    ],
  },
  {
    // X25519 is the only elliptic-curve key agreement. Both signature families stay (Steve, Q2).
    id: 'techniques', label: 'Techniques', items: [
      { id: 'aes', label: 'AES', slice: 'P2', status: 'Open it from lesson 1' },
      { id: 'hmac', label: 'HMAC and chain', slice: 'P6' },
      { id: 'feistel', label: 'Feistel', slice: 'P9' },
      { id: 'dh', label: 'Diffie-Hellman', slice: 'P7' },
      { id: 'x25519', label: 'X25519', slice: 'P8' },
      { id: 'ed25519', label: 'Ed25519', slice: 'P8' },
      { id: 'ecdsa', label: 'ECDSA P-256', slice: 'P8b' },
    ],
  },
  { id: 'lessons', label: 'Lessons', items: [] },
]

export const sectionOf = (id: SectionId): Section => SECTIONS.find(s => s.id === id)!

/** The line a learner sees under a walk: its own status, or a plain note that it comes later. */
export const walkStatus = (w: WalkItem): string => w.status ?? 'Coming in a later update'
