// Shapes the renderer reads from the Host (program-design.md section 2.1 and 5, ux-design.md section 0).

export type FieldKind = 'header' | 'length' | 'random' | 'key' | 'cipher' | 'mac' | 'id' | 'data'

export interface TraceField {
  name: string
  offset: number
  length: number
  kind: FieldKind
  visibleToWire: boolean
  gloss: string
}

// With Show keys OFF the Host sends no hex. A secret then carries fingerprint ("fp:" and 8 bytes as hex), length in bytes, and hidden ("toggle" or "non-exportable").
export interface TraceSecret { holder: string; name: string; hex: string; derivedFrom: string[]; fingerprint: string; length: number; hidden: string }

export interface TraceCheck { id: string; name: string; result: 'pass' | 'fail'; code: string; detail: string }

export interface TraceEvent {
  seq: number
  eventId: string
  streamId: string
  /** The event's place in its stream. With streamId it pairs an attack run's events with its parent's (sections-plan item 3, P3b). */
  streamSeq: number
  sessionId: string
  traceId: string
  hop: string
  actor: string
  from: string
  to: string
  type: string
  message: string
  step: string
  /** Lowercase hex, no separators. Empty when the event moves no bytes. */
  wire: string
  plain: string
  fields: TraceField[]
  secrets: TraceSecret[]
  check: TraceCheck | null
  waiting: string
  /** On key.in-use events: the type id, its key version (0 for a built-in key), and the provider (builtin, file or vault). */
  typeId: string
  version: number
  provider: string
  /** `name=value;name=value` on measure.result events. */
  detail: string
}

export interface LessonRow {
  lesson: number
  title: string
  built: boolean
  lanes: string[]
  attacks: AttackRow[]
}

export interface AttackRow { attackId: string; label: string; expectCheck?: string; expectCode?: string }

export type Transport = 'glass' | 'os'
export type ViewMode = 'endpoints' | 'eavesdropper' | 'both'
export type AppMode = 'tour' | 'free'

export interface HostError { code: string; message: string; retryable: boolean; requestId: string }

// Tour file schema, ux-design.md section 3.1.
export interface TourBind { kind: 'event' | 'concept'; eventType?: string; match?: { actor?: string; message?: string; step?: string } }

export interface TourAction { type: 'set-view' | 'flip-byte' | 'run-attack' | 'toggle-field' | 'press-run' | 'select-event'; value?: string; attackId?: string }

export interface TourExpect { type: 'view' | 'check' | 'selected' | 'ran' | 'attack-outcome'; value?: string; name?: string; result?: 'pass' | 'fail'; outcome?: string }

export interface TourStep {
  id: string
  lesson: number
  order?: number
  title: string
  text: string[]
  glossary?: string[]
  bind: TourBind
  highlight?: string[]
  tryIt?: { id: string; label: string; action: TourAction; expect: TourExpect }
  unlock?: { mode: 'event' | 'ack' | 'action' | 'check'; ref?: string; name?: string; result?: 'pass' | 'fail' }
  pause?: 'after-bound-event' | 'none'
  claims?: { id: string; text: string; source: string }[]
}

export interface GlossaryTerm { id: string; term: string; short: string; long?: string }
