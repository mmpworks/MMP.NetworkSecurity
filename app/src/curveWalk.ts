// The shapes of the elliptic-curve walk replies (slice P8a; docs/sections-plan.md R7 and section 4) and the small helpers the curve cards share.
// Every number comes from the engine (R5). The helpers here only format a number or place it on the picture; they compute no curve value.

/** A point as the engine sends it. The point at infinity, O, is `{ infinity: true }`. */
export type EnginePoint = { x: number; y: number } | { infinity: true }
export const isO = (p: EnginePoint | null | undefined): p is { infinity: true } => !!p && 'infinity' in p

/** The extended Euclid rows the engine used to find an inverse. */
export interface Inverse { of: number; modulus: number; value: number; rows: { a: number; b: number; quotient: number; remainder: number; t: number }[] }

/** One point add or double on the toy curve: kind is add, double or identity (a step with O in it, which needs no slope). */
export interface ToyStep {
  kind: 'add' | 'double' | 'identity'; p: EnginePoint; q: EnginePoint; result: EnginePoint
  numerator: number | null; denominator: number | null; inverse: Inverse | null; lambda: number | null
}

export interface Signature { z: number; nonce: number; bigR: EnginePoint; r: number; s: number; nonceInverse: Inverse }

export interface ToyCurve {
  curve: { p: number; a: number; b: number; order: number; g: { x: number; y: number } }
  points: { x: number; y: number }[]
  hops: { k: number; point: EnginePoint; step: ToyStep | null }[]
  k: number
  doubleAndAdd: { bit: number; isOne: boolean; doubleStep: ToyStep; addStep: ToyStep | null; after: EnginePoint }[]
  ladder: { bit: number; isOne: boolean; addStep: ToyStep; doubleStep: ToyStep; r0: EnginePoint; r1: EnginePoint }[]
  ecdh: { alicePrivate: number; bobPrivate: number; alicePublic: EnginePoint; bobPublic: EnginePoint; aliceShared: EnginePoint; bobShared: EnginePoint }
  ecdsa: {
    signerPrivate: number; signerPublic: EnginePoint; first: Signature; second: Signature
    recovery: { sDifferenceInverse: Inverse; rInverse: Inverse; nonce: number; privateKey: number }
  }
}

export interface ToyPick { pIndex: number; qIndex: number; resultIndex: number; step: ToyStep }

export interface RealPoint { x: number; y: number }
export interface RealSample { kind: 'chord' | 'tangent'; p: RealPoint; q: RealPoint; rPrime: RealPoint; r: RealPoint; lambda: number }
export interface RealCurve { root: number; xMax: number; upper: RealPoint[]; lower: RealPoint[]; chord: RealSample; tangent: RealSample; samples: RealSample[] }

/** "(5, 1)", or "O" for the point at infinity. */
export const ptText = (p: EnginePoint | null | undefined) => (!p ? '' : isO(p) ? 'O' : `(${p.x}, ${p.y})`)

/** The data attributes a spec reads off a shown point: data-point="O", or data-x and data-y with the engine's own numbers. */
export const ptAttrs = (p: EnginePoint | null | undefined) =>
  !p ? {} : isO(p) ? { 'data-point': 'O' } : { 'data-x': String(p.x), 'data-y': String(p.y) }

/** A real-curve decimal for reading, at 3 places. The data attributes keep the engine's full number. */
export const dec3 = (n: number) => (Math.round(n * 1000) / 1000).toString()
