/**
 * Elliptic curves in short Weierstrass form, y^2 = x^3 + ax + b (mod p), with step traces.
 *
 * 1. For the walk lessons: point add, point double, and k·P by double-and-add,
 *    each with the numbers a learner needs (the slope, the formula inputs).
 * 2. The toy curve is the textbook one: y^2 = x^3 + 2x + 2 mod 17, G = (5, 1), 19 points
 *    (Paar and Pelzl, Understanding Cryptography, chapter 9). 19 is prime, so every point
 *    other than O makes the whole group and no small subgroup exists.
 * 3. Pure and frozen. Native bigint. Practice values only: nothing here is constant time.
 * 4. X25519 is a different model (a Montgomery ladder on u only). It is not in this file.
 */

export interface Curve {
  readonly p: bigint
  readonly a: bigint
  readonly b: bigint
}

/** A point: the point at infinity (the "zero" of the group), or (x, y). */
export type Point = { readonly kind: 'inf' } | { readonly kind: 'pt'; readonly x: bigint; readonly y: bigint }

export type CurveErrorCode = 'CURVE_SINGULAR' | 'CURVE_NOT_ON_CURVE' | 'CURVE_BAD_SCALAR' | 'CURVE_WALK_DIVERGED'

export class CurveError extends Error {
  readonly code: CurveErrorCode
  constructor(code: CurveErrorCode, message: string) {
    super(message)
    this.name = 'CurveError'
    this.code = code
  }
}

export const INF: Point = Object.freeze({ kind: 'inf' })
export const pt = (x: bigint, y: bigint): Point => Object.freeze({ kind: 'pt', x, y })

const mod = (v: bigint, p: bigint): bigint => ((v % p) + p) % p

/** The inverse of v mod a prime p, by the extended Euclid method. */
export function invMod(v: bigint, p: bigint): bigint {
  let [r0, r1] = [mod(v, p), p]
  let [s0, s1] = [1n, 0n]
  while (r1 !== 0n) {
    const q = r0 / r1
    ;[r0, r1] = [r1, r0 - q * r1]
    ;[s0, s1] = [s1, s0 - q * s1]
  }
  return mod(s0, p)
}

/** A curve must have 4a^3 + 27b^2 != 0 (mod p). If not, it has a sharp corner and the add rule fails. */
export function checkCurve(c: Curve): void {
  if (mod(4n * c.a ** 3n + 27n * c.b ** 2n, c.p) === 0n) {
    throw new CurveError('CURVE_SINGULAR', '4a^3 + 27b^2 is 0 mod p, so this is not an elliptic curve.')
  }
}

export function isOnCurve(c: Curve, P: Point): boolean {
  if (P.kind === 'inf') return true
  return mod(P.y * P.y - (P.x ** 3n + c.a * P.x + c.b), c.p) === 0n
}

export const samePoint = (P: Point, Q: Point): boolean =>
  P.kind === 'inf' || Q.kind === 'inf' ? P.kind === Q.kind : P.x === Q.x && P.y === Q.y

export const negate = (c: Curve, P: Point): Point => (P.kind === 'inf' ? INF : pt(P.x, mod(-P.y, c.p)))

/** Which rule gave the sum. */
export type AddRule =
  | 'left-is-O' // O + Q = Q
  | 'right-is-O' // P + O = P
  | 'opposite' // P + (-P) = O: the line is vertical
  | 'double' // P + P: the tangent line
  | 'add' // two different points: the line through both

/** One point addition, with the numbers of the formula. */
export interface AddStep {
  readonly P: Point
  readonly Q: Point
  readonly rule: AddRule
  /** The slope of the line, for 'add' and 'double'. Null for the other rules. */
  readonly slope: bigint | null
  /** Top and bottom of the slope fraction before the division mod p. */
  readonly slopeTop: bigint | null
  readonly slopeBottom: bigint | null
  readonly result: Point
}

/** P + Q, with its trace. */
export function addStep(c: Curve, P: Point, Q: Point): AddStep {
  const none = { slope: null, slopeTop: null, slopeBottom: null }
  if (P.kind === 'inf') return Object.freeze({ P, Q, rule: 'left-is-O', ...none, result: Q })
  if (Q.kind === 'inf') return Object.freeze({ P, Q, rule: 'right-is-O', ...none, result: P })
  if (P.x === Q.x && mod(P.y + Q.y, c.p) === 0n) return Object.freeze({ P, Q, rule: 'opposite', ...none, result: INF })
  const double = P.x === Q.x && P.y === Q.y
  const top = double ? mod(3n * P.x * P.x + c.a, c.p) : mod(Q.y - P.y, c.p)
  const bottom = double ? mod(2n * P.y, c.p) : mod(Q.x - P.x, c.p)
  const slope = mod(top * invMod(bottom, c.p), c.p)
  const x = mod(slope * slope - P.x - Q.x, c.p)
  const y = mod(slope * (P.x - x) - P.y, c.p)
  return Object.freeze({ P, Q, rule: double ? 'double' : 'add', slope, slopeTop: top, slopeBottom: bottom, result: pt(x, y) })
}

export const add = (c: Curve, P: Point, Q: Point): Point => addStep(c, P, Q).result

/** One bit of k·P: double, then add P when the bit is 1. */
export interface MulRow {
  /** Position of the bit, 0 at the low end. */
  readonly bit: number
  readonly isOne: boolean
  readonly double: AddStep
  /** Null when the bit is 0: no add runs. */
  readonly addP: AddStep | null
  /** The running point after this row. */
  readonly after: Point
}

/** k·P, row by row. */
export interface MulWalk {
  readonly P: Point
  readonly k: bigint
  readonly result: Point
  readonly rows: readonly MulRow[]
}

/** Left-to-right double-and-add. The rows read k from its top set bit down to bit 0. The start value is O. */
export function mulWalk(c: Curve, k: bigint, P: Point): MulWalk {
  if (k < 1n) throw new CurveError('CURVE_BAD_SCALAR', 'The scalar must be 1 or more.')
  if (!isOnCurve(c, P)) throw new CurveError('CURVE_NOT_ON_CURVE', 'The point is not on the curve.')
  let acc: Point = INF
  const rows: MulRow[] = []
  for (let bit = k.toString(2).length - 1; bit >= 0; bit -= 1) {
    const isOne = ((k >> BigInt(bit)) & 1n) === 1n
    const double = addStep(c, acc, acc)
    acc = double.result
    let addP: AddStep | null = null
    if (isOne) {
      addP = addStep(c, acc, P)
      acc = addP.result
    }
    rows.push(Object.freeze({ bit, isOne, double, addP, after: acc }))
  }
  return Object.freeze({ P, k, result: acc, rows: Object.freeze(rows) })
}

export const mul = (c: Curve, k: bigint, P: Point): Point => mulWalk(c, k, P).result

/** Every point (x, y) of a small curve, by trying each pair. O is not in the list. Only for a toy prime. */
export function affinePoints(c: Curve): readonly Point[] {
  const out: Point[] = []
  for (let x = 0n; x < c.p; x += 1n) {
    for (let y = 0n; y < c.p; y += 1n) {
      const P = pt(x, y)
      if (isOnCurve(c, P)) out.push(P)
    }
  }
  return Object.freeze(out)
}

// ── The toy curve of the lesson ────────────────────────────────────────────────

/** y^2 = x^3 + 2x + 2 mod 17. */
export const TOY_CURVE: Curve = Object.freeze({ p: 17n, a: 2n, b: 2n })
/** The base point. Every point of the curve is a multiple of it. */
export const TOY_G: Point = pt(5n, 1n)
/** The number of points, O included. 19·G = O. */
export const TOY_ORDER = 19n
/** Practice secrets: 13 = 1101 and 7 = 111 in bits, so the walk shows doubles with and with no add. */
export const TOY_SECRETS = Object.freeze({ client: 13n, server: 7n })

/** What one side holds and makes in the exchange on a curve. */
export interface EcdhSideWalk {
  readonly private: bigint
  /** private·G: the point this side sends. */
  readonly public: MulWalk
  /** private·(peer public): the shared point this side makes. */
  readonly shared: MulWalk
}

export interface EcdhWalk {
  readonly curve: Curve
  readonly G: Point
  readonly order: bigint
  readonly client: EcdhSideWalk
  readonly server: EcdhSideWalk
  /** The point both sides now hold. Its x value is the shared secret. */
  readonly secret: Point
}

/** Diffie-Hellman on a curve: the same plan as dh.ts, with k·P in the place of g^k. */
export function ecdhWalk(c: Curve, G: Point, order: bigint, a: bigint, b: bigint): EcdhWalk {
  checkCurve(c)
  const clientPublic = mulWalk(c, a, G)
  const serverPublic = mulWalk(c, b, G)
  const client: EcdhSideWalk = Object.freeze({ private: a, public: clientPublic, shared: mulWalk(c, a, serverPublic.result) })
  const server: EcdhSideWalk = Object.freeze({ private: b, public: serverPublic, shared: mulWalk(c, b, clientPublic.result) })
  if (!samePoint(client.shared.result, server.shared.result)) {
    throw new CurveError('CURVE_WALK_DIVERGED', 'The two sides made different points.')
  }
  return Object.freeze({ curve: c, G, order, client, server, secret: client.shared.result })
}

/** The exchange of the lesson: the toy curve with secrets 13 and 7. */
export const toyEcdh = (): EcdhWalk => ecdhWalk(TOY_CURVE, TOY_G, TOY_ORDER, TOY_SECRETS.client, TOY_SECRETS.server)
