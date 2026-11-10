// Byte handling at the library's edge: input checks, frozen output, hex, and the coded error.

/** A byte sequence the library hands out. Each one is a frozen array, so no reader can change a trace. */
export type Bytes = readonly number[]

/** The stable codes an AesError carries. A caller branches on the code, never on the message. */
export type AesErrorCode = 'AES_KEY_LENGTH' | 'AES_BLOCK_LENGTH' | 'AES_BYTE' | 'AES_HEX' | 'AES_WALK_DIVERGED'

export class AesError extends Error {
  readonly code: AesErrorCode

  constructor(code: AesErrorCode, message: string) {
    super(message)
    this.name = 'AesError'
    this.code = code
  }
}

export const BLOCK_SIZE = 16
export const KEY_SIZES: readonly number[] = Object.freeze([16, 24, 32])

export function frozen(values: ArrayLike<number>): Bytes {
  return Object.freeze(Array.from(values))
}

/** A copy of `input`, after a check that each value is a byte. The caller's array is never kept or changed. */
function copyBytes(input: ArrayLike<number>, what: string): number[] {
  const out = Array.from(input)
  out.forEach((b, i) => {
    if (!Number.isInteger(b) || b < 0 || b > 255) throw new AesError('AES_BYTE', `${what}[${i}] is ${b}, which is not a byte`)
  })
  return out
}

export function readKey(key: ArrayLike<number>): number[] {
  if (!KEY_SIZES.includes(key.length)) throw new AesError('AES_KEY_LENGTH', `an AES key is 16, 24 or 32 bytes, not ${key.length}`)
  return copyBytes(key, 'key')
}

export function readBlock(block: ArrayLike<number>): number[] {
  if (block.length !== BLOCK_SIZE) throw new AesError('AES_BLOCK_LENGTH', `an AES block is 16 bytes, not ${block.length}`)
  return copyBytes(block, 'block')
}

/** Lowercase hex, two digits a byte. */
export function toHex(bytes: ArrayLike<number>): string {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

/** Hex to bytes. Spaces are allowed between bytes; an odd digit count or a non-hex character throws AES_HEX. */
export function fromHex(hex: string): Bytes {
  const digits = hex.replace(/\s+/g, '')
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(digits)) throw new AesError('AES_HEX', 'hex needs pairs of the digits 0-9 and a-f')
  return frozen(Array.from({ length: digits.length / 2 }, (_, i) => parseInt(digits.slice(2 * i, 2 * i + 2), 16)))
}
