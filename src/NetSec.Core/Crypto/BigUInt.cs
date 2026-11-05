using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// An unsigned integer of any size. An instance never changes. The limbs are 32-bit and little-endian, with no
    /// high zero limb, so zero has no limbs. The CF references have no BigInteger, so both builds use this type.
    /// Built to show the parts. Do not copy: the run time of these methods depends on the values.
    /// </summary>
    public sealed class BigUInt
    {
        public static readonly BigUInt Zero = new BigUInt(new uint[0]);
        public static readonly BigUInt One = FromUInt32(1);

        readonly uint[] _limbs;

        BigUInt(uint[] limbs) { _limbs = limbs; }

        /// <summary>Takes a copy of the limbs and drops high zero limbs.</summary>
        internal static BigUInt FromLimbs(uint[] limbs)
        {
            int count = limbs.Length;
            while (count > 0 && limbs[count - 1] == 0) count--;
            uint[] copy = new uint[count];
            Array.Copy(limbs, copy, count);
            return new BigUInt(copy);
        }

        public static BigUInt FromUInt32(uint value)
        {
            return value == 0 ? new BigUInt(new uint[0]) : new BigUInt(new uint[] { value });
        }

        /// <summary>Reads a big-endian value. Leading zero bytes change nothing.</summary>
        public static BigUInt FromBytes(byte[] bytes)
        {
            if (bytes == null) throw new ArgumentNullException("bytes");
            uint[] limbs = new uint[(bytes.Length + 3) / 4];
            for (int i = 0; i < bytes.Length; i++)
            {
                int fromEnd = bytes.Length - 1 - i;
                limbs[fromEnd / 4] |= (uint)bytes[i] << (8 * (fromEnd % 4));
            }
            return FromLimbs(limbs);
        }

        /// <summary>The shortest big-endian form. Zero gives an empty array.</summary>
        public byte[] ToBigEndian() { return ToBigEndian((BitLength + 7) / 8); }

        /// <summary>The big-endian form at a fixed width, with leading zeros. A value that does not fit throws.</summary>
        public byte[] ToBigEndian(int length)
        {
            if (length < (BitLength + 7) / 8) throw new ArgumentException("the value needs more than " + length + " bytes", "length");
            byte[] bytes = new byte[length];
            for (int fromEnd = 0; fromEnd < length && fromEnd / 4 < _limbs.Length; fromEnd++)
                bytes[length - 1 - fromEnd] = (byte)(_limbs[fromEnd / 4] >> (8 * (fromEnd % 4)));
            return bytes;
        }

        internal uint[] Limbs { get { return _limbs; } }

        public bool IsZero { get { return _limbs.Length == 0; } }

        public bool IsOdd { get { return _limbs.Length > 0 && (_limbs[0] & 1) == 1; } }

        public int BitLength
        {
            get
            {
                if (_limbs.Length == 0) return 0;
                return 32 * (_limbs.Length - 1) + BitsIn(_limbs[_limbs.Length - 1]);
            }
        }

        static int BitsIn(uint limb)
        {
            int bits = 0;
            while (limb != 0) { bits++; limb >>= 1; }
            return bits;
        }

        /// <summary>Negative when this value is smaller, zero when equal, positive when larger.</summary>
        public int CompareTo(BigUInt other)
        {
            if (_limbs.Length != other._limbs.Length) return _limbs.Length < other._limbs.Length ? -1 : 1;
            for (int i = _limbs.Length - 1; i >= 0; i--)
                if (_limbs[i] != other._limbs[i]) return _limbs[i] < other._limbs[i] ? -1 : 1;
            return 0;
        }

        public BigUInt Add(BigUInt other)
        {
            uint[] longer = _limbs.Length >= other._limbs.Length ? _limbs : other._limbs;
            uint[] shorter = _limbs.Length >= other._limbs.Length ? other._limbs : _limbs;
            uint[] sum = new uint[longer.Length + 1];
            ulong carry = 0;
            for (int i = 0; i < longer.Length; i++)
            {
                ulong total = (ulong)longer[i] + (i < shorter.Length ? shorter[i] : 0u) + carry;
                sum[i] = (uint)total;
                carry = total >> 32;
            }
            sum[longer.Length] = (uint)carry;
            return FromLimbs(sum);
        }

        /// <summary>This value minus other. A negative result throws, because this type has no sign.</summary>
        public BigUInt Subtract(BigUInt other)
        {
            if (CompareTo(other) < 0) throw new ArgumentException("the result would be negative", "other");
            uint[] difference = new uint[_limbs.Length];
            long borrow = 0;
            for (int i = 0; i < _limbs.Length; i++)
            {
                long total = (long)_limbs[i] - (i < other._limbs.Length ? other._limbs[i] : 0u) + borrow;
                difference[i] = (uint)total;
                borrow = total >> 32;   // An arithmetic shift, so this is -1 after a borrow and 0 otherwise.
            }
            return FromLimbs(difference);
        }

        /// <summary>Schoolbook multiplication: each limb of one value against each limb of the other.</summary>
        public BigUInt Multiply(BigUInt other)
        {
            if (IsZero || other.IsZero) return Zero;
            uint[] product = new uint[_limbs.Length + other._limbs.Length];
            for (int i = 0; i < _limbs.Length; i++)
            {
                ulong carry = 0;
                for (int j = 0; j < other._limbs.Length; j++)
                {
                    ulong total = (ulong)_limbs[i] * other._limbs[j] + product[i + j] + carry;
                    product[i + j] = (uint)total;
                    carry = total >> 32;
                }
                product[i + other._limbs.Length] = (uint)carry;
            }
            return FromLimbs(product);
        }

        public BigUInt Mod(BigUInt divisor)
        {
            BigUInt remainder;
            DivRem(divisor, out remainder);
            return remainder;
        }

        public BigUInt DivRem(BigUInt divisor, out BigUInt remainder)
        {
            if (divisor.IsZero) throw new DivideByZeroException();
            if (CompareTo(divisor) < 0)
            {
                remainder = this;
                return Zero;
            }
            uint[] quotient, rest;
            if (divisor._limbs.Length == 1) DivideByLimb(_limbs, divisor._limbs[0], out quotient, out rest);
            else DivideKnuth(_limbs, divisor._limbs, out quotient, out rest);
            remainder = FromLimbs(rest);
            return FromLimbs(quotient);
        }

        static void DivideByLimb(uint[] dividend, uint divisor, out uint[] quotient, out uint[] rest)
        {
            quotient = new uint[dividend.Length];
            ulong running = 0;
            for (int i = dividend.Length - 1; i >= 0; i--)
            {
                ulong current = (running << 32) | dividend[i];
                quotient[i] = (uint)(current / divisor);
                running = current % divisor;
            }
            rest = new uint[] { (uint)running };
        }

        /// <summary>
        /// Knuth's Algorithm D, in base 2^32. How it works:
        /// 1. Shift both values left until the divisor's top bit is set. Then the first guess of each quotient limb is at most 2 too high.
        /// 2. For each quotient limb, top down, guess from the top two limbs of the running remainder and the top limb of the divisor.
        /// 3. Test the guess against one more limb, and lower it while it is too high.
        /// 4. Subtract guess times divisor. If that goes below zero, the guess was still 1 too high, so add the divisor back.
        /// 5. Shift the remainder right to undo step 1.
        /// </summary>
        static void DivideKnuth(uint[] dividend, uint[] divisor, out uint[] quotient, out uint[] rest)
        {
            int n = divisor.Length;
            int m = dividend.Length - n;
            int shift = 32 - BitsIn(divisor[n - 1]);
            uint[] v = ShiftLeft(divisor, shift, n);
            uint[] u = ShiftLeft(dividend, shift, dividend.Length + 1);
            quotient = new uint[m + 1];
            for (int j = m; j >= 0; j--)
            {
                ulong guess = GuessQuotientLimb(u, v, j, n);
                bool wentNegative = SubtractProduct(u, v, j, guess);
                if (wentNegative)
                {
                    guess--;
                    AddBack(u, v, j);
                }
                quotient[j] = (uint)guess;
            }
            rest = ShiftRight(u, shift, n);
        }

        static ulong GuessQuotientLimb(uint[] u, uint[] v, int j, int n)
        {
            const ulong LimbBase = 1UL << 32;
            ulong top = ((ulong)u[j + n] << 32) | u[j + n - 1];
            ulong guess = top / v[n - 1];
            ulong rest = top % v[n - 1];
            while (guess >= LimbBase || guess * v[n - 2] > ((rest << 32) | u[j + n - 2]))
            {
                guess--;
                rest += v[n - 1];
                if (rest >= LimbBase) break;
            }
            return guess;
        }

        /// <summary>u at offset j, minus guess times v. Returns true when the result went below zero.</summary>
        static bool SubtractProduct(uint[] u, uint[] v, int j, ulong guess)
        {
            long borrow = 0;
            for (int i = 0; i < v.Length; i++)
            {
                ulong product = guess * v[i];
                long total = (long)u[i + j] - borrow - (long)(product & 0xFFFFFFFFUL);
                u[i + j] = (uint)total;
                borrow = (long)(product >> 32) - (total >> 32);
            }
            long top = (long)u[j + v.Length] - borrow;
            u[j + v.Length] = (uint)top;
            return top < 0;
        }

        static void AddBack(uint[] u, uint[] v, int j)
        {
            ulong carry = 0;
            for (int i = 0; i < v.Length; i++)
            {
                ulong total = (ulong)u[i + j] + v[i] + carry;
                u[i + j] = (uint)total;
                carry = total >> 32;
            }
            u[j + v.Length] = (uint)(u[j + v.Length] + carry);
        }

        static uint[] ShiftLeft(uint[] value, int bits, int resultLength)
        {
            uint[] shifted = new uint[resultLength];
            for (int i = 0; i < value.Length; i++)
            {
                shifted[i] |= value[i] << bits;
                if (bits != 0 && i + 1 < resultLength) shifted[i + 1] = value[i] >> (32 - bits);
            }
            return shifted;
        }

        static uint[] ShiftRight(uint[] value, int bits, int resultLength)
        {
            uint[] shifted = new uint[resultLength];
            for (int i = 0; i < resultLength; i++)
            {
                shifted[i] = value[i] >> bits;
                if (bits != 0 && i + 1 < value.Length) shifted[i] |= value[i + 1] << (32 - bits);
            }
            return shifted;
        }

        /// <summary>This value to the power of exponent, mod an odd modulus. RSA moduli and DH primes are odd.</summary>
        public BigUInt ModPow(BigUInt exponent, BigUInt modulus)
        {
            if (!modulus.IsOdd) throw new ArgumentException("the modulus must be odd", "modulus");
            if (modulus.CompareTo(One) == 0) return Zero;
            return new Montgomery(modulus).Pow(Mod(modulus), exponent);
        }

        /// <summary>The value of four exponent bits, with position 0 at the low end.</summary>
        internal int Nibble(int position)
        {
            int bit = position * 4;
            int limb = bit / 32;
            return limb < _limbs.Length ? (int)((_limbs[limb] >> (bit % 32)) & 15) : 0;
        }
    }
}
