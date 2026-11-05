namespace NetSec.Crypto
{
    /// <summary>
    /// Modular exponentiation for an odd modulus n. Division is slow, so this type moves each value x to x*R mod n, with
    /// R = 2^(32*limbs). In that form a product needs no division. It only adds multiples of n until the low limbs are
    /// zero, then drops those limbs. All arrays here have the limb count of n.
    /// </summary>
    internal sealed class Montgomery
    {
        readonly uint[] _n;
        readonly uint _nInverse;      // -1/n mod 2^32
        readonly uint[] _one;         // R mod n: the value 1 in this form
        readonly uint[] _rSquared;    // R*R mod n: a product with this moves a value into this form

        public Montgomery(BigUInt modulus)
        {
            _n = modulus.Limbs;
            _nInverse = NegativeInverse(_n[0]);
            int bits = 32 * _n.Length;
            _one = Pad(PowerOfTwo(bits).Mod(modulus));
            _rSquared = Pad(PowerOfTwo(2 * bits).Mod(modulus));
        }

        /// <summary>Newton's iteration. Each pass doubles the count of correct low bits, and an odd n starts with 3 correct bits.</summary>
        static uint NegativeInverse(uint n)
        {
            uint inverse = n;
            for (int i = 0; i < 4; i++) inverse *= 2 - n * inverse;
            return 0u - inverse;
        }

        static BigUInt PowerOfTwo(int exponent)
        {
            uint[] limbs = new uint[exponent / 32 + 1];
            limbs[exponent / 32] = 1u << (exponent % 32);
            return BigUInt.FromLimbs(limbs);
        }

        uint[] Pad(BigUInt value)
        {
            uint[] padded = new uint[_n.Length];
            uint[] limbs = value.Limbs;
            for (int i = 0; i < limbs.Length; i++) padded[i] = limbs[i];
            return padded;
        }

        /// <summary>
        /// A 4-bit window: square four times, then multiply by a table entry. The table holds powers 0 to 15 of the base.
        /// The base must be below the modulus.
        /// </summary>
        public BigUInt Pow(BigUInt value, BigUInt exponent)
        {
            uint[][] table = new uint[16][];
            table[0] = _one;
            table[1] = Multiply(Pad(value), _rSquared);
            for (int i = 2; i < 16; i++) table[i] = Multiply(table[i - 1], table[1]);

            uint[] result = _one;
            for (int position = (exponent.BitLength + 3) / 4 - 1; position >= 0; position--)
            {
                for (int i = 0; i < 4; i++) result = Multiply(result, result);
                result = Multiply(result, table[exponent.Nibble(position)]);
            }
            return BigUInt.FromLimbs(Multiply(result, Pad(BigUInt.One)));
        }

        /// <summary>
        /// CIOS: coarsely integrated operand scanning. Each pass adds a times one limb of b, then adds the multiple of n
        /// that makes the low limb zero, then shifts one limb right. The result is a*b/R mod n.
        /// </summary>
        uint[] Multiply(uint[] a, uint[] b)
        {
            int s = _n.Length;
            uint[] t = new uint[s + 2];
            for (int i = 0; i < s; i++)
            {
                AddProduct(t, a, b[i]);
                uint m = t[0] * _nInverse;
                ReduceOneLimb(t, m);
            }
            return SubtractModulusIfNeeded(t);
        }

        static void AddProduct(uint[] t, uint[] a, uint limb)
        {
            int s = a.Length;
            ulong carry = 0;
            for (int j = 0; j < s; j++)
            {
                ulong total = (ulong)t[j] + (ulong)a[j] * limb + carry;
                t[j] = (uint)total;
                carry = total >> 32;
            }
            ulong top = t[s] + carry;
            t[s] = (uint)top;
            t[s + 1] = (uint)(top >> 32);
        }

        void ReduceOneLimb(uint[] t, uint m)
        {
            int s = _n.Length;
            ulong total = (ulong)t[0] + (ulong)m * _n[0];
            ulong carry = total >> 32;
            for (int j = 1; j < s; j++)
            {
                total = (ulong)t[j] + (ulong)m * _n[j] + carry;
                t[j - 1] = (uint)total;
                carry = total >> 32;
            }
            total = t[s] + carry;
            t[s - 1] = (uint)total;
            t[s] = t[s + 1] + (uint)(total >> 32);
            t[s + 1] = 0;
        }

        uint[] SubtractModulusIfNeeded(uint[] t)
        {
            int s = _n.Length;
            uint[] result = new uint[s];
            if (t[s] == 0 && IsBelowModulus(t))
            {
                for (int i = 0; i < s; i++) result[i] = t[i];
                return result;
            }
            long borrow = 0;
            for (int i = 0; i < s; i++)
            {
                long total = (long)t[i] - _n[i] + borrow;
                result[i] = (uint)total;
                borrow = total >> 32;
            }
            return result;
        }

        bool IsBelowModulus(uint[] t)
        {
            for (int i = _n.Length - 1; i >= 0; i--)
                if (t[i] != _n[i]) return t[i] < _n[i];
            return false;
        }
    }
}
