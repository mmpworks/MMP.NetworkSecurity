namespace NetSec.Crypto
{
    /// <summary>
    /// ML-KEM polynomials: int[256], each coefficient in [0, q), q = 3329. The NTT is a change of form that makes a product
    /// cheap. Names follow FIPS 203 algorithms 9 to 12. These methods write into caller-owned arrays.
    /// </summary>
    internal static class Poly
    {
        public const int N = 256;
        public const int Q = 3329;

        const int Zeta = 17;                // A primitive 256th root of unity mod q (FIPS 203 section 4.3).
        const int NInverse = 3303;          // 128^-1 mod q: the factor at the end of the inverse transform.

        static readonly int[] Zetas = BuildZetas();         // zeta^BitRev7(i) mod q
        static readonly int[] Gammas = BuildGammas();       // zeta^(2*BitRev7(i)+1) mod q

        static int BitRev7(int value)
        {
            int reversed = 0;
            for (int bit = 0; bit < 7; bit++)
                if ((value & (1 << bit)) != 0) reversed |= 1 << (6 - bit);
            return reversed;
        }

        static int PowerOfZeta(int exponent)
        {
            int result = 1;
            for (int i = 0; i < exponent; i++) result = result * Zeta % Q;
            return result;
        }

        static int[] BuildZetas()
        {
            int[] table = new int[128];
            for (int i = 0; i < 128; i++) table[i] = PowerOfZeta(BitRev7(i));
            return table;
        }

        static int[] BuildGammas()
        {
            int[] table = new int[128];
            for (int i = 0; i < 128; i++) table[i] = PowerOfZeta(2 * BitRev7(i) + 1);
            return table;
        }

        /// <summary>FIPS 203 algorithm 9. The butterfly loops turn f into its NTT form, in place.</summary>
        public static void Ntt(int[] f)
        {
            int i = 1;
            for (int len = 128; len >= 2; len /= 2)
            {
                for (int start = 0; start < N; start += 2 * len)
                {
                    int zeta = Zetas[i];
                    i++;
                    for (int j = start; j < start + len; j++)
                    {
                        int t = zeta * f[j + len] % Q;
                        f[j + len] = (f[j] - t + Q) % Q;
                        f[j] = (f[j] + t) % Q;
                    }
                }
            }
        }

        /// <summary>FIPS 203 algorithm 10. Undoes Ntt, in place.</summary>
        public static void InverseNtt(int[] f)
        {
            int i = 127;
            for (int len = 2; len <= 128; len *= 2)
            {
                for (int start = 0; start < N; start += 2 * len)
                {
                    int zeta = Zetas[i];
                    i--;
                    for (int j = start; j < start + len; j++)
                    {
                        int t = f[j];
                        f[j] = (t + f[j + len]) % Q;
                        f[j + len] = zeta * (f[j + len] - t + Q) % Q;
                    }
                }
            }
            for (int j = 0; j < N; j++) f[j] = f[j] * NInverse % Q;
        }

        /// <summary>FIPS 203 algorithms 11 and 12. Adds the product of f and g in NTT form to h. Each pair of coefficients is one small product mod (X^2 - gamma).</summary>
        public static void AddMultiplyNtts(int[] h, int[] f, int[] g)
        {
            for (int i = 0; i < 128; i++)
            {
                int a0 = f[2 * i], a1 = f[2 * i + 1], b0 = g[2 * i], b1 = g[2 * i + 1];
                int c0 = (a0 * b0 % Q + (a1 * b1 % Q) * Gammas[i] % Q) % Q;
                int c1 = (a0 * b1 % Q + a1 * b0 % Q) % Q;
                h[2 * i] = (h[2 * i] + c0) % Q;
                h[2 * i + 1] = (h[2 * i + 1] + c1) % Q;
            }
        }

        public static void Add(int[] o, int[] a)
        {
            for (int i = 0; i < N; i++) o[i] = (o[i] + a[i]) % Q;
        }

        public static void Subtract(int[] o, int[] a)
        {
            for (int i = 0; i < N; i++) o[i] = (o[i] - a[i] + Q) % Q;
        }
    }
}
