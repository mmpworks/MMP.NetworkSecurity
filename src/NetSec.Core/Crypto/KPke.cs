using System;

namespace NetSec.Crypto
{
    /// <summary>One data row per ML-KEM parameter set (FIPS 203 section 8). A new set needs one more row.</summary>
    internal sealed class MlKemParameters
    {
        public static readonly MlKemParameters Ml768 = new MlKemParameters(3, 2, 2, 10, 4);

        public readonly int K, Eta1, Eta2, Du, Dv;

        MlKemParameters(int k, int eta1, int eta2, int du, int dv)
        {
            K = k;
            Eta1 = eta1;
            Eta2 = eta2;
            Du = du;
            Dv = dv;
        }

        public int PkeDecryptionKeyLength { get { return 384 * K; } }
        public int EncapsulationKeyLength { get { return 384 * K + 32; } }
        public int DecapsulationKeyLength { get { return 768 * K + 96; } }
        public int CiphertextLength { get { return 32 * (Du * K + Dv); } }
    }

    /// <summary>
    /// K-PKE, the public-key encryption inside ML-KEM (FIPS 203 section 5). Lattice idea: t = A*s + e hides s under the small
    /// noise e. Encryption adds the message at a high amplitude, and the small noise stays small enough to round away.
    /// </summary>
    internal static class KPke
    {
        /// <summary>FIPS 203 algorithm 13.</summary>
        public static void KeyGen(MlKemParameters p, byte[] d, out byte[] ek, out byte[] dk)
        {
            byte[] expanded = MlKemSampling.G(d, new byte[] { (byte)p.K });
            byte[] rho = Slice(expanded, 0, 32);
            byte[] sigma = Slice(expanded, 32, 32);
            int[][][] a = GenerateA(p, rho);
            int n = 0;
            int[][] s = SampleVector(p.K, p.Eta1, sigma, ref n);
            int[][] e = SampleVector(p.K, p.Eta1, sigma, ref n);
            NttAll(s);
            NttAll(e);

            ek = new byte[p.EncapsulationKeyLength];
            dk = new byte[p.PkeDecryptionKeyLength];
            for (int i = 0; i < p.K; i++)
            {
                int[] t = new int[Poly.N];
                for (int j = 0; j < p.K; j++) Poly.AddMultiplyNtts(t, a[i][j], s[j]);
                Poly.Add(t, e[i]);
                MlKemEncoding.ByteEncode(12, t, ek, 384 * i);
                MlKemEncoding.ByteEncode(12, s[i], dk, 384 * i);
            }
            Array.Copy(rho, 0, ek, 384 * p.K, 32);
        }

        /// <summary>FIPS 203 algorithm 14. All randomness comes from r, so one input always gives one ciphertext.</summary>
        public static byte[] Encrypt(MlKemParameters p, byte[] ek, byte[] m, byte[] r)
        {
            int[][] t = DecodeVector(p.K, ek);
            byte[] rho = Slice(ek, 384 * p.K, 32);
            int[][][] a = GenerateA(p, rho);
            int n = 0;
            int[][] y = SampleVector(p.K, p.Eta1, r, ref n);
            int[][] e1 = SampleVector(p.K, p.Eta2, r, ref n);
            int[] e2 = MlKemSampling.SamplePolyCbd(p.Eta2, MlKemSampling.Prf(p.Eta2, r, n));
            NttAll(y);

            byte[] c = new byte[p.CiphertextLength];
            for (int i = 0; i < p.K; i++)
            {
                int[] u = new int[Poly.N];
                for (int j = 0; j < p.K; j++) Poly.AddMultiplyNtts(u, a[j][i], y[j]);   // A transposed
                Poly.InverseNtt(u);
                Poly.Add(u, e1[i]);
                MlKemEncoding.ByteEncode(p.Du, MlKemEncoding.Compress(p.Du, u), c, 32 * p.Du * i);
            }

            int[] v = DotProduct(t, y);
            Poly.InverseNtt(v);
            Poly.Add(v, e2);
            Poly.Add(v, MlKemEncoding.Decompress(1, MlKemEncoding.ByteDecode(1, m, 0)));
            MlKemEncoding.ByteEncode(p.Dv, MlKemEncoding.Compress(p.Dv, v), c, 32 * p.Du * p.K);
            return c;
        }

        /// <summary>FIPS 203 algorithm 15. w = v - s*u leaves the message plus small noise. Compress(1) rounds the noise away.</summary>
        public static byte[] Decrypt(MlKemParameters p, byte[] dkPke, byte[] c)
        {
            int[][] u = new int[p.K][];
            for (int i = 0; i < p.K; i++)
            {
                u[i] = MlKemEncoding.Decompress(p.Du, MlKemEncoding.ByteDecode(p.Du, c, 32 * p.Du * i));
                Poly.Ntt(u[i]);
            }
            int[] w = MlKemEncoding.Decompress(p.Dv, MlKemEncoding.ByteDecode(p.Dv, c, 32 * p.Du * p.K));
            int[] product = DotProduct(DecodeVector(p.K, dkPke), u);
            Poly.InverseNtt(product);
            Poly.Subtract(w, product);
            byte[] m = new byte[32];
            MlKemEncoding.ByteEncode(1, MlKemEncoding.Compress(1, w), m, 0);
            return m;
        }

        /// <summary>The public matrix, in NTT form. Both sides build it from rho, so the key carries only rho.</summary>
        static int[][][] GenerateA(MlKemParameters p, byte[] rho)
        {
            int[][][] a = new int[p.K][][];
            for (int i = 0; i < p.K; i++)
            {
                a[i] = new int[p.K][];
                for (int j = 0; j < p.K; j++) a[i][j] = MlKemSampling.SampleNtt(rho, j, i);
            }
            return a;
        }

        static int[][] SampleVector(int k, int eta, byte[] seed, ref int n)
        {
            int[][] vector = new int[k][];
            for (int i = 0; i < k; i++)
            {
                vector[i] = MlKemSampling.SamplePolyCbd(eta, MlKemSampling.Prf(eta, seed, n));
                n++;
            }
            return vector;
        }

        static void NttAll(int[][] vector)
        {
            for (int i = 0; i < vector.Length; i++) Poly.Ntt(vector[i]);
        }

        static int[][] DecodeVector(int k, byte[] b)
        {
            int[][] vector = new int[k][];
            for (int i = 0; i < k; i++) vector[i] = MlKemEncoding.ByteDecode(12, b, 384 * i);
            return vector;
        }

        static int[] DotProduct(int[][] a, int[][] b)
        {
            int[] sum = new int[Poly.N];
            for (int i = 0; i < a.Length; i++) Poly.AddMultiplyNtts(sum, a[i], b[i]);
            return sum;
        }

        internal static byte[] Slice(byte[] b, int offset, int count)
        {
            byte[] part = new byte[count];
            Array.Copy(b, offset, part, 0, count);
            return part;
        }
    }
}
