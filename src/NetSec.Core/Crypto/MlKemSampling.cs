namespace NetSec.Crypto
{
    /// <summary>FIPS 203 section 4.2.2, and the hash functions of section 4.1: G, H, J, PRF, XOF.</summary>
    internal static class MlKemSampling
    {
        public static byte[] G(params byte[][] parts) { return HashAll(Hashes.Sha3_512(), parts); }

        public static byte[] H(params byte[][] parts) { return HashAll(Hashes.Sha3_256(), parts); }

        public static byte[] J(params byte[][] parts)
        {
            Shake shake = Shake.New256();
            foreach (byte[] part in parts) shake.Absorb(part, 0, part.Length);
            byte[] output = new byte[32];
            shake.Squeeze(output, 0, output.Length);
            return output;
        }

        /// <summary>PRF(eta, s, b) = SHAKE256(s || b), 64*eta bytes.</summary>
        public static byte[] Prf(int eta, byte[] s, int b)
        {
            Shake shake = Shake.New256();
            shake.Absorb(s, 0, s.Length);
            shake.Absorb(new byte[] { (byte)b }, 0, 1);
            byte[] output = new byte[64 * eta];
            shake.Squeeze(output, 0, output.Length);
            return output;
        }

        static byte[] HashAll(IHash hash, byte[][] parts)
        {
            foreach (byte[] part in parts) hash.Update(part, 0, part.Length);
            return hash.Finish();
        }

        /// <summary>
        /// FIPS 203 algorithm 7. Each 3 bytes of SHAKE128(rho || j || i) give two 12-bit values. A value below q becomes the
        /// next coefficient. A value at or above q is thrown away. So the XOF length is not known in advance.
        /// </summary>
        public static int[] SampleNtt(byte[] rho, int j, int i)
        {
            Shake xof = Shake.New128();
            xof.Absorb(rho, 0, rho.Length);
            xof.Absorb(new byte[] { (byte)j, (byte)i }, 0, 2);
            int[] a = new int[Poly.N];
            byte[] c = new byte[3];
            int count = 0;
            while (count < Poly.N)
            {
                xof.Squeeze(c, 0, 3);
                int d1 = c[0] + 256 * (c[1] & 15);
                int d2 = (c[1] >> 4) + 16 * c[2];
                if (d1 < Poly.Q) a[count++] = d1;
                if (d2 < Poly.Q && count < Poly.N) a[count++] = d2;
            }
            return a;
        }

        /// <summary>
        /// FIPS 203 algorithm 8. A coefficient is x - y, where x and y each count the set bits in eta input bits. So small
        /// values are likely and the range is [-eta, eta], written mod q.
        /// </summary>
        public static int[] SamplePolyCbd(int eta, byte[] b)
        {
            int[] f = new int[Poly.N];
            int position = 0;
            for (int i = 0; i < Poly.N; i++)
            {
                int x = 0, y = 0;
                for (int k = 0; k < eta; k++) x += ReadBit(b, position++);
                for (int k = 0; k < eta; k++) y += ReadBit(b, position++);
                f[i] = (x - y + Poly.Q) % Poly.Q;
            }
            return f;
        }

        static int ReadBit(byte[] b, int position)
        {
            return (b[position >> 3] >> (position & 7)) & 1;
        }
    }
}
