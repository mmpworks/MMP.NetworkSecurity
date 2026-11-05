using System;

namespace NetSec.Crypto
{
    /// <summary>
    /// Ed25519 (RFC 8032 section 5.1). A signature is R (a point, 32 bytes) then S (a scalar, 32 bytes).
    /// Built to show the parts. Do not copy: managed code gives no constant-time guarantee.
    /// </summary>
    public static class Ed25519
    {
        const int SeedLength = 32;
        const int PublicLength = 32;
        const int SignatureLength = 64;

        public static byte[] PublicFrom(byte[] seed)
        {
            CheckSeed(seed);
            return PublicFromScalar(ClampedScalar(Sha512(seed)));
        }

        public static byte[] Sign(byte[] seed, byte[] msg)
        {
            CheckSeed(seed);
            if (msg == null) throw new ArgumentNullException("msg");
            byte[] expanded = Sha512(seed);
            byte[] a = ClampedScalar(expanded);
            byte[] prefix = new byte[32];
            Array.Copy(expanded, 32, prefix, 0, 32);
            byte[] publicKey = PublicFromScalar(a);

            byte[] r = Sc25519.Reduce(Sha512(prefix, msg));
            byte[] signature = new byte[SignatureLength];
            long[][] rPoint = Ge25519.NewPoint();
            Ge25519.ScalarBase(rPoint, r);
            Ge25519.Pack(signature, 0, rPoint);

            byte[] rBytes = new byte[32];
            Array.Copy(signature, 0, rBytes, 0, 32);
            byte[] h = Sc25519.Reduce(Sha512(rBytes, publicKey, msg));
            Sc25519.MulAdd(signature, 32, r, h, a);
            return signature;
        }

        /// <summary>
        /// Checks S*B = R + h*A by computing R' = S*B + h*(-A) and comparing bytes with R. A comparison of encoded bytes
        /// also refuses an R in a form other than the canonical one.
        /// </summary>
        public static bool Verify(byte[] pub, byte[] msg, byte[] sig)
        {
            if (pub == null) throw new ArgumentNullException("pub");
            if (msg == null) throw new ArgumentNullException("msg");
            if (sig == null) throw new ArgumentNullException("sig");
            if (pub.Length != PublicLength || sig.Length != SignatureLength) return false;
            if (!Sc25519.IsCanonical(sig, 32)) return false;
            if (!IsCanonicalY(pub)) return false;
            long[][] negatedA = Ge25519.NewPoint();
            if (!Ge25519.TryUnpackNegated(negatedA, pub, 0)) return false;

            byte[] rBytes = new byte[32];
            byte[] s = new byte[32];
            Array.Copy(sig, 0, rBytes, 0, 32);
            Array.Copy(sig, 32, s, 0, 32);
            byte[] h = Sc25519.Reduce(Sha512(rBytes, pub, msg));

            long[][] p = Ge25519.NewPoint();
            long[][] sB = Ge25519.NewPoint();
            Ge25519.ScalarMult(p, negatedA, h);
            Ge25519.ScalarBase(sB, s);
            Ge25519.Add(p, sB);
            byte[] computed = new byte[32];
            Ge25519.Pack(computed, 0, p);

            int difference = 0;
            for (int i = 0; i < 32; i++) difference |= computed[i] ^ rBytes[i];
            return difference == 0;
        }

        /// <summary>
        /// RFC 8032 section 5.1.3 says decoding fails in three cases. This method checks the first: y is at or above p, where
        /// p is ed ff .. ff 7f, little-endian. Ge25519.TryUnpackNegated checks the other two: no square root, and x = 0 with
        /// the sign bit set.
        /// </summary>
        static bool IsCanonicalY(byte[] pub)
        {
            if ((pub[31] & 0x7f) != 0x7f) return true;
            for (int i = 30; i >= 1; i--)
                if (pub[i] != 0xff) return true;
            return pub[0] < 0xed;
        }

        static void CheckSeed(byte[] seed)
        {
            if (seed == null || seed.Length != SeedLength) throw new ArgumentException("an Ed25519 seed has 32 bytes", "seed");
        }

        /// <summary>RFC 8032 section 5.1.5: the low half of SHA-512(seed), clamped.</summary>
        static byte[] ClampedScalar(byte[] expanded)
        {
            byte[] a = new byte[32];
            Array.Copy(expanded, a, 32);
            a[0] &= 248;
            a[31] &= 127;
            a[31] |= 64;
            return a;
        }

        static byte[] PublicFromScalar(byte[] a)
        {
            long[][] point = Ge25519.NewPoint();
            Ge25519.ScalarBase(point, a);
            byte[] publicKey = new byte[PublicLength];
            Ge25519.Pack(publicKey, 0, point);
            return publicKey;
        }

        static byte[] Sha512(params byte[][] parts)
        {
            IHash hash = Hashes.Sha512();
            foreach (byte[] part in parts) hash.Update(part, 0, part.Length);
            return hash.Finish();
        }
    }
}
