using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>
    /// One Ed25519 signature, step by step (RFC 8032 section 5.1.6 to sign, 5.1.7 to verify). Scalars and points are 32 little-endian bytes,
    /// the encoding RFC 8032 prints. L is the group order, 2^252 + 27742317777372353535851937790883648493.
    /// </summary>
    public sealed class Ed25519Walk
    {
        /// <summary>Which RFC 8032 section 7.1 test: "1", "2" or "3".</summary>
        public string Test;
        public byte[] Seed, Message;

        /// <summary>Key expansion: SHA-512(seed) (64 bytes), its low half clamped (the secret scalar a), its high half (the prefix), and A = a*B.</summary>
        public byte[] Expanded, Scalar, Prefix, PublicKey;

        /// <summary>r = SHA-512(prefix || M) mod L, and R = r*B.</summary>
        public byte[] R, RPoint;

        /// <summary>h = SHA-512(R || A || M) mod L. RFC 8032 calls it k.</summary>
        public byte[] H;

        /// <summary>S = (r + h*a) mod L, and the signature R || S (64 bytes).</summary>
        public byte[] S, Signature;

        /// <summary>Verify: S*B, h*(-A), and R' = S*B + h*(-A). The signature holds when R' equals R.</summary>
        public byte[] SB, MinusHA, RPrime;
        public bool Valid;
    }

    /// <summary>
    /// The Ed25519 walk on RFC 8032 section 7.1's published test keys (docs/sections-plan.md, section 4, the Ed25519 row). Pure. Each step comes
    /// from the engine's own Ed25519 code through its trace. The signature is then compared with Ed25519.Sign and the verdict with Ed25519.Verify,
    /// so a walk that differs from the real path throws ED25519_WALK_DIVERGED and shows nothing. The keys are public, so it stays open with Show keys off.
    /// </summary>
    public static class Ed25519Walks
    {
        // RFC 8032 section 7.1, TEST 1, 2 and 3: the secret key (seed) and the message. Public test values.
        static readonly string[] Seeds = { "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7" };
        static readonly string[] Messages = { "", "72", "af82" };

        public static readonly string[] Tests = new string[] { "1", "2", "3" };

        public static Ed25519Walk Rfc8032(string test)
        {
            int i = Array.IndexOf(Tests, test);
            if (i < 0) throw new ArgumentException("test must be 1, 2 or 3", "test");
            byte[] seed = Hex.Decode(Seeds[i]), message = Hex.Decode(Messages[i]);

            Ed25519Trace signing = new Ed25519Trace(), verifying = new Ed25519Trace();
            byte[] signature = Ed25519.Sign(seed, message, signing);
            bool valid = Ed25519.Verify(signing.PublicKey, message, signature, verifying);

            Ed25519Walk w = new Ed25519Walk();
            w.Test = test;
            w.Seed = seed;
            w.Message = message;
            w.Expanded = signing.Expanded;
            w.Scalar = signing.Scalar;
            w.Prefix = signing.Prefix;
            w.PublicKey = signing.PublicKey;
            w.R = signing.R;
            w.RPoint = signing.RPoint;
            w.H = signing.H;
            w.S = signing.S;
            w.Signature = signature;
            w.SB = verifying.SB;
            w.MinusHA = verifying.MinusHA;
            w.RPrime = verifying.RPrime;
            w.Valid = valid;

            Require(Same(signature, Ed25519.Sign(seed, message)));
            Require(Same(w.PublicKey, Ed25519.PublicFrom(seed)));
            Require(valid == Ed25519.Verify(w.PublicKey, message, signature) && valid);
            Require(Same(w.RPrime, w.RPoint) && Same(w.H, verifying.VerifyH));
            return w;
        }

        static bool Same(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.Ed25519WalkDiverged, "The walk differs from the real Ed25519 path."));
        }
    }
}
