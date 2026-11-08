using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>
    /// One HMAC-SHA-256, step by step (RFC 2104): the key as used (hashed with SHA-256 first when it is longer than SHA-256's 64-byte block), padded
    /// with zeros to 64 bytes, then the inner pass H((K xor ipad) || message) and the outer pass H((K xor opad) || inner). ipad is 0x36, opad is 0x5c.
    /// </summary>
    public sealed class HmacWalk
    {
        /// <summary>Which RFC 4231 section 4 test case: "1", "2", "3", "4", "6" or "7". Case 5 is a truncated MAC, so the walk leaves it out.</summary>
        public string Case;
        public byte[] Key, Message;
        public bool KeyHashed;
        public byte[] KeyUsed, PaddedKey, InnerPad, InnerDigest, OuterPad, Mac;
    }

    /// <summary>
    /// The HMAC walk on RFC 4231's published test cases (docs/sections-plan.md, section 4, the HMAC row). Pure. Each step comes from the engine's own
    /// Hmac through its trace, and the MAC is compared with Hmac.Compute, so a walk that differs throws HMAC_WALK_DIVERGED. The keys are public test
    /// values, so it stays open with Show keys off.
    /// </summary>
    public static class HmacWalks
    {
        public static readonly string[] Cases = new string[] { "1", "2", "3", "4", "6", "7" };

        // RFC 4231 section 4, HMAC-SHA-256: the key and the data of each case. Public test values.
        static readonly string[] Keys = { "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4a656665", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "0102030405060708090a0b0c0d0e0f10111213141516171819", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
        static readonly string[] Data = { "4869205468657265", "7768617420646f2079612077616e7420666f72206e6f7468696e673f", "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374", "5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c6172676572207468616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365642062792074686520484d414320616c676f726974686d2e" };

        // RFC 4231 section 4: the published HMAC-SHA-256 of each case, so the guard also catches a fault in the engine, not only in the trace.
        static readonly string[] Macs = { "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b", "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2" };

        public static HmacWalk Rfc4231(string testCase)
        {
            int i = Array.IndexOf(Cases, testCase);
            if (i < 0) throw new ArgumentException("case must be 1, 2, 3, 4, 6 or 7", "testCase");
            byte[] key = Hex.Decode(Keys[i]), message = Hex.Decode(Data[i]);
            HmacTrace trace = new HmacTrace();
            byte[] mac = Hmac.Compute(Hashes.Sha256, key, message, trace);

            HmacWalk w = new HmacWalk();
            w.Case = testCase;
            w.Key = key;
            w.Message = message;
            w.KeyHashed = trace.KeyHashed;
            w.KeyUsed = trace.KeyUsed;
            w.PaddedKey = trace.PaddedKey;
            w.InnerPad = trace.InnerPad;
            w.InnerDigest = trace.InnerDigest;
            w.OuterPad = trace.OuterPad;
            w.Mac = mac;
            Require(Hex.Encode(mac) == Hex.Encode(Hmac.Compute(Hashes.Sha256, key, message)) && Hex.Encode(mac) == Macs[i]);
            return w;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.HmacWalkDiverged, "The walk differs from the real HMAC path."));
        }
    }
}
