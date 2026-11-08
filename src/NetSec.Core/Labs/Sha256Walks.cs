using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Labs
{
    /// <summary>One SHA-256 round t: K[t], W[t], T1 = h + Sigma1(e) + Ch(e, f, g) + K[t] + W[t], T2 = Sigma0(a) + Maj(a, b, c), and a..h after the round.</summary>
    public sealed class Sha256WalkRound
    {
        public int T;
        public uint K, W, T1, T2;
        public uint[] State;
    }

    /// <summary>One 64-byte block: its bytes (the last block holds the padding), the chaining value in, the schedule W[0..63], the 64 rounds, and the value out (in + a..h).</summary>
    public sealed class Sha256WalkBlock
    {
        public byte[] Bytes;
        public uint[] HIn, Schedule, HOut;
        public Sha256WalkRound[] Rounds;
    }

    public sealed class Sha256Walk
    {
        /// <summary>Which FIPS 180-4 example: "abc" (one block) or "two-block" (the 56-byte message that needs a second block for its padding).</summary>
        public string Name;
        public byte[] Message, Digest;
        public Sha256WalkBlock[] Blocks;
    }

    /// <summary>
    /// The SHA-256 walk (FIPS 180-4 section 6.2; docs/sections-plan.md, slice P6) on NIST's published examples. Pure. Each value comes from the
    /// engine's own Sha256Hash through its trace, and the digest is compared with an untraced hash, so a walk that differs throws SHA256_WALK_DIVERGED.
    /// There is no key, so it stays open with Show keys off.
    /// </summary>
    public static class Sha256Walks
    {
        public static readonly string[] Names = new string[] { "abc", "two-block" };

        static readonly string[] Messages = { "abc", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" };

        // FIPS 180-4's published digests of the two examples, so the guard also catches a fault in the engine, not only in the trace.
        static readonly string[] Digests = { "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" };

        public static Sha256Walk Fips180(string name)
        {
            int i = Array.IndexOf(Names, name);
            if (i < 0) throw new ArgumentException("name must be abc or two-block", "name");
            byte[] message = Encoding.ASCII.GetBytes(Messages[i]);

            Sha256Hash traced = new Sha256Hash();
            traced.Trace = new List<Sha256BlockTrace>();
            traced.Update(message, 0, message.Length);
            byte[] digest = traced.Finish();

            uint[] k = Sha256Hash.RoundConstants;
            Sha256Walk w = new Sha256Walk();
            w.Name = name;
            w.Message = message;
            w.Digest = digest;
            w.Blocks = new Sha256WalkBlock[traced.Trace.Count];
            for (int b = 0; b < w.Blocks.Length; b++)
            {
                Sha256BlockTrace t = traced.Trace[b];
                Sha256WalkBlock block = new Sha256WalkBlock();
                block.Bytes = t.Block;
                block.HIn = t.HIn;
                block.Schedule = t.W;
                block.HOut = t.HOut;
                block.Rounds = new Sha256WalkRound[64];
                for (int r = 0; r < 64; r++)
                {
                    Sha256WalkRound round = new Sha256WalkRound();
                    round.T = r; round.K = k[r]; round.W = t.W[r]; round.T1 = t.T1[r]; round.T2 = t.T2[r]; round.State = t.Rounds[r];
                    block.Rounds[r] = round;
                }
                w.Blocks[b] = block;
            }

            IHash plain = Hashes.Sha256();
            plain.Update(message, 0, message.Length);
            Require(NetSec.Bytes.Hex.Encode(plain.Finish()) == NetSec.Bytes.Hex.Encode(digest) && NetSec.Bytes.Hex.Encode(digest) == Digests[i]);
            return w;
        }

        internal static void Require(bool holds)
        {
            if (!holds) throw new NetSecException(NetSecError.Of(ErrorCodes.Sha256WalkDiverged, "The walk differs from the real SHA-256 path."));
        }
    }
}
