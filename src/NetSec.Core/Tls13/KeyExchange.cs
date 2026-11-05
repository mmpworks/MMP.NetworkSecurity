using System;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Tls13
{
    /// <summary>What the client holds between its ClientHello and the ServerHello.</summary>
    public sealed class KeyShareOffer
    {
        public byte[] Share, X25519Private, MlKemDk;
    }

    /// <summary>The shared secret and the parts it came from, so the trace can show each part.</summary>
    public sealed class KexOutcome
    {
        public byte[] ServerShare, Shared, X25519Part, MlKemPart;
    }

    /// <summary>
    /// X25519 and the hybrid of RFC 10024, code point 0x11EC. The hybrid puts ML-KEM first in each share and in the secret:
    /// client share = ek (1184) + X25519 public (32). Server share = ciphertext (1088) + X25519 public (32). Secret = 32 + 32.
    /// A malformed share throws ParseFailure, and the engine turns that into a named check.
    /// </summary>
    public static class KeyExchange
    {
        const int X25519Size = 32;
        const int MlKemEkSize = 1184;
        const int MlKemCiphertextSize = 1088;

        public static KeyShareOffer Offer(Tls13Group group, IRandomSource random)
        {
            KeyShareOffer offer = new KeyShareOffer();
            offer.X25519Private = Draw(random, X25519Size);
            byte[] x25519Public = X25519.MultBase(offer.X25519Private);
            if (group == Tls13Group.X25519)
            {
                offer.Share = x25519Public;
                return offer;
            }
            MlKemPair pair = MlKem768.KeyGen(Draw(random, 32), Draw(random, 32));
            offer.MlKemDk = pair.Dk;
            offer.Share = new ByteWriter().Put(pair.Ek).Put(x25519Public).ToArray();
            return offer;
        }

        /// <summary>The server side: answers a client share and computes the secret.</summary>
        public static KexOutcome Respond(Tls13Group group, byte[] clientShare, IRandomSource random)
        {
            byte[] serverPrivate = Draw(random, X25519Size);
            byte[] serverPublic = X25519.MultBase(serverPrivate);
            KexOutcome outcome = new KexOutcome();
            if (group == Tls13Group.X25519)
            {
                NeedLength(clientShare, X25519Size);
                outcome.X25519Part = SharedX25519(serverPrivate, clientShare);
                outcome.Shared = outcome.X25519Part;
                outcome.ServerShare = serverPublic;
                return outcome;
            }
            NeedLength(clientShare, MlKemEkSize + X25519Size);
            MlKemSealed sealedKey = EncapsOrFail(Slice(clientShare, 0, MlKemEkSize), Draw(random, 32));
            outcome.MlKemPart = sealedKey.SharedSecret;
            outcome.X25519Part = SharedX25519(serverPrivate, Slice(clientShare, MlKemEkSize, X25519Size));
            outcome.Shared = new ByteWriter().Put(outcome.MlKemPart).Put(outcome.X25519Part).ToArray();
            outcome.ServerShare = new ByteWriter().Put(sealedKey.Ciphertext).Put(serverPublic).ToArray();
            return outcome;
        }

        /// <summary>The client side: finishes with the server share. A bad ML-KEM ciphertext gives a wrong secret and no error (implicit rejection).</summary>
        public static KexOutcome Finish(Tls13Group group, KeyShareOffer offer, byte[] serverShare)
        {
            KexOutcome outcome = new KexOutcome();
            outcome.ServerShare = serverShare;
            if (group == Tls13Group.X25519)
            {
                NeedLength(serverShare, X25519Size);
                outcome.X25519Part = SharedX25519(offer.X25519Private, serverShare);
                outcome.Shared = outcome.X25519Part;
                return outcome;
            }
            NeedLength(serverShare, MlKemCiphertextSize + X25519Size);
            outcome.MlKemPart = MlKem768.Decaps(offer.MlKemDk, Slice(serverShare, 0, MlKemCiphertextSize));
            outcome.X25519Part = SharedX25519(offer.X25519Private, Slice(serverShare, MlKemCiphertextSize, X25519Size));
            outcome.Shared = new ByteWriter().Put(outcome.MlKemPart).Put(outcome.X25519Part).ToArray();
            return outcome;
        }

        /// <summary>RFC 8446 section 7.4.2: a small-order peer point gives all zeros, and the peer then controls the secret. X25519.Mult leaves this check to the protocol.</summary>
        static byte[] SharedX25519(byte[] secret, byte[] peer)
        {
            byte[] shared = X25519.Mult(secret, peer);
            int seen = 0;
            for (int i = 0; i < shared.Length; i++) seen |= shared[i];
            if (seen == 0) throw new ParseFailure(Tls13Codes.X25519Zero, "the X25519 result is all zeros, so the peer sent a small-order point");
            return shared;
        }

        static MlKemSealed EncapsOrFail(byte[] ek, byte[] m)
        {
            try { return MlKem768.Encaps(ek, m); }
            catch (NetSecException e) { throw new ParseFailure(Tls13Codes.KeyShareInvalid, e.Error.Message); }
        }

        static void NeedLength(byte[] share, int length)
        {
            if (share.Length != length)
                throw new ParseFailure(Tls13Codes.KeyShareInvalid, "the key share has " + share.Length + " bytes and the group needs " + length);
        }

        static byte[] Draw(IRandomSource random, int n)
        {
            byte[] bytes = new byte[n];
            random.Fill(bytes, 0, n);
            return bytes;
        }

        static byte[] Slice(byte[] bytes, int off, int n)
        {
            byte[] part = new byte[n];
            Buffer.BlockCopy(bytes, off, part, 0, n);
            return part;
        }
    }
}
