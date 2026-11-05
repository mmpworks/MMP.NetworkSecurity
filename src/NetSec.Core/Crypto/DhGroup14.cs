using System;
using NetSec.Bytes;
using NetSec.Errors;

namespace NetSec.Crypto
{
    /// <summary>Diffie-Hellman over the 2048-bit MODP group of RFC 3526 section 3. SSH legacy mode uses it. Generator 2.</summary>
    public static class DhGroup14
    {
        const int Length = 256;

        static readonly BigUInt P = BigUInt.FromBytes(Hex.Decode(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74" +
            "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437" +
            "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05" +
            "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB" +
            "9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
            "3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"));

        static readonly BigUInt Generator = BigUInt.FromUInt32(2);
        static readonly BigUInt Two = BigUInt.FromUInt32(2);

        /// <summary>2^x mod p, as 256 big-endian bytes.</summary>
        public static byte[] Public(byte[] x)
        {
            if (x == null) throw new ArgumentNullException("x");
            return Generator.ModPow(BigUInt.FromBytes(x), P).ToBigEndian(Length);
        }

        /// <summary>
        /// peer^x mod p, as 256 big-endian bytes. A peer value outside [2, p-2] gives a result that an attacker can
        /// predict (0, 1 or p-1), so it throws DH_PEER_OUT_OF_RANGE.
        /// </summary>
        public static byte[] Shared(byte[] x, byte[] peer)
        {
            if (x == null) throw new ArgumentNullException("x");
            if (peer == null) throw new ArgumentNullException("peer");
            BigUInt y = BigUInt.FromBytes(peer);
            if (y.CompareTo(Two) < 0 || y.CompareTo(P.Subtract(Two)) > 0)
                throw new NetSecException(NetSecError.Of(ErrorCodes.DhPeerOutOfRange, "the DH peer value is outside [2, p-2]"));
            return y.ModPow(BigUInt.FromBytes(x), P).ToBigEndian(Length);
        }
    }
}
