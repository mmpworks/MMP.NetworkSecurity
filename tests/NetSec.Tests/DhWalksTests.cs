using System;
using System.IO;
using System.Linq;
using System.Numerics;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// Slice P7's Diffie-Hellman walk. The referee is System.Numerics.BigInteger.ModPow, which shares no code with BigUInt. Group 14's prime is
    /// read from acceptance/vectors/dh-group14-rfc3526.nsv (RFC 3526 section 3), not from DhGroup14.
    /// </summary>
    public class DhWalksTests
    {
        static BigInteger Num(byte[] bigEndian) { return new BigInteger(bigEndian.Reverse().Concat(new byte[] { 0 }).ToArray()); }

        static BigInteger Rfc3526Prime()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "dh-group14-rfc3526.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/dh-group14-rfc3526.nsv was not found above the test folder");
            string line = File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "dh-group14-rfc3526.nsv")).Select(l => l.Trim()).First(l => l.StartsWith("p ="));
            return Num(Hex.Decode(line.Substring(line.IndexOf('=') + 1).Trim()));
        }

        /// <summary>Every row is the square, then the multiply on a 1 bit, of the row before; the rows cover each exponent bit; the result is pow().</summary>
        static void CheckPow(DhPowWalk w, BigInteger p)
        {
            BigInteger b = Num(w.Base), e = Num(w.Exponent), acc = BigInteger.One;
            Assert.Equal(e.IsZero ? 0 : (int)Math.Floor(BigInteger.Log(e, 2)) + 1, w.Rows.Length);
            foreach (DhPowRow row in w.Rows)
            {
                acc = acc * acc % p;
                Assert.Equal(acc, Num(row.AfterSquare));
                Assert.Equal(((e >> row.Bit) & 1) == 1, row.IsOne);
                if (row.IsOne) { acc = acc * b % p; Assert.Equal(acc, Num(row.AfterMultiply)); }
                else Assert.Null(row.AfterMultiply);
            }
            Assert.Equal(BigInteger.ModPow(b, e, p), Num(w.Result));
        }

        [Fact]
        public void The_small_exchange_gives_the_numbers_a_reader_can_check_by_hand()
        {
            DhWalk w = DhWalks.Small();
            BigInteger p = 467, g = 5;
            Assert.Equal(p, Num(w.Prime));
            Assert.Equal(g, Num(w.Generator));
            Assert.Equal(116, (int)Num(w.Client.Public.Result));
            Assert.Equal(429, (int)Num(w.Server.Public.Result));
            Assert.Equal(412, (int)Num(w.Client.Shared.Result));
            Assert.Equal(412, (int)Num(w.Server.Shared.Result));
            Assert.Equal(BigInteger.ModPow(g, 153, p), Num(w.Client.Public.Result));
            Assert.Equal(BigInteger.ModPow(BigInteger.ModPow(g, 197, p), 153, p), Num(w.Client.Shared.Result));
            foreach (DhPowWalk pow in new[] { w.Client.Public, w.Server.Public, w.Client.Shared, w.Server.Shared }) CheckPow(pow, p);
        }

        [Fact]
        public void Group_14_matches_pow_on_the_rfc_3526_prime_and_the_engine_lesson_8_runs()
        {
            DhWalk w = DhWalks.Group14();
            BigInteger p = Rfc3526Prime();
            Assert.Equal(p, Num(w.Prime));
            Assert.Equal(new BigInteger(2), Num(w.Generator));
            byte[] a = w.Client.Private, b = w.Server.Private;
            Assert.Equal(BigInteger.ModPow(2, Num(a), p), Num(w.Client.Public.Result));
            Assert.Equal(BigInteger.ModPow(2, Num(b), p), Num(w.Server.Public.Result));
            Assert.Equal(BigInteger.ModPow(2, Num(a) * Num(b), p), Num(w.Client.Shared.Result));
            Assert.Equal(Num(w.Client.Shared.Result), Num(w.Server.Shared.Result));
            // The live tie-in: DhGroup14 is what lesson 8's legacy exchange calls (SshClientRules and SshServerRules).
            Assert.Equal(Num(DhGroup14.Public(a)), Num(w.Client.Public.Result));
            Assert.Equal(Num(DhGroup14.Shared(a, DhGroup14.Public(b))), Num(w.Client.Shared.Result));
            foreach (DhPowWalk pow in new[] { w.Client.Public, w.Server.Public, w.Client.Shared, w.Server.Shared }) CheckPow(pow, p);
            Assert.Equal(32, w.Client.Public.Rows.Length);
        }

        [Fact]
        public void The_practice_exponents_are_fixed_32_bit_values_with_the_top_bit_set()
        {
            byte[] a = DhWalks.PracticeExponent("client"), b = DhWalks.PracticeExponent("server");
            Assert.Equal(4, a.Length);
            Assert.True((a[0] & 0x80) != 0 && (b[0] & 0x80) != 0);
            Assert.Equal(a, DhWalks.PracticeExponent("client"));
            Assert.NotEqual(a, b);
        }

        [Fact]
        public void The_guard_names_its_code()
        {
            NetSecException e = Assert.Throws<NetSecException>(() => DhWalks.RequireSame(new byte[] { 1 }, new byte[] { 2 }));
            Assert.Equal(ErrorCodes.DhWalkDiverged, e.Error.Code);
        }
    }
}
