using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Labs;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// The HMAC walk. Referees: RFC 4231 section 4's published MACs, read from acceptance/vectors/hmac-rfc4231.nsv, and every step recomputed here
    /// with the BCL's SHA256 and HMACSHA256, which share no code with the engine's hash.
    /// </summary>
    public class HmacWalksTests
    {
        static Dictionary<string, Dictionary<string, string>> Cases()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "hmac-rfc4231.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/hmac-rfc4231.nsv was not found above the test folder");
            var cases = new Dictionary<string, Dictionary<string, string>>();
            string section = null, cur = null;
            foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "hmac-rfc4231.nsv")))
            {
                string line = raw.Trim();
                if (line.StartsWith("[")) { section = line; continue; }
                if (section != "[hmac-sha256]" || line.StartsWith("#") || !line.Contains("=")) continue;
                string k = line.Substring(0, line.IndexOf('=')).Trim(), v = line.Substring(line.IndexOf('=') + 1).Trim();
                if (k == "case") cases[cur = v] = new Dictionary<string, string>();
                else if (cur != null) cases[cur][k] = v;
            }
            return cases;
        }

        static byte[] Sha256(params byte[][] parts) { using SHA256 h = SHA256.Create(); return h.ComputeHash(parts.SelectMany(p => p).ToArray()); }

        [Theory]
        [InlineData("1")]
        [InlineData("2")]
        [InlineData("3")]
        [InlineData("4")]
        [InlineData("6")]
        [InlineData("7")]
        public void Each_step_matches_rfc_4231_and_the_bcl(string testCase)
        {
            Dictionary<string, string> v = Cases()[testCase];
            HmacWalk w = HmacWalks.Rfc4231(testCase);
            Assert.Equal(v["key"], Hex.Encode(w.Key));
            Assert.Equal(v["data"], Hex.Encode(w.Message));
            Assert.Equal(v["mac"], Hex.Encode(w.Mac));
            using (HMACSHA256 bcl = new HMACSHA256(w.Key)) Assert.Equal(Hex.Encode(bcl.ComputeHash(w.Message)), Hex.Encode(w.Mac));

            byte[] used = w.Key.Length > 64 ? Sha256(w.Key) : w.Key;
            Assert.Equal(w.Key.Length > 64, w.KeyHashed);
            Assert.Equal(Hex.Encode(used), Hex.Encode(w.KeyUsed));
            byte[] padded = used.Concat(new byte[64 - used.Length]).ToArray();
            Assert.Equal(Hex.Encode(padded), Hex.Encode(w.PaddedKey));
            byte[] ipad = padded.Select(b => (byte)(b ^ 0x36)).ToArray(), opad = padded.Select(b => (byte)(b ^ 0x5c)).ToArray();
            Assert.Equal(Hex.Encode(ipad), Hex.Encode(w.InnerPad));
            Assert.Equal(Hex.Encode(opad), Hex.Encode(w.OuterPad));
            byte[] inner = Sha256(ipad, w.Message);
            Assert.Equal(Hex.Encode(inner), Hex.Encode(w.InnerDigest));
            Assert.Equal(Hex.Encode(Sha256(opad, inner)), Hex.Encode(w.Mac));
        }

        [Fact]
        public void Case_5_is_left_out_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => HmacWalks.Rfc4231("5"));
            NetSecException e = Assert.Throws<NetSecException>(() => HmacWalks.Require(false));
            Assert.Equal(ErrorCodes.HmacWalkDiverged, e.Error.Code);
        }
    }
}
