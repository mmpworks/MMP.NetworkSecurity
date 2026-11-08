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
    /// The DES walk. Referees: the NIST CAVP known answers in acceptance/vectors/tdes-cavp.nsv (each row uses one DES key three times, which is
    /// single DES), and the BCL's own DES for varkey and subtab. The BCL refuses weak keys, and vartext's key 0101010101010101 is one, so that row
    /// rests on the CAVP value. Each round is also checked against the Feistel rule and each S-box lookup against its 6 bits.
    /// </summary>
    public class DesWalksTests
    {
        static Dictionary<string, Dictionary<string, string>> FirstRows()
        {
            string dir = AppContext.BaseDirectory;
            while (dir != null && !File.Exists(Path.Combine(dir, "acceptance", "vectors", "tdes-cavp.nsv"))) dir = Path.GetDirectoryName(dir);
            Assert.True(dir != null, "acceptance/vectors/tdes-cavp.nsv was not found above the test folder");
            var rows = new Dictionary<string, Dictionary<string, string>>();
            string section = null, cur = null;
            foreach (string raw in File.ReadAllLines(Path.Combine(dir, "acceptance", "vectors", "tdes-cavp.nsv")))
            {
                string line = raw.Trim();
                if (line.StartsWith("[")) { section = line; continue; }
                if (section != "[tdes-ecb-encrypt-kat]" || line.StartsWith("#") || !line.Contains("=")) continue;
                string k = line.Substring(0, line.IndexOf('=')).Trim(), v = line.Substring(line.IndexOf('=') + 1).Trim();
                if (k == "file") { cur = rows.ContainsKey(v) ? null : v; if (cur != null) rows[cur] = new Dictionary<string, string>(); }
                else if (cur != null) rows[cur][k] = v;
            }
            return rows;
        }

        static string FileOf(string name) => name switch { "varkey" => "TECBvarkey", "vartext" => "TECBvartext", _ => "TECBsubtab" };

        [Theory]
        [InlineData("varkey")]
        [InlineData("vartext")]
        [InlineData("subtab")]
        public void The_walk_runs_the_cavp_known_answer(string name)
        {
            Dictionary<string, string> row = FirstRows()[FileOf(name)];
            DesWalk w = DesWalks.Known(name);
            Assert.Equal(row["key"].Substring(0, 16), Hex.Encode(w.Key));
            Assert.Equal(row["plaintext"], Hex.Encode(w.Plaintext));
            Assert.Equal(row["ciphertext"], Hex.Encode(w.Ciphertext));
        }

        [Theory]
        [InlineData("varkey")]
        [InlineData("subtab")]
        public void The_bcl_des_gives_the_same_ciphertext(string name)
        {
            DesWalk w = DesWalks.Known(name);
            using DES des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            des.Key = w.Key;
            using ICryptoTransform enc = des.CreateEncryptor();
            Assert.Equal(Hex.Encode(w.Ciphertext), Hex.Encode(enc.TransformFinalBlock(w.Plaintext, 0, 8)));
        }

        [Theory]
        [InlineData("varkey")]
        [InlineData("vartext")]
        [InlineData("subtab")]
        public void Each_round_follows_the_feistel_rule_and_each_box_reads_its_six_bits(string name)
        {
            DesWalk w = DesWalks.Known(name);
            Assert.Equal(16, w.Rounds.Length);
            Assert.Equal((uint)(w.Permuted >> 32), w.Rounds[0].LeftIn);
            Assert.Equal((uint)w.Permuted, w.Rounds[0].RightIn);
            for (int r = 0; r < 16; r++)
            {
                DesWalkRound round = w.Rounds[r];
                Assert.Equal(r + 1, round.Round);
                Assert.Equal(w.RoundKeys[r], round.RoundKey);
                Assert.Equal(round.Expanded ^ round.RoundKey, round.Mixed);
                Assert.Equal(round.RightIn, round.LeftOut);
                Assert.Equal(round.LeftIn ^ round.F, round.RightOut);
                if (r > 0) { Assert.Equal(w.Rounds[r - 1].LeftOut, round.LeftIn); Assert.Equal(w.Rounds[r - 1].RightOut, round.RightIn); }
                uint boxesOut = 0;
                for (int b = 0; b < 8; b++)
                {
                    DesWalkBox box = round.Boxes[b];
                    Assert.Equal((int)(round.Mixed >> (42 - 6 * b)) & 63, box.Six);
                    Assert.Equal(((box.Six >> 4) & 2) | (box.Six & 1), box.Row);
                    Assert.Equal((box.Six >> 1) & 15, box.Column);
                    Assert.InRange(box.Out, 0, 15);
                    boxesOut = (boxesOut << 4) | (uint)box.Out;
                }
                Assert.Equal(boxesOut, round.BoxesOut);
            }
            Assert.Equal(((ulong)w.Rounds[15].RightOut << 32) | w.Rounds[15].LeftOut, w.PreOutput);
            Assert.Equal(w.Output, BitConverter.ToUInt64(w.Ciphertext.Reverse().ToArray(), 0));
            Assert.All(w.C, c => Assert.True(c < (1u << 28)));
            Assert.All(w.D, d => Assert.True(d < (1u << 28)));
        }

        [Fact]
        public void An_unknown_name_is_refused_and_the_guard_names_its_code()
        {
            Assert.Throws<ArgumentException>(() => DesWalks.Known("other"));
            NetSecException e = Assert.Throws<NetSecException>(() => DesWalks.Require(false));
            Assert.Equal(ErrorCodes.DesWalkDiverged, e.Error.Code);
        }
    }
}
