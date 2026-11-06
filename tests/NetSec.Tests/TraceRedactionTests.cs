using System.Security.Cryptography;
using NetSec.Bytes;
using NetSec.Platform;
using NetSec.Trace;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>The Show keys boundary: TraceRedaction.Hide on an event, and the JSON line it gives. Design section 6.4.</summary>
    public class TraceRedactionTests
    {
        static readonly byte[] KeyA = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        static readonly byte[] KeyB = { 0xAA, 0xBB, 0xCC };

        static TraceEvent Sample()
        {
            TraceStream s = new TraceStream("s1/client", "s1", "s1", null, "client", new FixedClock(42));
            return s.Stamp(new TraceEventDraft
            {
                Type = "tls.keys", Message = "keys made", Wire = new byte[] { 9, 9 }, Plain = new byte[] { 7 },
                Secrets = new[]
                {
                    new TraceSecret { Holder = "client", Name = "tls.client-hs", Bytes = KeyA },
                    new TraceSecret { Holder = "client", Name = "tls.master", Bytes = KeyB, DerivedFrom = new[] { "tls.client-hs" } },
                },
            });
        }

        static string Expected(byte[] key)
        {
            using (SHA256 sha = SHA256.Create()) return "fp:" + Hex.Encode(sha.ComputeHash(key)).Substring(0, 16).ToLowerInvariant();
        }

        [Fact]
        public void A_fingerprint_is_fp_and_the_first_8_bytes_of_sha256()
        {
            Assert.Equal(Expected(KeyA), TraceRedaction.Fingerprint(KeyA));
            Assert.NotEqual(TraceRedaction.Fingerprint(KeyA), TraceRedaction.Fingerprint(KeyB));
        }

        [Fact]
        public void Hide_drops_the_bytes_and_keeps_everything_else()
        {
            TraceEvent shown = Sample();
            TraceEvent hidden = TraceRedaction.Hide(shown);

            Assert.NotSame(shown, hidden);
            for (int i = 0; i < 2; i++)
            {
                Assert.Null(hidden.Secrets[i].Bytes);
                Assert.Equal("toggle", hidden.Secrets[i].Hidden);
                Assert.Equal(Expected(shown.Secrets[i].Bytes), hidden.Secrets[i].Fingerprint);
                Assert.Equal(shown.Secrets[i].Bytes.Length, hidden.Secrets[i].Length);
                Assert.Equal(shown.Secrets[i].Name, hidden.Secrets[i].Name);
                Assert.Equal(shown.Secrets[i].Holder, hidden.Secrets[i].Holder);
            }
            Assert.Equal(new[] { "tls.client-hs" }, hidden.Secrets[1].DerivedFrom);
            Assert.Equal(shown.EventId, hidden.EventId);
            Assert.Equal(shown.StreamSeq, hidden.StreamSeq);
            Assert.Equal(shown.Wire, hidden.Wire);
            Assert.Equal(shown.Plain, hidden.Plain);
            // The shown event is not changed: a fork still runs on the real bytes.
            Assert.Equal(KeyA, shown.Secrets[0].Bytes);
        }

        [Fact]
        public void Hide_keeps_a_non_exportable_marker()
        {
            TraceStream s = new TraceStream("s1/keys", "s1", "s1", null, "host", new FixedClock(1));
            TraceEvent e = s.Stamp(new TraceEventDraft { Type = "key.in-use", Secrets = new[] { new TraceSecret { Holder = "host", Name = "x", Fingerprint = "fp:0011223344556677", Length = 32, Hidden = "non-exportable" } } });
            TraceSecret after = TraceRedaction.Hide(e).Secrets[0];
            Assert.Equal("non-exportable", after.Hidden);
            Assert.Equal("fp:0011223344556677", after.Fingerprint);
        }

        [Fact]
        public void The_hidden_line_holds_fingerprint_length_and_hidden_and_no_hex()
        {
            string hidden = TraceJson.ToLine(TraceRedaction.Hide(Sample()));
            Assert.DoesNotContain("\"hex\"", hidden);
            Assert.Contains("\"fingerprint\":\"" + Expected(KeyA) + "\"", hidden);
            Assert.Contains("\"length\":16", hidden);
            Assert.Contains("\"hidden\":\"toggle\"", hidden);
            Assert.DoesNotContain(Hex.Encode(KeyA), hidden, System.StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void The_shown_line_is_as_before_so_the_golden_traces_hold()
        {
            string shown = TraceJson.ToLine(Sample());
            Assert.Contains("\"hex\":\"" + Hex.Encode(KeyA) + "\"", shown);
            Assert.DoesNotContain("\"fingerprint\"", shown);
            Assert.DoesNotContain("\"hidden\"", shown);
        }

        [Fact]
        public void A_key_use_writes_its_three_fields_at_the_top_of_the_event()
        {
            TraceStream s = new TraceStream("s1/keys", "s1", "s1", null, "host", new FixedClock(1));
            string line = TraceJson.ToLine(s.Stamp(new TraceEventDraft { Type = "key.in-use", KeyUse = new TraceKeyUse { TypeId = "token.issuer", Version = 2, Provider = "vault" } }));
            Assert.Contains("\"typeId\":\"token.issuer\"", line);
            Assert.Contains("\"version\":2", line);
            Assert.Contains("\"provider\":\"vault\"", line);
        }
    }
}
