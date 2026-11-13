using System;
using System.Linq;
using NetSec.Tls13;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// RecordProtection holds one GcmKey and one nonce buffer that every record uses again (PRD 7.3 item 15), so its contract is one
    /// direction, one thread at a time. These tests hold that contract: an overlapping call is refused before it touches the nonce or the
    /// count, and records sealed through the shared buffer still open in order.
    /// </summary>
    public class RecordProtectionContractTests
    {
        static readonly byte[] Key = Enumerable.Range(1, 16).Select(i => (byte)i).ToArray();
        static readonly byte[] Iv = Enumerable.Range(40, 12).Select(i => (byte)i).ToArray();

        [Fact]
        public void A_call_while_another_runs_is_refused_and_moves_no_count()
        {
            RecordProtection seal = new RecordProtection(Key, Iv);
            seal.Enter();   // stands in for a call already running on another thread
            try
            {
                Assert.Throws<InvalidOperationException>(() => seal.Seal(ContentType.ApplicationData, new byte[] { 1, 2, 3 }, 0, 3));
                int type;
                byte[] content;
                Assert.Throws<InvalidOperationException>(() => seal.TryOpen(new byte[5], new byte[17], out type, out content));
                Assert.Equal(0, seal.Count);
            }
            finally
            {
                seal.Exit();
            }

            // Once the running call is gone, the same object works, and its first record still uses count 0.
            RecordProtection open = new RecordProtection(Key, Iv);
            byte[] record = seal.Seal(ContentType.ApplicationData, new byte[] { 1, 2, 3 }, 0, 3);
            Assert.True(Open(open, record, out int got, out byte[] plain));
            Assert.Equal(ContentType.ApplicationData, got);
            Assert.Equal(new byte[] { 1, 2, 3 }, plain);
        }

        [Fact]
        public void Records_sealed_through_the_one_nonce_buffer_open_in_order()
        {
            RecordProtection seal = new RecordProtection(Key, Iv), open = new RecordProtection(Key, Iv);
            for (int i = 0; i < 40; i++)
            {
                byte[] message = Enumerable.Range(0, i * 7 + 1).Select(b => (byte)(b ^ i)).ToArray();
                byte[] record = seal.Seal(ContentType.Handshake, message, 0, message.Length);
                Assert.True(Open(open, record, out int type, out byte[] plain), "record " + i + " did not open");
                Assert.Equal(ContentType.Handshake, type);
                Assert.Equal(message, plain);
            }
            Assert.Equal(40, seal.Count);
            Assert.Equal(40, open.Count);
        }

        static bool Open(RecordProtection p, byte[] record, out int type, out byte[] content)
        {
            return p.TryOpen(record.Take(5).ToArray(), record.Skip(5).ToArray(), out type, out content);
        }
    }
}
