using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace NetSec.Bench;

/// <summary>
/// The AO-5 rows, measured on the product the way the suite's own meter measures them (acceptance/groups/algo/AoAllocMeter.cs, as Echo
/// defined it): 300 warm-up calls, then 5 rounds of 400 calls, the lowest round kept, bytes from the runtime counter. When the op must
/// return a new array, the cost of <c>new byte[outLen]</c>, measured the same way, comes off. Result = (op - array) / 400 / units.
/// A row with two ops (encrypt and decrypt) takes the larger. The suite compares this record with its own as zero against not zero.
/// </summary>
static class AoAlloc
{
    const int Warm = 300, Rounds = 5, Calls = 400;
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;

    sealed class Row
    {
        public Row(string id, string op, int units, int outLen, params Action[] calls) { Id = id; Op = op; Units = units; OutLen = outLen; Calls = calls; }
        public string Id { get; }
        public string Op { get; }
        public int Units { get; }
        public int OutLen { get; }
        public Action[] Calls { get; }
    }

    static List<Row> Rows(IBlockCases c)
    {
        byte[] key16 = Cases.Filled(16, 0x10), key24 = Cases.Filled(24, 0x20), key32 = Cases.Filled(32, 0x30);
        byte[] message = Cases.Filled(Cases.MessageBytes, 0x40), zero16 = new byte[16], nonce = new byte[12], noAad = new byte[0];
        byte[] block = Cases.Filled(16, 0x80), output = new byte[16];
        int n = Cases.MessageBytes, blocks = n / 16;
        List<Row> rows = new List<Row>
        {
            new Row("aes-block", "one 16-byte AES-128 block, encrypt and decrypt, the larger", 1, 0, c.AesEncryptBlock(key16, block, output), c.AesDecryptBlock(key16, block, output)),
            new Row("aes-ecb", "1024-byte ECB encrypt, per block", blocks, n, c.Ecb(key16, message)),
            new Row("aes-cbc", "1024-byte CBC encrypt and decrypt, zero IV, the larger, per block", blocks, n, c.CbcEncrypt(key16, zero16, message), c.CbcDecrypt(key16, zero16, message)),
            new Row("aes-ctr", "1024-byte CTR, zero counter, per block", blocks, n, c.Ctr(key16, zero16, message)),
            new Row("aes-gcm", "1024-byte GCM seal, zero nonce, no AAD, per block", blocks, n + 16, c.GcmSeal(key16, nonce, noAad, message)),
            new Row("aes-cmac", "1024-byte CMAC, per block", blocks, 16, c.Cmac(key16, message)),
        };
        foreach (string h in Cases.HashNames)
            rows.Add(new Row(Stem(h), "Update of " + Cases.UpdateBlocks + " blocks on one state, per block", Cases.UpdateBlocks, 0, c.HashUpdate(h, Cases.UpdateBlocks)));
        foreach (string h in Cases.HashNames)
            rows.Add(new Row(Stem(h) + "-message", "factory, Update of 1024 bytes, Finish; every byte counts, per message", 1, 0, c.Hash(h, message)));
        rows.Add(new Row("hmac", "Hmac.Compute(SHA-256, 32-byte key, 1024 bytes), per message", 1, 32, c.HmacSha256(key32, message)));
        rows.Add(new Row("tdes", "one 8-byte TDES block, encrypt and decrypt, the larger", 1, 0, c.TdesEncryptBlock(key24, block, output), c.TdesDecryptBlock(key24, block, output)));
        rows.Add(new Row("dukpt-derive", "DukptBank.DeriveWorkingKey, counter 0x0F0F, PinEncryption, Aes128, per derivation", 1, 16, c.DukptDeriveWorkingKey(key16, Cases.Ksn)));
        return rows;
    }

    /// <summary>The AO-5 row stem of a hash name: sha3-256 is the keccak row.</summary>
    static string Stem(string hash) => hash == "sha3-256" ? "keccak" : hash;

    /// <summary>The AO-5 JSON rows for the product. Each line also goes to the console, so the run log carries the numbers.</summary>
    public static List<string> JsonRows(IBlockCases product)
    {
        List<string> json = new List<string>();
        foreach (Row r in Rows(product))
        {
            double array = r.OutLen == 0 ? 0 : Lowest(() => Cases.Sink = new byte[r.OutLen]);
            double bytes = r.Calls.Max(call => (Lowest(call) - array) / Calls / r.Units);
            Console.WriteLine(string.Format(Inv, "AO5 {0,-22} {1,10:F2} B per unit ({2})", r.Id, bytes, r.Op));
            json.Add(string.Format(Inv, "{{ \"id\": \"AO-5.{0}.net10\", \"bytesPerOp\": {1:F2}, \"op\": {2} }}", r.Id, bytes, Report.Quote(r.Op)));
        }
        return json;
    }

    /// <summary>Bytes allocated by <see cref="Calls"/> calls, the lowest of <see cref="Rounds"/> rounds, after <see cref="Warm"/> warm-up calls.</summary>
    static double Lowest(Action call)
    {
        for (int i = 0; i < Warm; i++) call();
        long best = long.MaxValue;
        for (int r = 0; r < Rounds; r++)
        {
            long before = Allocated.Now();
            for (int i = 0; i < Calls; i++) call();
            best = Math.Min(best, Allocated.Now() - before);
        }
        return best;
    }
}
