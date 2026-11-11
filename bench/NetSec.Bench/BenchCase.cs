using System;

namespace NetSec.Bench;

/// <summary>
/// One thing to time. <see cref="Op"/> does one operation; an operation covers <see cref="UnitsPerOp"/> units of <see cref="Unit"/>
/// (a 16-byte AES block, an 8-byte DES block, a hash block, one key setup, one derivation) and <see cref="BytesPerOp"/> payload bytes.
/// Each case owns its buffers, made once before timing, so the numbers show what the product path costs and nothing the bench adds.
/// </summary>
sealed class BenchCase
{
    public BenchCase(string id, string unit, int unitsPerOp, int bytesPerOp, Action op)
    {
        Id = id;
        Unit = unit;
        UnitsPerOp = unitsPerOp;
        BytesPerOp = bytesPerOp;
        Op = op;
    }

    public string Id { get; }
    public string Unit { get; }
    public int UnitsPerOp { get; }
    public int BytesPerOp { get; }
    public Action Op { get; }
}
