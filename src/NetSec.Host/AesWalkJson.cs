using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Labs;

namespace NetSec.Host;

/// <summary>The walk's reply shapes (docs/walkthrough-design.md section 3.4). Bytes go out as lowercase hex, and an unused cell as null.</summary>
public static class AesWalkJson
{
    static string? Bytes(byte[]? b) => b is null ? null : Hex.Encode(b);
    static string Byte(byte b) => b.ToString("x2");
    static string[] Each(byte[] b) => b.Select(Byte).ToArray();

    static object Doubling(AesDoubling d) => new { from = Byte(d.From), shifted = d.Shifted.ToString("x3"), reduced = d.Reduced, to = Byte(d.To) };

    static object Term(AesTerm t) => new
    {
        factor = t.Factor,
        input = Byte(t.Input),
        doublings = t.Doublings.Select(Doubling).ToArray(),
        picks = Each(t.Picks),
        sums = Each(t.Sums),
        reduced = t.Reduced,
        result = Byte(t.Result),
    };

    static object MixedByte(AesColumnByte b) => new { result = Byte(b.Result), running = Each(b.Running), parts = b.Terms.Select(Term).ToArray() };

    static object Step(AesStep s) => new
    {
        kind = s.Kind.ToString(),
        round = s.Round,
        state = Bytes(s.State),
        roundKey = Bytes(s.RoundKey),
        terms = s.Terms?.Select(MixedByte).ToArray(),
    };

    static object Walk(AesBlockWalk w) => new { input = Bytes(w.Input), output = Bytes(w.Output), steps = w.Steps.Select(Step).ToArray() };

    static object Word(AesKeyWord w) => new
    {
        i = w.Index,
        divisor = w.Divisor,
        quotient = w.Quotient,
        remainder = w.Remainder,
        previous = Bytes(w.Previous),
        rotated = Bytes(w.Rotated),
        substituted = Bytes(w.Substituted),
        rcon = Bytes(w.Rcon),
        afterRcon = Bytes(w.AfterRcon),
        keyBack = Bytes(w.KeyBack),
        word = Bytes(w.Word),
    };

    public static object Block(string source, string keySource, AesBlockPair pair, string wireStatus, string wireMessage) => new
    {
        source,
        keyBits = pair.KeyBits,
        rounds = pair.Forward.Rounds,
        keySource,
        inputHex = Bytes(pair.Forward.Input),
        keyWords = pair.KeyWords.Select(Word).ToArray(),
        forward = Walk(pair.Forward),
        inverse = pair.Inverse is null ? null : Walk(pair.Inverse),
        wire = new { status = wireStatus, message = wireMessage },
    };

    /// <summary>Chapter 1 on a typed block: the walk under the public practice key, and how the text was cut into the block.</summary>
    public static object TypedBlock(AesTypedBlock typed, AesBlockPair pair) => new
    {
        walk = Block("typed", "typed-practice", pair, "notSent", "TextEcb"),
        cut = new
        {
            block = Bytes(typed.Block),
            usedBytes = typed.UsedBytes,
            paddingBytes = typed.PaddingBytes,
            notIncludedBytes = typed.NotIncludedBytes,
            splitCharacterBytesIn = typed.SplitCharacterBytesIn,
        },
    };

    static object LongRow(AesLongTextRow r) => new
    {
        block = r.Block,
        data = Bytes(r.Data),
        ecb = Bytes(r.Ecb),
        cbc = Bytes(r.Cbc),
        ecbRepeat = r.EcbRepeat,
        cbcRepeat = r.CbcRepeat,
        ecbBitsChanged = r.EcbBitsChanged,
        cbcBitsChanged = r.CbcBitsChanged,
    };

    /// <summary>The longer text under the practice key and IV, ECB beside CBC. keySource names the key, so a reader never takes it for a run's key.</summary>
    public static object LongText(AesLongTextView v) => new
    {
        keySource = "typed-practice",
        blocks = v.Rows.Length,
        ecbRepeats = v.EcbRepeats,
        cbcRepeats = v.CbcRepeats,
        rows = v.Rows.Select(LongRow).ToArray(),
        flipped = v.FlippedRows is null ? null : new
        {
            ecbBlocksChanged = v.EcbBlocksChanged,
            cbcBlocksChanged = v.CbcBlocksChanged,
            rows = v.FlippedRows.Select(LongRow).ToArray(),
        },
    };

    /// <summary>The size table comes from a walk of an all-zero key at each size, so its numbers are the engine's own.</summary>
    static object Size(int keyBytes)
    {
        AesKeyWord[] rows = new AesKey(new byte[keyBytes]).WalkKeyExpansion();
        return new
        {
            keyBits = keyBytes * 8,
            keyWords = keyBytes / 4,
            rounds = rows.Length / 4 - 1,
            roundKeys = rows.Length / 4,
            words = rows.Length,
            rconUsed = rows.Count(r => r.Rcon is not null),
        };
    }

    public static object Tables()
    {
        const int RoundConstants = 10;
        return new
        {
            sbox = Bytes(AesKey.SubstitutionTable()),
            inverseSbox = Bytes(AesKey.InverseSubstitutionTable()),
            shiftRows = AesKey.ShiftMap(false),
            inverseShiftRows = AesKey.ShiftMap(true),
            rcon = Bytes(AesKey.RoundConstants(RoundConstants)),
            rconSteps = AesKey.RoundConstantSteps(RoundConstants).Select(Doubling).ToArray(),
            sizes = new[] { 16, 24, 32 }.Select(Size).ToArray(),
        };
    }
}
