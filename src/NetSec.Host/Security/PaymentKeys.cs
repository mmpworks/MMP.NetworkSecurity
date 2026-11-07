using System.Security.Cryptography;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Platform;

namespace NetSec.Host.Security;

/// <summary>
/// The my-payment flow's own code. No outside tool can judge a DUKPT base key, so the check runs the code the lessons run on the
/// published X9.24-3 vector, then does a PIN pad to bank round trip under the learner's key (modes-design.md section 8).
/// </summary>
public static class PaymentKeys
{
    const int BaseKeyBytes = 16, ShortCheckBytes = 3, LongCheckBytes = 5;
    const string Pin = "1234", Pan = "4111111111111111";

    // X9.24-3-2017 supplement, section 2.2, AES-128 from an AES-128 base key, counter 1. acceptance/vectors holds the full set.
    const string PublishedBaseKey = "fedcba9876543210f1f1f1f1f1f1f1f1", PublishedKeyId = "1234567890123456";
    const string PublishedInitialKey = "1273671ea26ac29afa4d1084127652a1", PublishedPinKey = "af8cb133a78f8dc2d1359f18527593fb";

    /// <summary>Reads a text file holding one test base key as 32 hex characters. A check value, when given, must match it.</summary>
    public static byte[] ReadBaseKey(string path, string? checkValue)
    {
        byte[] key = Parse(ReadText(path));
        if (checkValue is not null && !MatchesCheckValue(key, checkValue))
            throw new NetSecException(NetSecError.Of(ErrorCodes.DukptKcvMismatch, "The key in this file does not match the check value you gave."));
        return key;
    }

    static string ReadText(string path)
    {
        try { return File.ReadAllText(path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new NetSecException(NetSecError.Of(ErrorCodes.KeyFileUnreadable, "The course cannot read this file."));
        }
    }

    static byte[] Parse(string text)
    {
        byte[] key;
        try { key = Convert.FromHexString(text.Trim()); }
        catch (FormatException) { throw new NetSecException(NetSecError.Of(ErrorCodes.KeyFileFormat, "This file must hold one key as hex characters and nothing else.")); }
        if (key.Length != BaseKeyBytes) throw new NetSecException(NetSecError.Of(ErrorCodes.DukptKeySize, $"A test base key is {BaseKeyBytes} bytes, because the lessons use AES-128. This file holds {key.Length}."));
        return key;
    }

    /// <summary>A vendor prints one of 2 forms: AES over a zero block, or CMAC over a zero block. Its first 3 or 5 bytes, as hex.</summary>
    public static bool MatchesCheckValue(byte[] key, string checkValue)
    {
        string given = checkValue.Trim().ToLowerInvariant();
        byte[] zeros = new byte[BaseKeyBytes];
        string cmac = Convert.ToHexString(Cmac.Compute(new AesKey(key), zeros)).ToLowerInvariant();
        using Aes aes = Aes.Create();
        aes.Key = key;
        string block = Convert.ToHexString(aes.EncryptEcb(zeros, PaddingMode.None)).ToLowerInvariant();
        return given == block[..(ShortCheckBytes * 2)] || given == cmac[..(ShortCheckBytes * 2)] || given == cmac[..(LongCheckBytes * 2)];
    }

    public static CheckFact Check(string typeId, byte[] baseKey)
    {
        int published = PublishedValuesEqual();
        bool controlDiffers = PublishedControlDiffers();
        bool roundTrip = OpensAtTheBank(baseKey, baseKey);
        bool otherKeyRefused = !OpensAtTheBank(baseKey, Flipped(baseKey));
        bool passed = published == 2 && controlDiffers && roundTrip && otherKeyRefused;
        string output = $"Published X9.24-3 vector: {published} of 2 values equal. One changed bit in the base key: {(controlDiffers ? "the values differ" : "the values stay equal")}. "
            + $"A PIN locked at the pad under this key: {(roundTrip ? "opens at the bank" : "does not open")}. Under another base key: {(otherKeyRefused ? "does not open" : "opens")}.";
        return new CheckFact(typeId, FlowParts.JudgeNone, FlowParts.SaysNoOutsideJudge, "", output, passed, passed ? null : "CHECK_FAILED", passed ? null : "This key does not work in the course's DUKPT code.");
    }

    static int PublishedValuesEqual()
    {
        byte[] bdk = Hex.Decode(PublishedBaseKey), id = Hex.Decode(PublishedKeyId);
        int equal = Hex.Encode(DukptBank.DeriveInitialKey(bdk, id)) == PublishedInitialKey ? 1 : 0;
        return equal + (Hex.Encode(DukptBank.DeriveWorkingKey(bdk, FirstKsn(id), DukptKeyUsage.PinEncryption, DukptKeyType.Aes128)) == PublishedPinKey ? 1 : 0);
    }

    static bool PublishedControlDiffers() =>
        Hex.Encode(DukptBank.DeriveInitialKey(Flipped(Hex.Decode(PublishedBaseKey)), Hex.Decode(PublishedKeyId))) != PublishedInitialKey;

    static byte[] FirstKsn(byte[] id)
    {
        byte[] ksn = new byte[id.Length + 4];
        id.CopyTo(ksn, 0);
        ksn[^1] = 1;
        return ksn;
    }

    static byte[] Flipped(byte[] key)
    {
        byte[] other = (byte[])key.Clone();
        other[0] ^= 1;
        return other;
    }

    static bool OpensAtTheBank(byte[] padBase, byte[] bankBase)
    {
        DukptPinPad pad = new(PinPadCore.InitialKeyUnder(padBase), Hex.Decode(PinPadCore.InjectedKeyId));
        DukptUse use = pad.Next(DukptKeyUsage.PinEncryption, DukptKeyType.Aes128);
        byte[] fill = new byte[8];
        new OsRandom().Fill(fill, 0, fill.Length);
        byte[] block = PinBlock.EncryptFormat4(use.Key, Pin, Pan, fill);
        byte[] bankKey = DukptBank.DeriveWorkingKey(bankBase, use.Ksn, DukptKeyUsage.PinEncryption, DukptKeyType.Aes128);
        return PinBlock.TryDecryptFormat4(bankKey, block, Pan, out string opened) && opened == Pin;
    }
}
