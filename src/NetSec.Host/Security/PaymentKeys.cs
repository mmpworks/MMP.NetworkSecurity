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

    /// <summary>
    /// Reads a text file holding one test base key as 32 hex characters. A check value, when given, must match it, and matched names the form it
    /// matched. A blank check value is no value.
    /// </summary>
    public static byte[] ReadBaseKey(string path, string? checkValue, out string? matched)
    {
        matched = null;
        string? given = string.IsNullOrWhiteSpace(checkValue) ? null : checkValue.Trim().ToLowerInvariant();
        string intro = $"A check value is {ShortCheckBytes * 2} or {LongCheckBytes * 2} hex characters.";
        if (given is not null && given.Length is not (ShortCheckBytes * 2) and not (LongCheckBytes * 2))
            throw new NetSecException(NetSecError.Of(ErrorCodes.DukptKcvFormat, $"{intro} This one is {given.Length} characters."));
        if (given is not null && !given.All(Uri.IsHexDigit))
            throw new NetSecException(NetSecError.Of(ErrorCodes.DukptKcvFormat, $"{intro} It holds a character that is not hex (0-9, a-f)."));
        byte[] key = Parse(ReadText(path));
        if (given is null) return key;
        matched = MatchedForm(key, given)
            ?? throw new NetSecException(NetSecError.Of(ErrorCodes.DukptKcvMismatch, "The key in this file does not match the check value you gave, in any of its 3 forms: AES 3 bytes, CMAC 3 bytes, CMAC 5 bytes."));
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

    /// <summary>
    /// The form a vendor's check value takes, or null when it matches none. CMAC over 16 zero bytes, first 3 bytes, is the AES form in a vendor
    /// source: the AWS Payment Cryptography API Reference, Key data type, KeyCheckValueAlgorithm (vendor source, read 2026-11-07,
    /// https://docs.aws.amazon.com/payment-cryptography/latest/APIReference/API_Key.html). The X9.24-3 vector PDF defines no check value. AES over a
    /// zero block, first 3 bytes, is the older form some tools still print, and CMAC first 5 bytes is a longer print of the CMAC form.
    /// </summary>
    public static string? MatchedForm(byte[] key, string given)
    {
        byte[] zeros = new byte[BaseKeyBytes];
        string cmac = Convert.ToHexString(Cmac.Compute(new AesKey(key), zeros)).ToLowerInvariant();
        using Aes aes = Aes.Create();
        aes.Key = key;
        string block = Convert.ToHexString(aes.EncryptEcb(zeros, PaddingMode.None)).ToLowerInvariant();
        if (given == cmac[..(ShortCheckBytes * 2)]) return "CMAC, 3 bytes";
        if (given == cmac[..(LongCheckBytes * 2)]) return "CMAC, 5 bytes";
        if (given == block[..(ShortCheckBytes * 2)]) return "AES, 3 bytes";
        return null;
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
