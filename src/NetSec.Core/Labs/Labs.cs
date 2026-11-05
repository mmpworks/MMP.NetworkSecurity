using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Platform;
using NetSec.Tls13;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Labs
{
    public enum AttackOutcome { Rejected, Accepted, NoCheck }

    /// <summary>A tamper as data. It flips one byte of one message at one point, by message name or by stream address.</summary>
    public sealed class TamperPlan : ITamperHook
    {
        public string Kind = "flip-byte";
        public TamperPoint Point = TamperPoint.Wire;
        public string Message;
        public string StreamId;
        public long StreamSeq;
        public int Offset;
        public int Xor = 1;
        public byte[] Replacement;

        public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
        {
            if (point != Point || !Matches(streamId, streamSeq, message)) return TamperResult.Unchanged;
            if (Replacement != null) return TamperResult.Replace(Replacement);
            if (Offset < 0 || Offset >= bytes.Length) return TamperResult.Unchanged;
            byte[] changed = (byte[])bytes.Clone();
            changed[Offset] = (byte)(changed[Offset] ^ Xor);
            return TamperResult.Replace(changed);
        }

        bool Matches(string streamId, long streamSeq, string message)
        {
            if (StreamId != null) return StreamId == streamId && StreamSeq == streamSeq;
            return Message == message;
        }
    }

    public sealed class LabOption
    {
        public string Name;
        public string Value;
    }

    public sealed class AttackDefinition
    {
        public string AttackId;
        public int Lesson;
        public string Kind;
        public TamperPlan Plan;
        public LabOption[] Options;
        public AttackOutcome Expect;
        public string ExpectCode, ExpectCheck;
    }

    public sealed class LabContext
    {
        public int Seed;
        public string SessionId, TraceId;
        public ITransportFactory Transports;
        public IStepGate Gate;
        public ITraceSink Sink;
        public IClock Clock;
        public IRandomSource Random;
        public AttackDefinition Attack;
        /// <summary>The read deadline of each pump. Zero means LabPair.DeadlineMs. A test sets a short one.</summary>
        public int DeadlineMs;
    }

    public sealed class LabResult
    {
        public bool Completed;
        public string FailedCode;
        public string FailedCheck;
    }

    public interface ILab
    {
        string LabId { get; }
        IFuture<LabResult> Run(LabContext context);
    }

    /// <summary>Lesson 0: a client and a server on loopback, each its own EnginePump. The pipe has no lock.</summary>
    public sealed class EchoLab : ILab
    {
        static readonly byte[] Message = Encoding.UTF8.GetBytes("hello, pipe");

        public string LabId { get { return "lab-00-echo"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            ITamperHook plan = LabPair.Plan(c);
            return LabPair.Run(c, EchoEngine.Client(Message, LabPair.Stream(c, "client", "echo"), plan), EchoEngine.Server(LabPair.Stream(c, "server", "echo"), plan), plan);
        }
    }

    public static class LabCatalog
    {
        /// <summary>The lab for a lesson number, or null when the lesson is not built yet.</summary>
        public static ILab Find(int lesson)
        {
            switch (lesson)
            {
                case 0: return new EchoLab();
                case 1: return new Lesson01Aes();
                case 2: return new Lesson02Seals();
                case 3: return new Lesson03Kex();
                case 4: return Tls13Lab.Lesson4();
                case 5: return Tls13Lab.Lesson5();
                case 6: return new Lesson06Dukpt();
                case 7: return new Lesson07Tls11();
                case 8: return new Lesson08Ssh();
                case 10: return new Lesson10Auth();
                case 11: return new TimingAttackLab();
                default: return null;
            }
        }
    }

    /// <summary>The one list of attacks. Each row runs beside a control, and a test compares its code and check.</summary>
    public static class AttackCatalog
    {
        const string CbcText = "TextCbc", GcmText = "TextGcm1";

        static readonly AttackDefinition[] Rows =
        {
            Flip("L0-flip-wire-byte", 0, EchoEngine.HelloName, 3, ErrorCodes.EchoMismatch, EchoEngine.CompareCheck),

            WithOption("L1-use-ecb", 1, Lesson01Aes.OptionTextMode, "ecb", AttackOutcome.NoCheck, null, null),
            Unchecked(Flip("L1-flip-cbc", 1, CbcText, Frame.HeaderSize + 16, null, null)),
            Flip("L1-flip-gcm", 1, GcmText, Frame.HeaderSize + 12, ErrorCodes.AesGcmTag, Lesson01Aes.TagCheck),
            WithOption("L1-reuse-nonce", 1, Lesson01Aes.OptionReuseNonce, "yes", AttackOutcome.Rejected, ErrorCodes.AesGcmNonceReuse, Lesson01Aes.NonceCheck),

            Flip("L2-flip-hash-message", 2, "PlainHashSealed", Lesson02Seals.MessageOffset + 3, ErrorCodes.SealHashMismatch, Lesson02Seals.HashCheck),
            Flip("L2-flip-hmac-message", 2, "HmacSealed", Lesson02Seals.MessageOffset + 3, ErrorCodes.SealHmacMismatch, Lesson02Seals.HmacCheck),
            Flip("L2-flip-hmac-tag", 2, "HmacSealed", Lesson02Seals.SealOffset, ErrorCodes.SealHmacMismatch, Lesson02Seals.HmacCheck),
            Flip("L2-flip-cmac-message", 2, "CmacSealed", Lesson02Seals.MessageOffset + 3, ErrorCodes.SealCmacMismatch, Lesson02Seals.CmacCheck),
            Flip("L2-flip-cmac-tag", 2, "CmacSealed", Lesson02Seals.SealOffset, ErrorCodes.SealCmacMismatch, Lesson02Seals.CmacCheck),
            WithOption("L2-extend-keyed-hash", 2, Lesson02Seals.OptionExtend, "KeyedHashSealed", AttackOutcome.NoCheck, null, null),
            WithOption("L2-extend-hmac", 2, Lesson02Seals.OptionExtend, "HmacSealed", AttackOutcome.Rejected, ErrorCodes.SealHmacMismatch, Lesson02Seals.HmacCheck),

            Swap("L3-swap-server-share", 3, "X25519ServerShare", Lesson03Kex.SwappedServerShare(), ErrorCodes.KexConfirmMismatch, Lesson03Kex.ConfirmCheck),
            Flip("L3-flip-mlkem-ciphertext", 3, "MlKemCiphertext", Frame.HeaderSize + 10, ErrorCodes.KexConfirmMismatch, Lesson03Kex.ConfirmCheck),

            PlainFlip("L4-flip-cert-byte", 4, "Certificate", Tls13Lab.CertSerialOffset, ChainCheck.BadSignature),
            PlainFlip("L4-flip-cert-verify", 4, "CertificateVerify", Tls13Lab.CertVerifySignatureOffset, Tls13Codes.CertVerifyBad),
            WithOption("L4-expired-cert", 4, Tls13Lab.OptionServerCert, Tls13Lab.CertExpired, AttackOutcome.Rejected, ChainCheck.Validity, Tls13Codes.CheckName(ChainCheck.Validity)),
            WithOption("L4-wrong-name", 4, Tls13Lab.OptionServerCert, Tls13Lab.CertWrongName, AttackOutcome.Rejected, ChainCheck.Name, Tls13Codes.CheckName(ChainCheck.Name)),
            WithOption("L4-unknown-ca", 4, Tls13Lab.OptionServerCert, Tls13Lab.CertUnknownCa, AttackOutcome.Rejected, ChainCheck.NoAnchor, Tls13Codes.CheckName(ChainCheck.NoAnchor)),

            PlainFlip("L5-flip-finished", 5, "Finished", Tls13Lab.VerifyDataOffset, Tls13Codes.FinishedMismatch),
            Flip("L5-flip-record-byte", 5, "EncryptedExtensions", Tls13Lab.RecordCipherOffset, Tls13Codes.AeadTag, Tls13Codes.CheckName(Tls13Codes.AeadTag)),
            PlainFlip("L5-replace-key-share", 5, "ClientHello", Tls13Lab.ClientX25519ShareOffset, Tls13Codes.AeadTag),
            PlainFlip("L5-flip-mlkem-ciphertext", 5, "ServerHello", Tls13Lab.ServerMlKemCiphertextOffset, Tls13Codes.AeadTag),
            FlipLength("L5-flip-record-length", 5, "Finished"),

            WithOption("L6-replay-sale", 6, Lesson06Dukpt.OptionScenario, Lesson06Dukpt.ScenarioReplaySale, AttackOutcome.Rejected, ErrorCodes.DukptKsnReplay, Lesson06Dukpt.ReplayCheck),
            Flip("L6-flip-pin-block", 6, Lesson06Dukpt.SaleName, Lesson06Dukpt.PinBlockOffset + 3, ErrorCodes.DukptPinBlockFormat, Lesson06Dukpt.FormatCheck),
            WithOption("L6-ask-past-key", 6, Lesson06Dukpt.OptionScenario, Lesson06Dukpt.ScenarioAskPastKey, AttackOutcome.Rejected, ErrorCodes.DukptKeyNotHeld, Lesson06Dukpt.NotHeldCheck),

            WithOption("L7-downgrade", 7, Lesson07Tls11.OptionScenario, Lesson07Tls11.ScenarioDowngrade, AttackOutcome.Rejected, Tls13Codes.DowngradeSentinel, Tls13Codes.CheckName(Tls13Codes.DowngradeSentinel)),
            WithOption("L7-modern-server", 7, Lesson07Tls11.OptionScenario, Lesson07Tls11.ScenarioModernServer, AttackOutcome.Rejected, NetSec.Tls11.Tls11Codes.AlertProtocolVersion, NetSec.Tls11.Tls11Checks.ProtocolVersionAlert),
            Flip("L7-flip-record", 7, Lesson07Tls11.ApplicationData, Lesson07Tls11.CipherOffset, NetSec.Tls11.Tls11Codes.RecordMac, NetSec.Tls11.Tls11Checks.RecordHmac),

            WithOption("L8-change-host-key", 8, Lesson08Ssh.OptionHostKey, "attacker", AttackOutcome.Rejected, SshCodes.HostKeyChanged, SshChecks.KnownHosts),
            Flip("L8-flip-exchange-signature", 8, SshNames.KexEcdhReply, SshEd25519SignatureOffset, SshCodes.ExchangeSignature, SshChecks.ExchangeSignature),
            WithOption("L8-zero-share", 8, Lesson08Ssh.OptionZeroShare, "yes", AttackOutcome.Rejected, SshCodes.KexZeroSecret, SshChecks.ZeroSecret),
            Flip("L8-flip-packet", 8, SshNames.UserauthSigned, SshProtectedBodyOffset, SshCodes.PacketMac, SshChecks.PacketMac),
            WithOption("L8-wrong-user-key", 8, Lesson08Ssh.OptionWrongUserKey, "attacker", AttackOutcome.Rejected, SshCodes.AuthRefused, SshChecks.AuthSignature),
            WithOption("L8-refused-tunnel", 8, Lesson08Ssh.OptionRefusedTunnel, "yes", AttackOutcome.Rejected, SshCodes.TunnelRefused, SshChecks.TunnelAllowList),
            Flip("L8-legacy-flip-signature", 8, SshNames.KexdhReply, SshRsaSignatureOffset, SshCodes.ExchangeSignature, SshChecks.ExchangeSignature),

            Flip("L10-change-token-claim", 10, "ReadTotals", Lesson10Auth.ClaimsOffset + 5, ErrorCodes.TokenBadSignature, NetSec.Auth.Token.SignatureCheck),
            WithOption("L10-expired-token", 10, Lesson10Auth.OptionTokenExpired, "yes", AttackOutcome.Rejected, ErrorCodes.TokenExpired, NetSec.Auth.Token.ExpiryCheck),
            WithOption("L10-replay-proof", 10, Lesson10Auth.OptionReplayProof, "yes", AttackOutcome.Rejected, ErrorCodes.DpopReplay, NetSec.Auth.DpopProof.ReplayCheck),
            WithOption("L10-stolen-token", 10, Lesson10Auth.OptionStolenToken, "yes", AttackOutcome.Rejected, ErrorCodes.DpopJktMismatch, NetSec.Auth.DpopProof.BindingCheck),
            WithOption("L10-ungranted-capability", 10, Lesson10Auth.OptionCallRefund, "yes", AttackOutcome.Rejected, ErrorCodes.CapabilityDenied, NetSec.Auth.AccessRules.PermissionCheck),
            WithOption("L10-wrong-role", 10, Lesson10Auth.OptionTokenRole, "guest", AttackOutcome.Rejected, ErrorCodes.RoleDenied, NetSec.Auth.AccessRules.PermissionCheck),
            WithOption("L10-replay-challenge", 10, Lesson10Auth.OptionReplayChallenge, "yes", AttackOutcome.Rejected, ErrorCodes.ChallengeReplay, NetSec.Auth.Challenge.ReplayCheck),
            WithOption("L10-remove-client-cert", 10, Lesson10Auth.OptionClientCert, Lesson10Auth.ClientCertNone, AttackOutcome.Rejected, NetSec.Tls13.Tls13Codes.CertRequired, NetSec.Tls13.Tls13Codes.CheckName(NetSec.Tls13.Tls13Codes.CertRequired)),
            WithOption("L10-corrupt-client-cert", 10, Lesson10Auth.OptionClientCert, Lesson10Auth.ClientCertCorrupt, AttackOutcome.Rejected, NetSec.Tls13.Tls13Codes.BadCertificate, NetSec.Tls13.Tls13Codes.CheckName(NetSec.Tls13.Tls13Codes.BadCertificate)),
            WithOption("L10-wrong-client-name", 10, Lesson10Auth.OptionClientCert, Lesson10Auth.ClientCertWrongName, AttackOutcome.Rejected, Tls13Codes.ClientNameRefused, Tls13Codes.CheckName(Tls13Codes.ClientNameRefused)),
            WithOption("L10-unissued-challenge", 10, Lesson10Auth.OptionAnswerUnissued, "yes", AttackOutcome.Rejected, ErrorCodes.ChallengeNotIssued, NetSec.Auth.Challenge.IssuedCheck),
            WithOption("L10-unknown-device", 10, Lesson10Auth.OptionUnknownDevice, "yes", AttackOutcome.Rejected, ErrorCodes.DeviceNotEnrolled, NetSec.Auth.Challenge.EnrolledCheck),
            WithOption("L10-wrong-audience", 10, Lesson10Auth.OptionTokenAudience, "https://other.training/api", AttackOutcome.Rejected, ErrorCodes.TokenBadAudience, NetSec.Auth.Token.AudienceCheck),

            TimingAttackLab.AttackRows[0],
            TimingAttackLab.AttackRows[1],
        };

        // Packet header 5, type 1, host key 4 + 51, share 4 + 32, signature length 4, name 4 + 11, value length 4, then 10 bytes into the signature value.
        const int SshEd25519SignatureOffset = 130;

        // Past the first encrypted block, which holds the length. A flip there reaches the MAC check rather than the length check.
        const int SshProtectedBodyOffset = 20;

        // Header 5, type 1, RSA host key 4 + 279, f 4 + 256 or 257, signature length 4, name 4 + 7, value length 4: the 256-byte value starts near 569. This lands inside it for either size of f.
        const int SshRsaSignatureOffset = 669;

        public static AttackDefinition[] All { get { return (AttackDefinition[])Rows.Clone(); } }

        /// <summary>Lesson 9's rows, which join All when its tour lands.</summary>
        public static AttackDefinition[] Lesson9Unreleased { get { return (AttackDefinition[])Lesson9Rows.Clone(); } }

        static readonly AttackDefinition[] Lesson9Rows =
        {
            Flip("L9-tamper-hop1", 9, SshNames.ChannelData, SshProtectedBodyOffset, SshCodes.PacketMac, SshChecks.PacketMac),
            Flip("L9-tamper-hop2", 9, "ApplicationData", Tls13Lab.RecordCipherOffset, Tls13Codes.AeadTag, Tls13Codes.CheckName(Tls13Codes.AeadTag)),
            WithOption("L9-flip-pin-block", 9, Lesson09Bridge.OptionFlipPinBlock, "yes", AttackOutcome.Rejected, ErrorCodes.DukptMacMismatch, NetSec.Bridge.BankHsmCore.MacCheck),
        };

        static AttackDefinition Flip(string id, int lesson, string message, int offset, string code, string check)
        {
            TamperPlan plan = new TamperPlan();
            plan.Message = message;
            plan.Offset = offset;
            return Row(id, lesson, "flip-byte", plan, new LabOption[0], AttackOutcome.Rejected, code, check);
        }

        static AttackDefinition Unchecked(AttackDefinition row)
        {
            row.Expect = AttackOutcome.NoCheck;
            return row;
        }

        /// <summary>A flip before protection, so a sealed record still opens and a deeper check gets the catch.</summary>
        static AttackDefinition PlainFlip(string id, int lesson, string message, int offset, string code)
        {
            TamperPlan plan = new TamperPlan();
            plan.Point = TamperPoint.Plain;
            plan.Message = message;
            plan.Offset = offset;
            return Row(id, lesson, "flip-byte", plan, new LabOption[0], AttackOutcome.Rejected, code, Tls13Codes.CheckName(code));
        }

        /// <summary>The record length grows by 256 bytes that never come, so the receiver waits until its read deadline ends the run.</summary>
        static AttackDefinition FlipLength(string id, int lesson, string message)
        {
            TamperPlan plan = new TamperPlan();
            plan.Message = message;
            plan.Offset = 3;
            return Row(id, lesson, "flip-byte", plan, new LabOption[0], AttackOutcome.Rejected, ErrorCodes.LinkDeadline, "read deadline");
        }

        static AttackDefinition Swap(string id, int lesson, string message, byte[] replacement, string code, string check)
        {
            TamperPlan plan = new TamperPlan();
            plan.Kind = "swap-field";
            plan.Message = message;
            plan.Replacement = replacement;
            return Row(id, lesson, "swap-field", plan, new LabOption[0], AttackOutcome.Rejected, code, check);
        }

        static AttackDefinition WithOption(string id, int lesson, string name, string value, AttackOutcome expect, string code, string check)
        {
            LabOption option = new LabOption();
            option.Name = name;
            option.Value = value;
            return Row(id, lesson, "scenario", null, new LabOption[] { option }, expect, code, check);
        }

        static AttackDefinition Row(string id, int lesson, string kind, TamperPlan plan, LabOption[] options, AttackOutcome expect, string code, string check)
        {
            AttackDefinition row = new AttackDefinition();
            row.AttackId = id;
            row.Lesson = lesson;
            row.Kind = kind;
            row.Plan = plan;
            row.Options = options;
            row.Expect = expect;
            row.ExpectCode = code;
            row.ExpectCheck = check;
            return row;
        }
    }
}
