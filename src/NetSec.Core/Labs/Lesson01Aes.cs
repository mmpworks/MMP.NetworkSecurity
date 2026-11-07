using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 1. The client sends the same text and the same picture under ECB, CBC, and GCM. The picture shows what ECB leaks.
    /// The server unlocks each message and counts repeated cipher blocks. Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson01Aes : ILab
    {
        public const string OptionTextMode = "text-mode";
        public const string OptionReuseNonce = "reuse-nonce";
        public const string TagCheck = "GCM tag";
        public const string NonceCheck = "nonce reuse detector";

        const int BlockSize = 16;
        const int NonceSize = 12;
        const int TagSize = 16;
        const string KeyName = "aes.key";
        const string Suite = "aes-128";
        const string Sender = "Start";
        const string SenderWait = "WaitDone";

        const int TextGcm1 = 1, TextCbc = 2, PictureEcb = 3, PictureCbc = 4, PictureGcm = 5, TextGcm2 = 6, AesDone = 7, TextEcb = 8;

        static readonly string[] Names = { "", "TextGcm1", "TextCbc", "PictureEcb", "PictureCbc", "PictureGcm", "TextGcm2", "AesDone", "TextEcb" };

        // Four equal blocks, so an ECB run shows three repeats in the text alone.
        static readonly byte[] Text = Encoding.UTF8.GetBytes("Pump four is ok.Pump four is ok.Pump four is ok.Pump four is ok.");

        enum Mode { Ecb, Cbc, Gcm }

        sealed class Session : FrameSession
        {
            public bool TextInEcb, ReuseNonce;
            readonly Dictionary<string, bool> _nonces = new Dictionary<string, bool>();

            public Session(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "aes"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }

            public override void Absorb(byte[] nonce) { _nonces[Hex.Encode(nonce)] = true; }
            public bool NonceSeen(byte[] nonce) { return _nonces.ContainsKey(Hex.Encode(nonce)); }

            public override byte[] PlainOf(InboundMessage message)
            {
                return message.Type == AesDone ? new byte[0] : Unlock(new AesKey(Secret(KeyName)), ModeOf(message.Type), message.Body) ?? new byte[0];
            }
        }

        public string LabId { get { return "lab-01-aes"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            byte[] key = LabCredentials.LessonKey(c, SecurityTypes.LabAesKey);

            Session clientSession = new Session(LabPair.Fork(c));
            clientSession.TextInEcb = LabPair.Option(c, OptionTextMode) == "ecb";
            clientSession.ReuseNonce = LabPair.Option(c, OptionReuseNonce) == "yes";
            clientSession.Remember(KeyName, key);
            Session serverSession = new Session(LabPair.Fork(c));
            serverSession.Remember(KeyName, key);

            ITamperHook plan = LabPair.Plan(c);
            FrameEngine<Session> client = new FrameEngine<Session>(ClientTable, clientSession, Sender, LabPair.Stream(c, "client", "aes"), "server", plan);
            FrameEngine<Session> server = new FrameEngine<Session>(ServerTable, serverSession, Sender, LabPair.Stream(c, "server", "aes"), "client", plan);
            return LabPair.Run(c, client, server, plan);
        }

        static readonly StepTable<Session> ClientTable = new StepTable<Session>(
            new StepRow<Session>("aes.c.send", Sender, InboundMessage.StartType, ClientSendAll, SenderWait),
            new StepRow<Session>("aes.c.done", SenderWait, AesDone, ClientDone, MachineStates.Closed));

        static readonly StepTable<Session> ServerTable = new StepTable<Session>(
            new StepRow<Session>("aes.s.key", Sender, InboundMessage.StartType, ServerKey, "WaitTextGcm1"),
            new StepRow<Session>("aes.s.text-gcm-1", "WaitTextGcm1", TextGcm1, ServerGcm, "WaitTextCbc"),
            new StepRow<Session>("aes.s.text-cbc", "WaitTextCbc", TextCbc, ServerMeasure, "WaitPictureEcb"),
            new StepRow<Session>("aes.s.text-ecb", "WaitTextCbc", TextEcb, ServerMeasure, "WaitPictureEcb"),
            new StepRow<Session>("aes.s.picture-ecb", "WaitPictureEcb", PictureEcb, ServerMeasure, "WaitPictureCbc"),
            new StepRow<Session>("aes.s.picture-cbc", "WaitPictureCbc", PictureCbc, ServerMeasure, "WaitPictureGcm"),
            new StepRow<Session>("aes.s.picture-gcm", "WaitPictureGcm", PictureGcm, ServerGcm, "WaitTextGcm2"),
            new StepRow<Session>("aes.s.text-gcm-2", "WaitTextGcm2", TextGcm2, ServerLastGcm, MachineStates.Closed));

        static StepDecision ClientSendAll(Session s, InboundMessage m)
        {
            AesKey key = new AesKey(s.Secret(KeyName));
            byte[] firstNonce = s.Draw(NonceSize);
            byte[] picture = Picture();
            List<StepEffect> effects = new List<StepEffect>();
            effects.Add(Effect.Secret("client", KeyName, s.Secret(KeyName)));
            effects.Add(Effect.InstallKeys(Direction.Outbound, Suite, s.Secret(KeyName), new byte[0]));
            effects.Add(SendGcm(key, TextGcm1, Text, firstNonce));
            effects.Add(s.TextInEcb ? SendEcb(key, TextEcb, Text) : SendCbc(key, TextCbc, Text, s.Draw(BlockSize)));
            effects.Add(SendEcb(key, PictureEcb, picture));
            effects.Add(SendCbc(key, PictureCbc, picture, s.Draw(BlockSize)));
            effects.Add(SendGcm(key, PictureGcm, picture, s.Draw(NonceSize)));
            effects.Add(SendGcm(key, TextGcm2, Text, s.ReuseNonce ? firstNonce : s.Draw(NonceSize)));
            return StepDecision.Advance(effects.ToArray());
        }

        static StepDecision ClientDone(Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        static StepDecision ServerKey(Session s, InboundMessage m)
        {
            return StepDecision.Advance(
                Effect.Secret("server", KeyName, s.Secret(KeyName)),
                Effect.InstallKeys(Direction.Inbound, Suite, s.Secret(KeyName), new byte[0]));
        }

        static StepDecision ServerMeasure(Session s, InboundMessage m)
        {
            return StepDecision.Advance(MeasureBlocks(m));
        }

        static StepDecision ServerGcm(Session s, InboundMessage m)
        {
            byte[] nonce = Slice(m.Body, 0, NonceSize);
            if (Unlock(new AesKey(s.Secret(KeyName)), Mode.Gcm, m.Body) == null)
                return StepDecision.Fail(ErrorCodes.AesGcmTag, TagCheck, m.Name + " failed the tag check");
            if (s.NonceSeen(nonce))
                return StepDecision.Fail(ErrorCodes.AesGcmNonceReuse, NonceCheck, m.Name + " repeats a nonce, so the two messages share a key stream");
            return StepDecision.Advance(
                Effect.Check(TagCheck, ErrorCodes.AesGcmTag),
                Effect.Check(NonceCheck, ErrorCodes.AesGcmNonceReuse),
                Effect.Absorb(nonce),
                MeasureBlocks(m));
        }

        static StepDecision ServerLastGcm(Session s, InboundMessage m)
        {
            StepDecision gcm = ServerGcm(s, m);
            if (gcm.Outcome == StepOutcome.Fail) return gcm;
            StepEffect[] effects = new StepEffect[gcm.Effects.Length + 1];
            gcm.Effects.CopyTo(effects, 0);
            effects[gcm.Effects.Length] = Effect.SendProtected(Names[AesDone], new byte[0], Frame.Build(AesDone, new byte[0]), Frame.Fields(0));
            return StepDecision.Advance(effects);
        }

        static StepEffect SendEcb(AesKey key, int type, byte[] plain)
        {
            byte[] body = Modes.EcbEncrypt(key, Pad(plain));
            return Effect.SendProtected(Names[type], plain, Frame.Build(type, body), Frame.Fields(body.Length, new FieldSpan("cipher", "cipher", -1, 0, false)));
        }

        static StepEffect SendCbc(AesKey key, int type, byte[] plain, byte[] iv)
        {
            byte[] body = new ByteWriter().Put(iv).Put(Modes.CbcEncrypt(key, iv, Pad(plain))).ToArray();
            return Effect.SendProtected(Names[type], plain, Frame.Build(type, body), Frame.Fields(body.Length,
                new FieldSpan("iv", "random", BlockSize, 0, true), new FieldSpan("cipher", "cipher", -1, 0, false)));
        }

        static StepEffect SendGcm(AesKey key, int type, byte[] plain, byte[] nonce)
        {
            byte[] body = new ByteWriter().Put(nonce).Put(Gcm.Seal(key, nonce, new byte[0], plain)).ToArray();
            return Effect.SendProtected(Names[type], plain, Frame.Build(type, body), Frame.Fields(body.Length,
                new FieldSpan("nonce", "random", NonceSize, 0, true), new FieldSpan("cipher", "cipher", -1, TagSize, false), new FieldSpan("tag", "mac", TagSize, 0, true)));
        }

        /// <summary>The receiver's view of a body, or null when a GCM tag fails. CBC and ECB have no check, so a flip gives garbled bytes.</summary>
        static byte[] Unlock(AesKey key, Mode mode, byte[] body)
        {
            switch (mode)
            {
                case Mode.Ecb:
                    return Unpad(EcbDecrypt(key, body));
                case Mode.Cbc:
                    return Unpad(Modes.CbcDecrypt(key, Slice(body, 0, BlockSize), Slice(body, BlockSize, body.Length - BlockSize)));
                default:
                    byte[] plain;
                    return Gcm.TryOpen(key, Slice(body, 0, NonceSize), new byte[0], Slice(body, NonceSize, body.Length - NonceSize), out plain) ? plain : null;
            }
        }

        static Mode ModeOf(int type)
        {
            switch (type)
            {
                case TextGcm1: case PictureGcm: case TextGcm2: return Mode.Gcm;
                case TextCbc: case PictureCbc: return Mode.Cbc;
                default: return Mode.Ecb;
            }
        }

        static StepEffect MeasureBlocks(InboundMessage m)
        {
            Mode mode = ModeOf(m.Type);
            int skip = mode == Mode.Gcm ? NonceSize : mode == Mode.Cbc ? BlockSize : 0;
            int tail = mode == Mode.Gcm ? TagSize : 0;
            int length = m.Body.Length - skip - tail;
            int blocks = length / BlockSize;
            Dictionary<string, bool> distinct = new Dictionary<string, bool>();
            for (int i = 0; i < blocks; i++) distinct[Hex.Encode(Slice(m.Body, skip + i * BlockSize, BlockSize))] = true;
            return Effect.Measure(m.Name, "repeats=" + (blocks - distinct.Count) + ";blocks=" + blocks, null);
        }

        static byte[] EcbDecrypt(AesKey key, byte[] cipher)
        {
            byte[] plain = new byte[cipher.Length];
            for (int i = 0; i + BlockSize <= cipher.Length; i += BlockSize) key.DecryptBlock(cipher, i, plain, i);
            return plain;
        }

        internal static byte[] Pad(byte[] plain)
        {
            int pad = BlockSize - plain.Length % BlockSize;
            byte[] padded = new byte[plain.Length + pad];
            Buffer.BlockCopy(plain, 0, padded, 0, plain.Length);
            for (int i = plain.Length; i < padded.Length; i++) padded[i] = (byte)pad;
            return padded;
        }

        /// <summary>Removes padding when it reads as padding. A flipped block can break it, and this lesson shows that result as it is.</summary>
        static byte[] Unpad(byte[] padded)
        {
            if (padded.Length == 0) return padded;
            int pad = padded[padded.Length - 1];
            if (pad < 1 || pad > BlockSize || pad > padded.Length) return padded;
            return Slice(padded, 0, padded.Length - pad);
        }

        static byte[] Slice(byte[] bytes, int offset, int count)
        {
            if (offset < 0 || count < 0 || offset + count > bytes.Length)
                throw new ParseFailure(ErrorCodes.ParseTruncated, "the body holds " + bytes.Length + " bytes, and the layout needs " + (offset + count));
            byte[] part = new byte[count];
            Buffer.BlockCopy(bytes, offset, part, 0, count);
            return part;
        }

        /// <summary>A fuel pump, 64 by 64, one byte per pixel. Large flat areas give ECB equal blocks to repeat.</summary>
        static byte[] Picture()
        {
            const int Size = 64, Sky = 230, Body = 40, Glass = 200, Hose = 90;
            byte[] pixels = new byte[Size * Size];
            for (int y = 0; y < Size; y++)
                for (int x = 0; x < Size; x++)
                {
                    int shade = Sky;
                    if (x >= 16 && x < 40 && y >= 8 && y < 60) shade = Body;
                    if (x >= 20 && x < 36 && y >= 12 && y < 28) shade = Glass;
                    if (x >= 40 && x < 48 && y == 32) shade = Hose;
                    if (x == 48 && y >= 32 && y < 52) shade = Hose;
                    pixels[y * Size + x] = (byte)shade;
                }
            return pixels;
        }
    }
}
