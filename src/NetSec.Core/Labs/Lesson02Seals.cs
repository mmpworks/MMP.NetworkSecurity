using System;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 2. One message under four seals: a plain hash, a key in front of a hash, HMAC, and CMAC. A hash with the key in front
    /// falls to a length extension, and HMAC does not. These compares stop at the first difference. Lesson 11 shows why that matters.
    /// Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson02Seals : ILab
    {
        public const string OptionExtend = "extend";
        public const string HashCheck = "hash compare";
        public const string KeyedCheck = "keyed hash compare";
        public const string HmacCheck = "HMAC compare";
        public const string CmacCheck = "CMAC compare";
        public const string AvalancheName = "SHA-256 avalanche";

        const int KeySize = 16;
        const int HashBlock = 64;
        const int LengthPrefix = 2;
        const string KeyName = "seal.key";
        const string Start0 = "Start";

        const int PlainHashSealed = 1, KeyedHashSealed = 2, HmacSealed = 3, CmacSealed = 4, SealDone = 5;

        static readonly string[] Names = { "", "PlainHashSealed", "KeyedHashSealed", "HmacSealed", "CmacSealed", "SealDone" };

        /// <summary>The message under each seal. Public, so an attack row can aim at a byte of it.</summary>
        public static readonly byte[] Message = Encoding.UTF8.GetBytes("Pay the pump owner 20 dollars.");

        /// <summary>Where a message byte and a seal byte sit in a frame.</summary>
        public static int MessageOffset { get { return Frame.HeaderSize + LengthPrefix; } }
        public static int SealOffset { get { return MessageOffset + Message.Length; } }

        static readonly byte[] Suffix = Encoding.UTF8.GetBytes(" And 900 more.");

        sealed class Session : FrameSession
        {
            public Session(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "seal"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }
            public override byte[] PlainOf(InboundMessage message) { return message.Type == SealDone ? new byte[0] : MessageOf(message.Body); }
        }

        public string LabId { get { return "lab-02-seals"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            byte[] key = new byte[KeySize];
            c.Random.Fill(key, 0, key.Length);
            Session clientSession = new Session(LabPair.Fork(c)), serverSession = new Session(LabPair.Fork(c));
            clientSession.Remember(KeyName, key);
            serverSession.Remember(KeyName, key);

            ITamperHook hook = LabPair.Plan(c);
            string extend = LabPair.Option(c, OptionExtend);
            if (extend != null) hook = new LengthExtension(extend);

            FrameEngine<Session> client = new FrameEngine<Session>(ClientTable, clientSession, Start0, LabPair.Stream(c, "client", "seal"), "server", hook);
            FrameEngine<Session> server = new FrameEngine<Session>(ServerTable, serverSession, Start0, LabPair.Stream(c, "server", "seal"), "client", hook);
            return LabPair.Run(c, client, server, hook);
        }

        static readonly StepTable<Session> ClientTable = new StepTable<Session>(
            new StepRow<Session>("seal.c.send", Start0, InboundMessage.StartType, ClientSendAll, "WaitDone"),
            new StepRow<Session>("seal.c.done", "WaitDone", SealDone, ClientDone, MachineStates.Closed));

        static readonly StepTable<Session> ServerTable = new StepTable<Session>(
            new StepRow<Session>("seal.s.key", Start0, InboundMessage.StartType, ServerKey, "WaitPlainHash"),
            new StepRow<Session>("seal.s.plain-hash", "WaitPlainHash", PlainHashSealed, ServerPlainHash, "WaitKeyedHash"),
            new StepRow<Session>("seal.s.keyed-hash", "WaitKeyedHash", KeyedHashSealed, ServerKeyedHash, "WaitHmac"),
            new StepRow<Session>("seal.s.hmac", "WaitHmac", HmacSealed, ServerHmac, "WaitCmac"),
            new StepRow<Session>("seal.s.cmac", "WaitCmac", CmacSealed, ServerCmac, MachineStates.Closed));

        static StepDecision ClientSendAll(Session s, InboundMessage m)
        {
            byte[] key = s.Secret(KeyName);
            return StepDecision.Advance(
                Effect.Secret("client", KeyName, key),
                Avalanche(),
                Send(PlainHashSealed, PlainHash(Message)),
                Send(KeyedHashSealed, KeyedHash(key, Message)),
                Send(HmacSealed, HmacOf(key, Message)),
                Send(CmacSealed, CmacOf(key, Message)));
        }

        static StepDecision ClientDone(Session s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        static StepDecision ServerKey(Session s, InboundMessage m)
        {
            return StepDecision.Advance(Effect.Secret("server", KeyName, s.Secret(KeyName)));
        }

        static StepDecision ServerPlainHash(Session s, InboundMessage m)
        {
            return Compare(m, PlainHash(MessageOf(m.Body)), ErrorCodes.SealHashMismatch, HashCheck);
        }

        static StepDecision ServerKeyedHash(Session s, InboundMessage m)
        {
            return Compare(m, KeyedHash(s.Secret(KeyName), MessageOf(m.Body)), ErrorCodes.SealKeyedHashMismatch, KeyedCheck);
        }

        static StepDecision ServerHmac(Session s, InboundMessage m)
        {
            return Compare(m, HmacOf(s.Secret(KeyName), MessageOf(m.Body)), ErrorCodes.SealHmacMismatch, HmacCheck);
        }

        static StepDecision ServerCmac(Session s, InboundMessage m)
        {
            StepDecision compared = Compare(m, CmacOf(s.Secret(KeyName), MessageOf(m.Body)), ErrorCodes.SealCmacMismatch, CmacCheck);
            if (compared.Outcome == StepOutcome.Fail) return compared;
            return StepDecision.Advance(compared.Effects[0], Effect.SendProtected(Names[SealDone], new byte[0], Frame.Build(SealDone, new byte[0]), Frame.Fields(0)));
        }

        static StepDecision Compare(InboundMessage m, byte[] expected, string code, string check)
        {
            if (!Same(expected, SealOf(m.Body))) return StepDecision.Fail(code, check, m.Name + ": the seal does not fit the message");
            return StepDecision.Advance(Effect.Check(check, code));
        }

        static StepEffect Send(int type, byte[] seal)
        {
            byte[] body = new ByteWriter().U16(Message.Length).Put(Message).Put(seal).ToArray();
            return Effect.SendProtected(Names[type], Message, Frame.Build(type, body), Frame.Fields(body.Length,
                new FieldSpan("messageLength", "length", LengthPrefix, 0, true),
                new FieldSpan("message", "data", Message.Length, 0, true),
                new FieldSpan("seal", "mac", -1, 0, true)));
        }

        /// <summary>Two digests, one bit apart in the message, and how many of their 256 bits differ.</summary>
        static StepEffect Avalanche()
        {
            byte[] flipped = (byte[])Message.Clone();
            flipped[0] ^= 1;
            byte[] a = PlainHash(Message), b = PlainHash(flipped);
            int bits = 0;
            for (int i = 0; i < a.Length; i++)
                for (int x = a[i] ^ b[i]; x != 0; x &= x - 1) bits++;
            return Effect.Measure(AvalancheName, "bits=" + bits + ";of=" + (a.Length * 8), new ByteWriter().Put(a).Put(b).ToArray());
        }

        static byte[] PlainHash(byte[] message)
        {
            IHash h = Hashes.Sha256();
            h.Update(message, 0, message.Length);
            return h.Finish();
        }

        static byte[] KeyedHash(byte[] key, byte[] message)
        {
            IHash h = Hashes.Sha256();
            h.Update(key, 0, key.Length);
            h.Update(message, 0, message.Length);
            return h.Finish();
        }

        static byte[] HmacOf(byte[] key, byte[] message) { return Hmac.Compute(Hashes.Sha256, key, message); }
        static byte[] CmacOf(byte[] key, byte[] message) { return Cmac.Compute(new AesKey(key), message); }

        static byte[] MessageOf(byte[] body)
        {
            ByteReader r = new ByteReader(body, 0, body.Length, true);
            int length = r.U16("messageLength", "length");
            return r.Take("message", "data", length);
        }

        static byte[] SealOf(byte[] body)
        {
            ByteReader r = new ByteReader(body, 0, body.Length, true);
            int length = r.U16("messageLength", "length");
            r.Take("message", "data", length);
            return r.Take("seal", "mac", r.Remaining);
        }

        // This compare stops at the first difference on purpose. Lesson 11 measures what that leaks.
        static bool Same(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        /// <summary>
        /// The attacker has the message and a seal, and no key. SHA-256's digest is its whole state, so the attacker continues hashing from
        /// that digest over the padding and a suffix. The server hashes key, message, padding, and suffix, and reaches the same value.
        /// HMAC hashes twice under the key, so the same forgery fails there.
        /// </summary>
        sealed class LengthExtension : ITamperHook
        {
            readonly string _target;
            public LengthExtension(string target) { _target = target; }

            public TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes)
            {
                if (point != TamperPoint.Wire || message != _target) return TamperResult.Unchanged;
                byte[] body = new byte[bytes.Length - Frame.HeaderSize];
                Buffer.BlockCopy(bytes, Frame.HeaderSize, body, 0, body.Length);
                byte[] glue = Padding(KeySize + Message.Length);
                IHash resumed = Hashes.Sha256Resume(SealOf(body), KeySize + Message.Length + glue.Length);
                resumed.Update(Suffix, 0, Suffix.Length);
                byte[] forgedSeal = resumed.Finish();
                byte[] forgedMessage = new ByteWriter().Put(Message).Put(glue).Put(Suffix).ToArray();
                byte[] forgedBody = new ByteWriter().U16(forgedMessage.Length).Put(forgedMessage).Put(forgedSeal).ToArray();
                return TamperResult.Replace(Frame.Build(bytes[0], forgedBody));
            }

            /// <summary>SHA-256 padding after count bytes: 0x80, zeros, and the bit length in 8 bytes.</summary>
            static byte[] Padding(int count)
            {
                int zeros = (HashBlock + 56 - (count + 1) % HashBlock) % HashBlock;
                ByteWriter w = new ByteWriter().U8(0x80);
                for (int i = 0; i < zeros; i++) w.U8(0);
                return w.U32(0).U32(count * 8L).ToArray();
            }
        }
    }
}
