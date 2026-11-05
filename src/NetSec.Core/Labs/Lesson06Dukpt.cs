using System;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Keys;
using NetSec.Machine;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 6. A card reader makes four sales. Each sale locks the PIN block under a new key, and the reader erases the key it came from.
    /// The bank keeps only the base key and derives each key again from the KSN. docs/lesson-6-names.md lists the names.
    /// Erasing clears a register in place. A managed heap can keep copies, so this does not prove the bytes are gone from memory.
    /// This lab's trace also keeps each key on purpose, so the learner can compare the two sides.
    /// Built to show the parts. Do not copy.
    /// </summary>
    public sealed class Lesson06Dukpt : ILab
    {
        public const string ReplayCheck = "KSN already seen";
        public const string FormatCheck = "PIN block format check";
        public const string NotHeldCheck = "key not in reader state";
        public const string OptionScenario = "scenario";
        public const string ScenarioReplaySale = "replay-sale";
        public const string ScenarioAskPastKey = "ask-past-key";
        public const string SaleName = "Sale";

        /// <summary>Where the PIN block starts in a Sale frame: the header, then the KSN.</summary>
        public const int PinBlockOffset = Frame.HeaderSize + KsnSize;

        const int KsnSize = 12;
        const int PinBlockSize = 16;
        const int SaleBodySize = KsnSize + PinBlockSize;
        const int RandomSize = 8;
        const int Sales = 4;
        const string Pin = "1234";
        const string Pan = "4111111111111111";
        const string Start0 = "Start";
        const string WaitAnswer = "WaitAnswer";
        const string WaitSale = "WaitSale";
        const string Derived = "dukpt.key.derived";
        const string Erased = "dukpt.key.erased";
        const string BaseKeyName = "dukpt.bdk";
        const string InitialKeyName = "dukpt.initial";
        const string RegistersMeasure = "Reader registers";
        const int SaleType = 1, ApprovedType = 2, DoneType = 3;
        const DukptKeyUsage PinUsage = DukptKeyUsage.PinEncryption;
        const DukptKeyType KeyType = DukptKeyType.Aes128;

        static readonly byte[] InitialKeyId = { 0x4d, 0x4d, 0x50, 0x54, 0x52, 0x41, 0x49, 0x4e };
        static readonly string[] Names = { "", SaleName, "SaleApproved", "SaleDone" };

        abstract class DukptSession : FrameSession
        {
            protected DukptSession(IRandomSource random) : base(random) { }
            public override string Protocol { get { return "dukpt"; } }
            public override string NameOf(int type) { return type > 0 && type < Names.Length ? Names[type] : "Unknown"; }
        }

        /// <summary>The reader's rules read this. It holds the pad, and never the base key. The registers mutate by design, because erasing them is the point of the lesson.</summary>
        sealed class ReaderSession : DukptSession
        {
            public readonly DukptPinPad Pad;
            public readonly string Scenario;
            public byte[] LoadedKey;
            public int SalesSent;
            public byte[] FirstSale;

            public ReaderSession(IRandomSource random, DukptPinPad pad, byte[] loadedKey, string scenario) : base(random)
            {
                Pad = pad;
                LoadedKey = loadedKey;
                Scenario = scenario;
            }
        }

        /// <summary>The bank's rules read this. It holds the base key and the ledger of KSNs seen.</summary>
        sealed class BankSession : DukptSession
        {
            public readonly byte[] BaseKey;
            public readonly KsnLedger Ledger = new KsnLedger();
            public int SalesApproved;

            public BankSession(IRandomSource random, byte[] baseKey) : base(random) { BaseKey = baseKey; }

            /// <summary>The received event shows the PIN the bank opens, or nothing when the frame fails. The rule makes the checks.</summary>
            public override byte[] PlainOf(InboundMessage message)
            {
                if (message.Type != SaleType || message.Body.Length != SaleBodySize) return new byte[0];
                byte[] key = DukptBank.DeriveWorkingKey(BaseKey, Part(message.Body, 0, KsnSize), PinUsage, KeyType);
                string pin;
                return PinBlock.TryDecryptFormat4(key, Part(message.Body, KsnSize, PinBlockSize), Pan, out pin) ? Encoding.UTF8.GetBytes(pin) : new byte[0];
            }
        }

        public string LabId { get { return "lab-06-dukpt"; } }

        public IFuture<LabResult> Run(LabContext c)
        {
            if (c == null) throw new ArgumentNullException("c");
            ITamperHook plan = LabPair.Plan(c);
            byte[] bdk = new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial();
            byte[] initial = DukptBank.DeriveInitialKey(bdk, InitialKeyId);
            ReaderSession readerSession = new ReaderSession(LabPair.Fork(c), new DukptPinPad(initial, InitialKeyId), initial, LabPair.Option(c, OptionScenario));
            BankSession bankSession = new BankSession(LabPair.Fork(c), bdk);
            FrameEngine<ReaderSession> reader = new FrameEngine<ReaderSession>(ReaderTable, readerSession, Start0, LabPair.Stream(c, "reader", "dukpt"), "bank", plan);
            FrameEngine<BankSession> bank = new FrameEngine<BankSession>(BankTable, bankSession, Start0, LabPair.Stream(c, "bank", "dukpt"), "reader", plan);
            return LabPair.Run(c, reader, bank, plan);
        }

        static readonly StepTable<ReaderSession> ReaderTable = new StepTable<ReaderSession>(
            new StepRow<ReaderSession>("dukpt.r.load", Start0, InboundMessage.StartType, ReaderLoad, WaitAnswer),
            new StepRow<ReaderSession>("dukpt.r.approved", WaitAnswer, ApprovedType, ReaderApproved, WaitAnswer),
            new StepRow<ReaderSession>("dukpt.r.done", WaitAnswer, DoneType, ReaderDone, MachineStates.Closed));

        static readonly StepTable<BankSession> BankTable = new StepTable<BankSession>(
            new StepRow<BankSession>("dukpt.b.start", Start0, InboundMessage.StartType, BankStart, WaitSale),
            new StepRow<BankSession>("dukpt.b.sale", WaitSale, SaleType, BankSale, MachineStates.Closed));

        // ---------------------------------------------------------------- reader

        /// <summary>The pad's constructor already loaded the registers. The session drops its copy of the initial key here, and the trace shows both facts.</summary>
        static StepDecision ReaderLoad(ReaderSession s, InboundMessage m)
        {
            byte[] initial = s.LoadedKey;
            s.LoadedKey = null;
            StepEffect[] load =
            {
                Effect.SecretAs(Derived, InitialKeyName, "reader", InitialKeyName, initial, BaseKeyName),
                Effect.Note(Erased, InitialKeyName),
                Effect.Measure(RegistersMeasure, Registers(s), null),
            };
            StepEffect[] sale = NextSale(s);
            StepEffect[] all = new StepEffect[load.Length + sale.Length];
            load.CopyTo(all, 0);
            sale.CopyTo(all, load.Length);
            return StepDecision.Advance(all);
        }

        static StepDecision ReaderApproved(ReaderSession s, InboundMessage m)
        {
            if (s.SalesSent == 1 && s.Scenario == ScenarioReplaySale)
                return StepDecision.Stay(Effect.SendProtected(SaleName, Encoding.UTF8.GetBytes(Pin), s.FirstSale, Frame.Fields(SaleBodySize, SaleSpans())));
            if (s.SalesSent == 2 && s.Scenario == ScenarioAskPastKey) return AskPastKey(s);
            return StepDecision.Stay(NextSale(s));
        }

        static StepDecision ReaderDone(ReaderSession s, InboundMessage m)
        {
            return StepDecision.Advance();
        }

        /// <summary>The attempt runs for real against the registers. A true result would mean the register logic is broken, so it stops the lab loudly.</summary>
        static StepDecision AskPastKey(ReaderSession s)
        {
            byte[] key;
            if (s.Pad.TryDeriveFromHeldKeys(1, PinUsage, KeyType, out key))
                throw new InvalidOperationException("The reader rebuilt a used key.");
            return StepDecision.Fail(ErrorCodes.DukptKeyNotHeld, NotHeldCheck, "counter 1: no register the reader holds leads to this key");
        }

        /// <summary>One sale: use the next counter and lock the PIN. The pad erases inside Next. The trace shows the erase after the send, the order the names file states.</summary>
        static StepEffect[] NextSale(ReaderSession s)
        {
            ulong counter = s.Pad.NextCounter;
            DukptUse use = s.Pad.Next(PinUsage, KeyType);
            byte[] block = PinBlock.EncryptFormat4(use.Key, Pin, Pan, s.Draw(RandomSize));
            byte[] body = new ByteWriter().Put(use.Ksn).Put(block).ToArray();
            byte[] frame = Frame.Build(SaleType, body);
            s.SalesSent++;
            if (s.FirstSale == null) s.FirstSale = frame;
            return new StepEffect[]
            {
                Effect.SecretAs(Derived, PinKeyName(counter), "reader", PinKeyName(counter), use.Key, DerivationKeyName(counter)),
                Effect.SendProtected(SaleName, Encoding.UTF8.GetBytes(Pin), frame, Frame.Fields(body.Length, SaleSpans())),
                Effect.Note(Erased, DerivationKeyName(counter)),
                Effect.Measure(RegistersMeasure, Registers(s), null),
            };
        }

        static FieldSpan[] SaleSpans()
        {
            return new FieldSpan[] { new FieldSpan("ksn", "header", KsnSize, 0, true), new FieldSpan("pinBlock", "cipher", PinBlockSize, 0, false) };
        }

        static string Registers(ReaderSession s)
        {
            return "held=" + s.Pad.HeldKeys().Length + ";next=" + s.Pad.NextCounter;
        }

        // ---------------------------------------------------------------- bank

        static StepDecision BankStart(BankSession s, InboundMessage m)
        {
            return StepDecision.Advance(
                Effect.SecretAs(Derived, BaseKeyName, "bank", BaseKeyName, s.BaseKey),
                Effect.SecretAs(Derived, InitialKeyName, "bank", InitialKeyName, DukptBank.DeriveInitialKey(s.BaseKey, InitialKeyId), BaseKeyName));
        }

        /// <summary>Checks the KSN, derives the key, opens the block. The row closes the engine on the last sale and stays for the others.</summary>
        static StepDecision BankSale(BankSession s, InboundMessage m)
        {
            if (m.Body.Length != SaleBodySize)
                return StepDecision.Fail(ErrorCodes.MessageRefused, "message shape", "a Sale holds " + SaleBodySize + " bytes, and this one holds " + m.Body.Length);
            byte[] ksn = Part(m.Body, 0, KsnSize);
            if (!s.Ledger.TryRecord(ksn))
                return StepDecision.Fail(ErrorCodes.DukptKsnReplay, ReplayCheck, "KSN " + Hex.Encode(ksn) + " was used in an earlier sale");

            uint counter = CounterOf(ksn);
            byte[] key = DukptBank.DeriveWorkingKey(s.BaseKey, ksn, PinUsage, KeyType);
            string pin;
            if (!PinBlock.TryDecryptFormat4(key, Part(m.Body, KsnSize, PinBlockSize), Pan, out pin))
                return StepDecision.Fail(ErrorCodes.DukptPinBlockFormat, FormatCheck, "counter " + counter + ": the opened block has the wrong shape");

            s.SalesApproved++;
            int answer = s.SalesApproved == Sales ? DoneType : ApprovedType;
            StepEffect[] effects =
            {
                Effect.Check(ReplayCheck, ErrorCodes.DukptKsnReplay),
                Effect.SecretAs(Derived, PinKeyName(counter), "bank", PinKeyName(counter), key, BaseKeyName, "ksn"),
                Effect.Check(FormatCheck, ErrorCodes.DukptPinBlockFormat),
                Effect.SendProtected(Names[answer], new byte[0], Frame.Build(answer, new byte[0]), Frame.Fields(0)),
            };
            return answer == DoneType ? StepDecision.Advance(effects) : StepDecision.Stay(effects);
        }

        static uint CounterOf(byte[] ksn)
        {
            return ((uint)ksn[8] << 24) | ((uint)ksn[9] << 16) | ((uint)ksn[10] << 8) | ksn[11];
        }

        static string PinKeyName(ulong counter) { return "dukpt.pinKey." + counter; }
        static string DerivationKeyName(ulong counter) { return "dukpt.derivationKey." + counter; }

        static byte[] Part(byte[] bytes, int offset, int count)
        {
            byte[] part = new byte[count];
            Buffer.BlockCopy(bytes, offset, part, 0, count);
            return part;
        }
    }
}
