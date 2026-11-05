using System;
using System.Collections.Generic;
using NetSec.Errors;
using NetSec.Trace;

namespace NetSec.Machine
{
    /// <summary>What the interpreter asks of a protocol session when a rule's effect runs.</summary>
    public interface IMachineSession
    {
        string SentType { get; }
        string ReceivedType { get; }
        void Absorb(byte[] message);
        byte[] Protect(string message, byte[] body);
        void InstallKeys(Direction direction, string suite, byte[] key, byte[] iv);
    }

    public static class MachineStates
    {
        public const string Open = "Open";
        public const string Closed = "Closed";
    }

    /// <summary>
    /// The one switch over effect kinds. Each effect emits its trace event here, so "every step emits" holds by construction.
    /// A rule decides. This class acts.
    /// </summary>
    public sealed class Interpreter<TSession> where TSession : IMachineSession
    {
        readonly StepTable<TSession> _table;
        readonly TSession _session;
        readonly TraceStream _stream;
        readonly ITamperHook _tamper;
        readonly string _peer;
        readonly List<OutputItem> _items = new List<OutputItem>();
        readonly List<DeliveredChunk> _app = new List<DeliveredChunk>();

        public string State { get; private set; }
        public EngineStatus Status { get; private set; }
        public NetSecError Error { get; private set; }

        public Interpreter(StepTable<TSession> table, TSession session, string startState, TraceStream stream, string peer, ITamperHook tamper)
        {
            _table = table; _session = session; _stream = stream; _peer = peer; _tamper = tamper;
            State = startState;
            Status = EngineStatus.Handshaking;
        }

        /// <summary>Runs the row for this message, unless the engine has already ended.</summary>
        public void Dispatch(InboundMessage message)
        {
            if (IsEnded) return;
            StepRow<TSession> row = _table.Find(State, message.Type);
            if (message.Type != InboundMessage.StartType) EmitReceived(message, row);
            if (row == null)
            {
                Apply(NoRow(message), null);
                return;
            }
            Apply(row.Rule(_session, message), row);
        }

        public void Fail(string code, string checkName, string detail, string step)
        {
            StepDecision failure = StepDecision.Fail(code, checkName, detail);
            failure.Error.Step = step;
            Conclude(failure);
        }

        public void CloseCleanly()
        {
            if (IsEnded) return;
            Status = EngineStatus.Closed;
        }

        public bool IsEnded { get { return Status == EngineStatus.Closed || Status == EngineStatus.Failed; } }

        /// <summary>Hands over what the last calls produced, and starts a new output.</summary>
        public EngineOutput TakeOutput()
        {
            EngineOutput output = new EngineOutput(_items.ToArray(), _app.ToArray(), Status, Error);
            _items.Clear();
            _app.Clear();
            return output;
        }

        StepDecision NoRow(InboundMessage message)
        {
            return StepDecision.Fail(ErrorCodes.UnexpectedMessage, "message allowed in this state",
                "state " + State + " has no row for message type " + message.Type);
        }

        void Apply(StepDecision decision, StepRow<TSession> row)
        {
            string step = row == null ? null : row.Step;
            for (int i = 0; i < decision.Effects.Length; i++) ApplyEffect(decision.Effects[i], step);
            if (decision.Outcome == StepOutcome.Fail)
            {
                decision.Error.Step = step;
                Conclude(decision);
                return;
            }
            if (decision.Outcome == StepOutcome.Advance) MoveTo(row.To, step);
        }

        void Conclude(StepDecision failure)
        {
            TraceCheck check = new TraceCheck();
            check.Id = failure.Error.Code;
            check.Name = failure.Error.CheckName;
            check.Passed = false;
            check.Code = failure.Error.Code;
            check.Detail = failure.Error.Message;
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "check.result";
            draft.Step = failure.Error.Step;
            draft.Check = check;
            Emit(draft, null);
            failure.Error.TraceId = _stream.TraceId;
            Error = failure.Error;
            Status = EngineStatus.Failed;
        }

        void MoveTo(string state, string step)
        {
            State = state;
            if (state == MachineStates.Closed) { Status = EngineStatus.Closed; return; }
            if (state == MachineStates.Open) Status = EngineStatus.Open;
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "state.waiting";
            draft.Step = step;
            draft.WaitingFor = _peer;
            Emit(draft, null);
        }

        void ApplyEffect(StepEffect effect, string step)
        {
            switch (effect.Kind)
            {
                case EffectKind.Absorb: _session.Absorb(effect.Bytes); break;
                case EffectKind.Send: ApplySend(effect, step); break;
                case EffectKind.Secret: ApplySecret(effect, step); break;
                case EffectKind.InstallKeys: ApplyInstallKeys(effect, step); break;
                case EffectKind.Check: ApplyCheck(effect, step); break;
                case EffectKind.Deliver: _app.Add(new DeliveredChunk(effect.Channel, effect.Bytes)); break;
                case EffectKind.Note: ApplyNote(effect, step); break;
                default: throw new InvalidOperationException("no case for effect kind " + effect.Kind);
            }
        }

        void ApplySend(StepEffect effect, string step)
        {
            byte[] body = effect.Bytes;
            if (_tamper != null)
            {
                TamperResult result = _tamper.Apply(TamperPoint.Plain, _stream.StreamId, _stream.NextSeq, effect.Name, body);
                if (result != null && result.Bytes != null) body = result.Bytes;
            }
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = _session.SentType;
            draft.Message = effect.Name;
            draft.Step = step;
            draft.Plain = body;
            draft.Fields = effect.Fields;
            Emit(draft, _session.Protect(effect.Name, body));
        }

        void ApplySecret(StepEffect effect, string step)
        {
            TraceSecret secret = new TraceSecret();
            secret.Holder = effect.Text;
            secret.Name = effect.Name;
            secret.Bytes = effect.Bytes;
            secret.DerivedFrom = effect.From;
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "secret.derived";
            draft.Step = step;
            draft.Secrets = new TraceSecret[] { secret };
            Emit(draft, null);
        }

        void ApplyInstallKeys(StepEffect effect, string step)
        {
            _session.InstallKeys(effect.Direction, effect.Name, effect.Bytes, effect.Iv);
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "keys.installed";
            draft.Message = effect.Name;
            draft.Step = step;
            Emit(draft, null);
        }

        void ApplyCheck(StepEffect effect, string step)
        {
            TraceCheck check = new TraceCheck();
            check.Id = effect.Text;
            check.Name = effect.Name;
            check.Passed = true;
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = "check.result";
            draft.Step = step;
            draft.Check = check;
            Emit(draft, null);
        }

        void ApplyNote(StepEffect effect, string step)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = effect.Name;
            draft.Message = effect.Text;
            draft.Step = step;
            Emit(draft, null);
        }

        void EmitReceived(InboundMessage message, StepRow<TSession> row)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = _session.ReceivedType;
            draft.Message = message.Name;
            draft.Step = row == null ? null : row.Step;
            draft.Plain = message.Bytes;
            draft.Fields = message.Fields;
            Emit(draft, null);
        }

        void Emit(TraceEventDraft draft, byte[] wire)
        {
            _items.Add(new OutputItem(_stream.Stamp(draft), wire));
        }
    }
}
