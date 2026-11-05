using System;
using System.Collections.Generic;
using NetSec.Errors;
using NetSec.Trace;

namespace NetSec.Machine
{
    public enum StepOutcome { Advance, Stay, Fail }
    public enum EffectKind { Absorb, Send, Secret, InstallKeys, Check, Deliver, Note }
    public enum Direction { Inbound, Outbound }

    public sealed class InboundMessage
    {
        public const int StartType = -1;

        public readonly int Type;
        public readonly string Name;
        public readonly byte[] Bytes;
        public readonly byte[] Body;
        public readonly TraceField[] Fields;

        public InboundMessage(int type, string name, byte[] bytes, byte[] body, TraceField[] fields)
        {
            Type = type; Name = name; Bytes = bytes; Body = body; Fields = fields;
        }

        public static readonly InboundMessage Start = new InboundMessage(StartType, null, new byte[0], new byte[0], null);
    }

    /// <summary>One thing a rule wants done. The interpreter does it and emits the trace event for it.</summary>
    public sealed class StepEffect
    {
        public readonly EffectKind Kind;
        public readonly string Name, Text;
        public readonly byte[] Bytes, Iv;
        public readonly TraceField[] Fields;
        public readonly string[] From;
        public readonly int Channel;
        public readonly Direction Direction;

        internal StepEffect(EffectKind kind, string name, string text, byte[] bytes, byte[] iv, TraceField[] fields, string[] from, int channel, Direction direction)
        {
            Kind = kind; Name = name; Text = text; Bytes = bytes; Iv = iv; Fields = fields; From = from; Channel = channel; Direction = direction;
        }
    }

    public static class Effect
    {
        public static StepEffect Absorb(byte[] message) { return Make(EffectKind.Absorb, null, null, message); }
        public static StepEffect Send(string message, byte[] body, TraceField[] fields) { return new StepEffect(EffectKind.Send, message, null, body, null, fields, null, 0, Direction.Outbound); }
        public static StepEffect Secret(string holder, string name, byte[] value, params string[] from) { return new StepEffect(EffectKind.Secret, name, holder, value, null, null, from, 0, Direction.Outbound); }
        public static StepEffect InstallKeys(Direction d, string suite, byte[] key, byte[] iv) { return new StepEffect(EffectKind.InstallKeys, suite, null, key, iv, null, null, 0, d); }
        public static StepEffect Check(string name, string code) { return Make(EffectKind.Check, name, code, null); }
        public static StepEffect Deliver(int channel, byte[] plain) { return new StepEffect(EffectKind.Deliver, null, null, plain, null, null, null, channel, Direction.Inbound); }
        public static StepEffect Note(string type, string message) { return Make(EffectKind.Note, type, message, null); }

        static StepEffect Make(EffectKind kind, string name, string text, byte[] bytes)
        {
            return new StepEffect(kind, name, text, bytes, null, null, null, 0, Direction.Outbound);
        }
    }

    /// <summary>A value. A rule runs no side effect, so a test can call a rule with no engine.</summary>
    public sealed class StepDecision
    {
        public readonly StepOutcome Outcome;
        public readonly StepEffect[] Effects;
        public readonly NetSecError Error;

        StepDecision(StepOutcome outcome, StepEffect[] effects, NetSecError error)
        {
            Outcome = outcome; Effects = effects; Error = error;
        }

        public static StepDecision Advance(params StepEffect[] e) { return new StepDecision(StepOutcome.Advance, e, null); }
        public static StepDecision Stay(params StepEffect[] e) { return new StepDecision(StepOutcome.Stay, e, null); }

        public static StepDecision Fail(string code, string checkName, string detail)
        {
            NetSecError error = NetSecError.Of(code, detail);
            error.CheckName = checkName;
            return new StepDecision(StepOutcome.Fail, new StepEffect[0], error);
        }
    }

    public delegate StepDecision StepRule<TSession>(TSession session, InboundMessage message);

    public sealed class StepRow<TSession>
    {
        public readonly string Step, From, To;
        public readonly int MessageType;
        public readonly StepRule<TSession> Rule;

        public StepRow(string step, string from, int messageType, StepRule<TSession> rule, string to)
        {
            Step = step; From = from; MessageType = messageType; Rule = rule; To = to;
        }
    }

    public sealed class StepTable<TSession>
    {
        readonly StepRow<TSession>[] _rows;

        public StepTable(params StepRow<TSession>[] rows) { _rows = rows; }

        public StepRow<TSession> Find(string state, int type)
        {
            for (int i = 0; i < _rows.Length; i++)
                if (_rows[i].MessageType == type && _rows[i].From == state) return _rows[i];
            return null;
        }

        public string[] Steps
        {
            get
            {
                string[] steps = new string[_rows.Length];
                for (int i = 0; i < _rows.Length; i++) steps[i] = _rows[i].Step;
                return steps;
            }
        }
    }
}
