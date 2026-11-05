using System;
using System.Collections.Generic;
using System.Text;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Native;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.Labs
{
    /// <summary>
    /// Lesson 11. A control run measures both compares, measures the managed compare, and runs the guess loop against both native compares.
    /// An attack row runs one guess loop. Times are measured numbers on the run's machine. Managed code has no constant-time guarantee,
    /// and the C++ result depends on the optimizer.
    /// </summary>
    public sealed class TimingAttackLab : ILab
    {
        public const string GuessOption = "guess-target";
        public const string GuessLeaky = "leaky";
        public const string GuessConstantTime = "constant-time";
        public const string ConstantTimeCheck = "constant-time compare";
        public const string SeparationCheck = "leaky compare separates";
        public const string LeakyGuessCheck = "guess loop reads the leak";

        public const int BufferSize = 4096;
        public const int Samples = 100000;
        public const int ManagedSamples = 20000;
        public const int SecretBytes = 4;

        const string Attacker = "attacker", Target = "target";

        public string LabId { get { return "lab-11-timing"; } }

        public IFuture<LabResult> Run(LabContext context)
        {
            if (context == null) throw new ArgumentNullException("context");
            return AsyncProxy.Run<LabResult>(delegate(Return<LabResult> ret) { return Body(context, ret); });
        }

        /// <summary>A work item's outcome. The lab reads a named error from here and never from a faulted future.</summary>
        sealed class Attempt<T>
        {
            public T Value;
            public NetSecError Error;
        }

        sealed class Lanes
        {
            public LabContext Context;
            public TraceStream Attacker, Target;
        }

        sealed class Measured
        {
            public TimingCase[] Leaky, Constant, Control, Managed;
        }

        static IEnumerable<IFuture> Body(LabContext c, Return<LabResult> ret)
        {
            Lanes lanes = new Lanes();
            lanes.Context = c;
            lanes.Attacker = Stream(c, Attacker);
            lanes.Target = Stream(c, Target);
            byte[] secret = LabBytes.Fill(SecretBytes, c.Seed);
            string guessTarget = GuessTargetOf(c.Attack);

            foreach (IFuture step in Emit(lanes, lanes.Target, Started(secret))) yield return step;

            LabResult result = new LabResult();
            result.Completed = true;
            ret.Value = result;

            if (guessTarget == null)
            {
                foreach (IFuture step in MeasureSteps(lanes, result)) yield return step;
                if (!result.Completed) yield break;
            }
            if (guessTarget != GuessConstantTime)
            {
                foreach (IFuture step in GuessSteps(lanes, CompareKind.Leaky, secret, guessTarget != null, result)) yield return step;
                if (!result.Completed) yield break;
            }
            if (guessTarget != GuessLeaky)
            {
                foreach (IFuture step in GuessSteps(lanes, CompareKind.ConstantTime, secret, guessTarget != null, result)) yield return step;
            }
        }

        /// <summary>Takes the samples on a pool thread, so a long measure never holds the caller, then emits one event per case and the verdict.</summary>
        static IEnumerable<IFuture> MeasureSteps(Lanes lanes, LabResult result)
        {
            IFuture<Attempt<Measured>> work = Futures.Run<Attempt<Measured>>(delegate { return Try<Measured>(Measure); });
            yield return work;
            if (work.Result.Error != null)
            {
                foreach (IFuture step in Fail(lanes, work.Result.Error, "measure", result)) yield return step;
                yield break;
            }

            Measured m = work.Result.Value;
            TimingCase[] cases = new TimingCase[] { m.Leaky[0], m.Leaky[1], m.Constant[0], m.Constant[1] };
            for (int i = 0; i < cases.Length; i++)
                foreach (IFuture step in Emit(lanes, lanes.Target, SampleEvent(cases[i], "timing.samples", "Time of one compare"))) yield return step;

            TimingVerdict leaky = TimingJudge.Judge(m.Leaky[0], m.Leaky[1]);
            TimingVerdict constant = TimingJudge.Judge(m.Constant[0], m.Constant[1]);
            TimingVerdict control = TimingJudge.Judge(m.Control[0], m.Control[1]);
            TimingVerdict managed = TimingJudge.Judge(m.Managed[0], m.Managed[1]);

            foreach (IFuture step in Emit(lanes, lanes.Target, SampleEvent(m.Managed[0], "timing.managed", ManagedStatement))) yield return step;
            foreach (IFuture step in Emit(lanes, lanes.Target, SampleEvent(m.Managed[1], "timing.managed", ManagedStatement))) yield return step;

            bool separated = TimingJudge.Separated(leaky, constant);
            string detail = TimingReport.Verdict(leaky, constant, control, managed);
            TraceEventDraft verdict = Draft("timing.verdict", "Welch t: the leaky compare against the constant-time compare", "measure", null);
            verdict.Plain = Utf8(detail);
            verdict.Check = MakeCheck(SeparationCheck, separated, separated ? null : ErrorCodes.TimingNotSeparated, detail);
            foreach (IFuture step in Emit(lanes, lanes.Target, verdict)) yield return step;
            if (!separated) Stop(result, ErrorCodes.TimingNotSeparated, SeparationCheck);
        }

        const string ManagedStatement = "Managed code has no constant-time guarantee. The JIT may change this code while it runs, so this number holds for this run only.";

        static Measured Measure()
        {
            Measured m = new Measured();
            m.Leaky = TimingLab.Interleaved(CompareKind.Leaky, BufferSize, Samples, 0, BufferSize - 1);
            m.Constant = TimingLab.Interleaved(CompareKind.ConstantTime, BufferSize, Samples, 0, BufferSize - 1);
            m.Control = TimingLab.Interleaved(CompareKind.ConstantTime, BufferSize, Samples, 0, 0);
            m.Managed = TimingLab.InterleavedManaged(BufferSize, ManagedSamples, 0, BufferSize - 1);
            return m;
        }

        /// <summary>Runs one guess loop. An attack row reports the outcome by check. A control run needs the leak read and the constant-time guess stopped.</summary>
        static IEnumerable<IFuture> GuessSteps(Lanes lanes, CompareKind kind, byte[] secret, bool isAttack, LabResult result)
        {
            string step = kind == CompareKind.Leaky ? "guess-leaky" : "guess-constant-time";
            IFuture<Attempt<GuessResult>> work = Futures.Run<Attempt<GuessResult>>(delegate
            {
                return Try<GuessResult>(delegate { return TimingGuess.Recover(kind, secret); });
            });
            yield return work;
            if (work.Result.Error != null)
            {
                foreach (IFuture s in Fail(lanes, work.Result.Error, step, result)) yield return s;
                yield break;
            }

            GuessResult guess = work.Result.Value;
            TraceEventDraft finished = Draft("timing.guess.finished", guess.CorrectBytes + " of " + guess.Recovered.Length + " secret bytes recovered from the " + guess.Compare + " compare", step, null);
            finished.Plain = Utf8(TimingReport.Guess(guess));
            finished.From = Attacker;
            finished.To = Target;
            finished.Check = GuessCheck(kind, guess, isAttack);
            foreach (IFuture s in Emit(lanes, lanes.Attacker, finished)) yield return s;
            if (finished.Check != null && !finished.Check.Passed) Stop(result, finished.Check.Code, finished.Check.Name);
        }

        /// <summary>
        /// The leak must read in every run, or the machine is too noisy to show it. The constant-time check fails only on the attack row, where a
        /// failed check means the check stopped the attacker. A control run reports the guess with no check, so a control has no failed check.
        /// </summary>
        static TraceCheck GuessCheck(CompareKind kind, GuessResult guess, bool isAttack)
        {
            string detail = guess.CorrectBytes + " of " + guess.Recovered.Length + " bytes";
            if (kind == CompareKind.Leaky)
                return MakeCheck(LeakyGuessCheck, guess.RecoveredAll, guess.RecoveredAll ? null : ErrorCodes.TimingNotSeparated, detail);
            if (guess.RecoveredAll) return MakeCheck(ConstantTimeCheck, false, ErrorCodes.TimingNotSeparated, "the guess recovered the whole secret from the constant-time compare. " + detail);
            return isAttack ? MakeCheck(ConstantTimeCheck, false, ErrorCodes.TimingGuessStopped, "flat timing gave the attacker " + detail) : null;
        }

        static IEnumerable<IFuture> Fail(Lanes lanes, NetSecError error, string step, LabResult result)
        {
            string check = error.CheckName ?? step;
            TraceEventDraft draft = Draft("timing.failed", error.Message, step, MakeCheck(check, false, error.Code, error.Message));
            foreach (IFuture s in Emit(lanes, lanes.Target, draft)) yield return s;
            Stop(result, error.Code, check);
        }

        static void Stop(LabResult result, string code, string check)
        {
            result.Completed = false;
            result.FailedCode = code;
            result.FailedCheck = check;
        }

        static Attempt<T> Try<T>(Func<T> work)
        {
            Attempt<T> attempt = new Attempt<T>();
            try { attempt.Value = work(); }
            catch (NetSecException e) { attempt.Error = e.Error; }
            return attempt;
        }

        static IEnumerable<IFuture> Emit(Lanes lanes, TraceStream stream, TraceEventDraft draft)
        {
            TraceEvent e = stream.Stamp(draft);
            yield return lanes.Context.Gate.Pass(e);
            lanes.Context.Sink.Write(e);
        }

        static string GuessTargetOf(AttackDefinition attack)
        {
            if (attack == null) return null;
            LabOption[] options = attack.Options;
            if (options != null && options.Length == 1 && options[0].Name == GuessOption
                && (options[0].Value == GuessLeaky || options[0].Value == GuessConstantTime)) return options[0].Value;
            throw new ArgumentException("lesson 11 has no attack named " + attack.AttackId);
        }

        static TraceEventDraft Started(byte[] secret)
        {
            TraceEventDraft draft = Draft("timing.lab.started", "The lab times each compare inside native code. All numbers are from this machine.", "start", null);
            draft.Plain = Utf8(TimingReport.Machine());
            TraceSecret held = new TraceSecret();
            held.Holder = Target;
            held.Name = "lab-secret";
            held.Bytes = secret;
            draft.Secrets = new TraceSecret[] { held };
            return draft;
        }

        static TraceEventDraft SampleEvent(TimingCase c, string type, string message)
        {
            TraceEventDraft draft = Draft(type, message, "measure", null);
            draft.Plain = Utf8(TimingReport.Case(c));
            return draft;
        }

        static TraceEventDraft Draft(string type, string message, string step, TraceCheck check)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = type;
            draft.Message = message;
            draft.Step = step;
            draft.Check = check;
            return draft;
        }

        static TraceCheck MakeCheck(string name, bool passed, string code, string detail)
        {
            TraceCheck check = new TraceCheck();
            check.Id = name;
            check.Name = name;
            check.Passed = passed;
            check.Code = code;
            check.Detail = detail;
            return check;
        }

        static byte[] Utf8(string text) { return Encoding.UTF8.GetBytes(text); }

        static TraceStream Stream(LabContext c, string actor)
        {
            return new TraceStream(c.SessionId + "/" + actor + "/timing", c.SessionId, c.TraceId, null, actor, c.Clock);
        }
    }
}
