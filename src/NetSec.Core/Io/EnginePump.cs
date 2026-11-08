using System;
using System.Collections.Generic;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.Io
{
    public sealed class PumpResult
    {
        public readonly EngineStatus Status;
        public readonly NetSecError Error;
        public readonly long BytesSent, BytesReceived;

        public PumpResult(EngineStatus status, NetSecError error, long bytesSent, long bytesReceived)
        {
            Status = status; Error = error; BytesSent = bytesSent; BytesReceived = bytesReceived;
        }
    }

    public sealed class FreeRunGate : IStepGate
    {
        public IFuture Pass(TraceEvent e) { return Futures.Completed; }
    }

    /// <summary>Holds each event until Step releases one. Run opens the gate for good, and Pause closes it again.</summary>
    public sealed class StepGate : IStepGate, IGateState
    {
        readonly object _lock = new object();
        readonly Queue<Promise> _waiting = new Queue<Promise>();
        bool _open;
        bool _stepHeld;

        public IFuture Pass(TraceEvent e)
        {
            lock (_lock)
            {
                if (_open) return Futures.Completed;
                if (_stepHeld)
                {
                    _stepHeld = false;
                    return Futures.Completed;
                }
                Promise waiter = new Promise(PromiseOptions.RunContinuationsAsynchronously);
                _waiting.Enqueue(waiter);
                return waiter.Future;
            }
        }

        public bool IsHolding { get { lock (_lock) return _waiting.Count > 0; } }

        public void Step()
        {
            Promise waiter = null;
            lock (_lock)
            {
                // A lab can do slow work before an event reaches the gate. One step waits for that event. More steps add nothing, because the app resends.
                if (_waiting.Count > 0) waiter = _waiting.Dequeue();
                else _stepHeld = true;
            }
            if (waiter != null) waiter.TrySetResult();
        }

        public void Run()
        {
            Promise[] released;
            lock (_lock)
            {
                _open = true;
                _stepHeld = false;
                released = _waiting.ToArray();
                _waiting.Clear();
            }
            for (int i = 0; i < released.Length; i++) released[i].TrySetResult();
        }

        public void Pause()
        {
            lock (_lock)
            {
                _open = false;
                _stepHeld = false;
            }
        }
    }

    /// <summary>
    /// The only code that joins an engine to a socket. Two C# 3 iterators run on MMP.AsyncProxy:
    /// the read loop feeds the engine. With a gate it waits for the outbox to drain, so the engine cannot run ahead of the gate. With no gate it keeps reading while a write waits, up to InboundBacklogLimit;
    /// the outbox loop is the only code that touches the gate, the Wire tamper point, the sink, and the socket write.
    /// A socket event carries the bytes as they went on the wire, on a stream of its own: TCP chunking can change between
    /// runs, and the engine's own sequence numbers must not change with it.
    /// </summary>
    public sealed class EnginePump
    {
        const int DeadlineSliceMs = 250;

        readonly IProtocolEngine _engine;
        readonly IByteLink _link;
        readonly ITraceSink _sink;
        readonly IStepGate _gate;
        readonly ITamperHook _tamper;
        readonly int _deadlineMs;
        readonly TraceStream _wireStream;
        readonly object _lock = new object();
        readonly Queue<EngineOutput> _outbox = new Queue<EngineOutput>();
        readonly Queue<TraceEvent> _received = new Queue<TraceEvent>();
        readonly Promise<PumpResult> _result = new Promise<PumpResult>();
        Promise _outboxWake;
        Promise _drained;
        Promise _readRoom;
        readonly Queue<int> _outboxSizes = new Queue<int>();
        readonly Queue<PublishWaiter> _publishWaiters = new Queue<PublishWaiter>();
        readonly bool _readsWhileWriting;
        long _inboundBacklog, _queuedOutputs, _publishedOutputs;

        /// <summary>
        /// With no gate, the read loop keeps reading while a write waits, or two ends that both send would each wait for the other. What reads produce
        /// then waits behind that write, so this limit bounds it. Past it, the loop stops reading, and TCP makes the peer wait. A peer that also stops ends in the write deadline.
        /// </summary>
        public const int InboundBacklogLimit = 16 * 1024 * 1024;

        sealed class PublishWaiter
        {
            public readonly long Ticket;
            public readonly Promise Done;
            public PublishWaiter(long ticket, Promise done) { Ticket = ticket; Done = done; }
        }
        bool _publishing;
        bool _ended;
        NetSecError _linkError;
        long _bytesSent, _bytesReceived;

        // Issue #309. A side that holds part of a frame waits the read deadline for the rest. A side that holds nothing waits longer, by role
        // only: the side that opened the connection waits twice the read deadline, the side that accepted it three times. Neither side can see
        // the other's view, so a rule built on a view (such as "who sent last") can tie; a role rule cannot. So a stuck run always ends on a
        // fixed side: the holder of a cut-short frame first; in a mutual wait, the opener. The gap is a whole read deadline (30 s at the
        // default), far above any scheduling jitter. acceptance/CONTRACT.md holds the clause that checks them.
        const int IdleOpenerFactor = 2, IdleAcceptorFactor = 3;

        /// <summary>True for the pump on the side that dialed the connection. The code that builds both pumps of a pair sets it before Run (issue #309).</summary>
        public bool OpenedLink { get; set; }

        public EnginePump(IProtocolEngine engine, IByteLink link, ITraceSink sink, IStepGate gate, ITamperHook tamper, int deadlineMs)
            : this(engine, link, sink, gate, tamper, deadlineMs, new MonotonicClock())
        {
        }

        public EnginePump(IProtocolEngine engine, IByteLink link, ITraceSink sink, IStepGate gate, ITamperHook tamper, int deadlineMs, IClock clock)
        {
            if (engine == null) throw new ArgumentNullException("engine");
            if (link == null) throw new ArgumentNullException("link");
            _engine = engine; _link = link; _sink = sink ?? new NullSink(); _gate = gate ?? new FreeRunGate();
            _tamper = tamper; _deadlineMs = deadlineMs;
            _readsWhileWriting = _gate is FreeRunGate;
            TraceStream s = engine.Stream;
            _wireStream = new TraceStream(s.StreamId + "/wire", s.SessionId, s.TraceId, s.Hop, s.Actor, clock);
        }

        /// <summary>Called on a pool thread with each piece of application data the engine delivers.</summary>
        public Action<AppChunk> OnApp { get; set; }

        public IFuture<PumpResult> Run()
        {
            Drive(delegate { return _engine.Start(); }, false);
            Observed(AsyncProxy.Run(OutboxLoop()));
            Observed(AsyncProxy.Run(ReadLoop()));
            return _result.Future;
        }

        public IFuture Enqueue(EngineCommand command)
        {
            return PublishedThrough(Drive(delegate { return _engine.Command(command); }, false));
        }

        /// <summary>Completes when this output is out. It never waits for a quiet moment, because a two-way flow may have none.</summary>
        IFuture PublishedThrough(long ticket)
        {
            lock (_lock)
            {
                if (_ended || _publishedOutputs >= ticket) return Futures.Completed;
                Promise done = new Promise(PromiseOptions.RunContinuationsAsynchronously);
                _publishWaiters.Enqueue(new PublishWaiter(ticket, done));
                return done.Future;
            }
        }

        void Observed(IFuture loop)
        {
            loop.GetAwaiter().OnCompleted(delegate
            {
                if (loop.IsFaulted) End(NetSecError.Of(ErrorCodes.LinkLost, loop.Exception.Message));
            });
        }

        IEnumerable<IFuture> ReadLoop()
        {
            byte[] buffer = new byte[16384];
            while (!IsEnded)
            {
                yield return ReadMayGo();
                if (IsEnded || EngineEnded) yield break;

                IFuture<int> read = _link.Read(buffer, 0, buffer.Length);
                foreach (IFuture wait in AwaitRead(read)) yield return wait;
                if (!read.IsCompleted)
                {
                    Expire(ExpiryNow());
                    yield break;
                }
                if (read.IsFaulted || read.IsCanceled)
                {
                    if (!IsEnded && !EngineEnded) End(NetSecError.Of(ErrorCodes.LinkLost, read.IsFaulted ? read.Exception.Message : "read canceled"));
                    yield break;
                }
                Take(buffer, read.Result);
            }
        }

        /// <summary>A gate needs the drain wait: a learner holds each event, and the engine must not run ahead of what the learner has seen.</summary>
        IFuture ReadMayGo()
        {
            if (!_readsWhileWriting) return Drained();
            lock (_lock)
            {
                if (_ended || _inboundBacklog < InboundBacklogLimit) return Futures.Completed;
                if (_readRoom == null) _readRoom = new Promise(PromiseOptions.RunContinuationsAsynchronously);
                return _readRoom.Future;
            }
        }

        /// <summary>
        /// A learner can read one event for an hour, so the clock restarts while the gate holds an event. It also restarts while this side has output to
        /// write: a long upload with no reply is no silent peer, and a stuck write has its own deadline.
        /// A read that stays open with nothing else going on has no one left to wake it: a flipped length byte does that.
        /// </summary>
        IEnumerable<IFuture> AwaitRead(IFuture<int> read)
        {
            if (_deadlineMs <= 0) { yield return Futures.Observe(read); yield break; }
            int waited = 0;
            while (!read.IsCompleted && waited < ReadLimitMs())
            {
                int slice = Math.Min(DeadlineSliceMs, ReadLimitMs() - waited);
                yield return Futures.WhenAny(read, Futures.Delay(slice));
                waited = LearnerHolds || OutboxBusy ? 0 : waited + slice;
            }
        }

        /// <summary>True while the engine holds unconsumed input. An engine that cannot say keeps the read deadline on every read, as before #309.</summary>
        bool HoldsPartialInput
        {
            get
            {
                IPartialInput partial = _engine as IPartialInput;
                if (partial == null) return true;
                lock (_lock) return partial.HoldsPartialInput;
            }
        }

        /// <summary>How long this read may wait now (issue #309): the read deadline while part of a frame waits, else an idle limit by role.</summary>
        int ReadLimitMs()
        {
            if (HoldsPartialInput) return _deadlineMs;
            return _deadlineMs * (OpenedLink ? IdleOpenerFactor : IdleAcceptorFactor);
        }

        NetSecError ExpiryNow()
        {
            int limit = ReadLimitMs();
            if (HoldsPartialInput)
            {
                NetSecError deadline = NetSecError.Of(ErrorCodes.LinkDeadline, "no bytes for " + limit + " ms while part of a message waited");
                deadline.CheckName = "read deadline";
                return deadline;
            }
            NetSecError idle = NetSecError.Of(ErrorCodes.LinkIdle, "no bytes for " + limit + " ms while waiting for the next message");
            idle.CheckName = "idle limit";
            return idle;
        }

        /// <summary>
        /// The engine fails with the expiry as a named check, so it shows in the trace, and the outbox then concludes the run as for any engine
        /// failure. An engine that ignores Expire (a test fake) is ended here, as before #309.
        /// </summary>
        void Expire(NetSecError expiry)
        {
            Drive(delegate { return _engine.Command(EngineCommand.Expire(expiry)); }, false);
            if (!EngineEnded) End(expiry);
        }

        /// <summary>A peer that stops reading parks a write, and only this ends that wait. The clock restarts only while a learner holds an event.</summary>
        IEnumerable<IFuture> AwaitWrite(IFuture write)
        {
            if (_deadlineMs <= 0) { yield return Futures.Observe(write); yield break; }
            int waited = 0;
            while (!write.IsCompleted && waited < _deadlineMs)
            {
                int slice = Math.Min(DeadlineSliceMs, _deadlineMs - waited);
                yield return Futures.WhenAny(write, Futures.Delay(slice));
                waited = LearnerHolds ? 0 : waited + slice;
            }
        }

        bool LearnerHolds
        {
            get
            {
                IGateState gate = _gate as IGateState;
                return gate != null && gate.IsHolding;
            }
        }

        bool OutboxBusy { get { lock (_lock) return _publishing || _outbox.Count > 0; } }

        void Take(byte[] buffer, int count)
        {
            if (count == 0)
            {
                Drive(delegate { return _engine.Command(EngineCommand.PeerClosed); }, true);
            }
            else
            {
                _bytesReceived += count;
                byte[] chunk = new byte[count];
                Buffer.BlockCopy(buffer, 0, chunk, 0, count);
                TraceEvent arrival = WireEvent("wire.received", _engine.Peer, _engine.Stream.Actor, null, chunk, null, null);
                Drive(delegate
                {
                    _received.Enqueue(arrival);
                    return _engine.Feed(buffer, 0, count);
                }, true);
            }
        }

        IEnumerable<IFuture> OutboxLoop()
        {
            while (true)
            {
                TraceEvent arrival = null;
                EngineOutput output = null;
                IFuture wake = null;
                bool finish = false;
                int size = 0;
                lock (_lock)
                {
                    if (_received.Count > 0) arrival = _received.Dequeue();
                    else if (_outbox.Count > 0)
                    {
                        output = _outbox.Dequeue();
                        size = _outboxSizes.Dequeue();
                    }
                    else if (_ended) finish = true;
                    else wake = ParkOutbox();
                    _publishing = arrival != null || output != null;
                }
                if (finish) yield break;
                if (wake != null) { yield return wake; continue; }
                if (arrival != null)
                {
                    yield return _gate.Pass(arrival);
                    _sink.Write(arrival);
                    continue;
                }
                foreach (IFuture step in Publish(output)) yield return step;
                OutputPublished(size);
                if (_linkError != null) { Conclude(); yield break; }
                if (output.Status == EngineStatus.Closed || output.Status == EngineStatus.Failed) { Conclude(); yield break; }
            }
        }

        IEnumerable<IFuture> Publish(EngineOutput output)
        {
            for (int i = 0; i < output.Items.Length; i++)
            {
                OutputItem item = output.Items[i];
                yield return _gate.Pass(item.Event);
                _sink.Write(item.Event);
                if (item.Wire == null) continue;
                foreach (IFuture step in SendWire(item)) yield return step;
                if (_linkError != null) yield break;
            }
            Deliver(output);
        }

        IEnumerable<IFuture> SendWire(OutputItem item)
        {
            byte[] wire = item.Wire;
            if (_tamper != null)
            {
                TamperResult result = _tamper.Apply(TamperPoint.Wire, _engine.Stream.StreamId, item.Event.StreamSeq, item.Event.Message, wire);
                if (result != null && result.Bytes != null) wire = result.Bytes;
            }
            TraceEvent sent = WireEvent("wire.sent", _engine.Stream.Actor, _engine.Peer, item.Event.Message, wire, item.Event.Plain, item.Event.Fields);
            yield return _gate.Pass(sent);
            // Logged before the write. Once the bytes leave, the peer can answer and log its reply, and the session list is one order across both pumps.
            // A write that then fails leaves this event behind, so a wire.write.failed event follows it. The run's result cannot say so on the alert path (see Conclude).
            _sink.Write(sent);
            IFuture write = _link.Write(wire, 0, wire.Length);
            foreach (IFuture wait in AwaitWrite(write)) yield return wait;
            if (!write.IsCompleted)
            {
                _linkError = NetSecError.Of(ErrorCodes.LinkDeadline, "the peer took no bytes for " + _deadlineMs + " ms");
                _linkError.CheckName = "write deadline";
                LogLostWrite(sent, _linkError.Code);
                yield break;
            }
            if (write.IsFaulted || write.IsCanceled)
            {
                _linkError = NetSecError.Of(ErrorCodes.LinkLost, write.IsFaulted ? write.Exception.Message : "write canceled");
                LogLostWrite(sent, _linkError.Code);
                yield break;
            }
            _bytesSent += wire.Length;
        }

        void LogLostWrite(TraceEvent sent, string code)
        {
            _sink.Write(_wireStream.Stamp(TraceEventDraft.LostWrite(sent, code)));
        }

        void Deliver(EngineOutput output)
        {
            Action<AppChunk> handler = OnApp;
            if (handler == null) return;
            for (int i = 0; i < output.App.Length; i++)
            {
                AppChunk chunk = new AppChunk();
                chunk.Channel = output.App[i].Channel;
                chunk.Bytes = output.App[i].Bytes;
                handler(chunk);
            }
        }

        TraceEvent WireEvent(string type, string from, string to, string message, byte[] wire, byte[] plain, TraceField[] fields)
        {
            TraceEventDraft draft = new TraceEventDraft();
            draft.Type = type; draft.From = from; draft.To = to; draft.Message = message;
            draft.Wire = wire; draft.Plain = plain; draft.Fields = fields;
            return _wireStream.Stamp(draft);
        }

        /// <summary>
        /// Runs the engine and queues what it made under one lock. A record cipher numbers records in the order the engine makes them.
        /// With a gap between the call and the queue, a caller's Enqueue and the read loop could swap, and a clean link then failed its AEAD tag.
        /// </summary>
        long Drive(Func<EngineOutput> call, bool fromRead)
        {
            Promise wake;
            long ticket;
            lock (_lock)
            {
                EngineOutput output = call();
                int size = fromRead ? SizeOf(output) : 0;
                _outbox.Enqueue(output);
                _outboxSizes.Enqueue(size);
                _inboundBacklog += size;
                ticket = ++_queuedOutputs;
                wake = _outboxWake;
                _outboxWake = null;
            }
            if (wake != null) wake.TrySetResult();
            return ticket;
        }

        /// <summary>Counts wire and app bytes, because app bytes wait behind a stuck write too. A caller's own sends stay out: the caller paces those.</summary>
        static int SizeOf(EngineOutput output)
        {
            int size = 0;
            for (int i = 0; i < output.Items.Length; i++)
                if (output.Items[i].Wire != null) size += output.Items[i].Wire.Length;
            for (int i = 0; i < output.App.Length; i++)
                if (output.App[i].Bytes != null) size += output.App[i].Bytes.Length;
            return size;
        }

        void OutputPublished(int size)
        {
            List<Promise> done = new List<Promise>();
            Promise room = null;
            lock (_lock)
            {
                _publishedOutputs++;
                _inboundBacklog -= size;
                while (_publishWaiters.Count > 0 && _publishWaiters.Peek().Ticket <= _publishedOutputs) done.Add(_publishWaiters.Dequeue().Done);
                if (_inboundBacklog < InboundBacklogLimit)
                {
                    room = _readRoom;
                    _readRoom = null;
                }
            }
            for (int i = 0; i < done.Count; i++) done[i].TrySetResult();
            if (room != null) room.TrySetResult();
        }

        IFuture ParkOutbox()
        {
            _outboxWake = new Promise(PromiseOptions.RunContinuationsAsynchronously);
            IFuture wake = _outboxWake.Future;
            Promise drained = _drained;
            _drained = null;
            if (drained != null) drained.TrySetResult();
            return wake;
        }

        IFuture Drained()
        {
            lock (_lock)
            {
                if (_ended) return Futures.Completed;
                if (_received.Count == 0 && _outbox.Count == 0 && !_publishing) return Futures.Completed;
                if (_drained == null) _drained = new Promise(PromiseOptions.RunContinuationsAsynchronously);
                return _drained.Future;
            }
        }

        bool IsEnded { get { lock (_lock) return _ended; } }
        bool EngineEnded { get { return _engine.Status == EngineStatus.Closed || _engine.Status == EngineStatus.Failed; } }

        void Conclude()
        {
            // A failed engine's last write is its alert, and the peer may already be gone. The engine's named failure is the news, so a lost write does not replace it.
            End(_engine.Status == EngineStatus.Failed ? null : _linkError);
        }

        /// <summary>Ends the run once. A link error wins over the engine's status, because the engine never saw the failure.</summary>
        void End(NetSecError linkError)
        {
            Promise wake, drained, room;
            PublishWaiter[] waiters;
            lock (_lock)
            {
                if (_ended) return;
                _ended = true;
                wake = _outboxWake; _outboxWake = null;
                drained = _drained; _drained = null;
                room = _readRoom; _readRoom = null;
                waiters = _publishWaiters.ToArray();
                _publishWaiters.Clear();
            }
            _link.Close();
            if (wake != null) wake.TrySetResult();
            if (drained != null) drained.TrySetResult();
            if (room != null) room.TrySetResult();
            for (int i = 0; i < waiters.Length; i++) waiters[i].Done.TrySetResult();
            EngineStatus status = linkError != null ? EngineStatus.Failed : _engine.Status;
            NetSecError error = linkError;
            if (error == null)
            {
                EngineOutput last;
                lock (_lock) last = _engine.Command(EngineCommand.Close);
                status = last.Status;
                error = last.Error;
            }
            _result.TrySetResult(new PumpResult(status, error, _bytesSent, _bytesReceived));
        }
    }
}
