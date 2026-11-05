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

        public IFuture Pass(TraceEvent e)
        {
            lock (_lock)
            {
                if (_open) return Futures.Completed;
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
                if (_waiting.Count > 0) waiter = _waiting.Dequeue();
            if (waiter != null) waiter.TrySetResult();
        }

        public void Run()
        {
            Promise[] released;
            lock (_lock)
            {
                _open = true;
                released = _waiting.ToArray();
                _waiting.Clear();
            }
            for (int i = 0; i < released.Length; i++) released[i].TrySetResult();
        }

        public void Pause()
        {
            lock (_lock) _open = false;
        }
    }

    /// <summary>
    /// The only code that joins an engine to a socket. Two C# 3 iterators run on MMP.AsyncProxy:
    /// the read loop feeds the engine and waits for the outbox to drain, so the engine cannot run ahead of the gate;
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
        bool _publishing;
        bool _ended;
        NetSecError _linkError;
        long _bytesSent, _bytesReceived;

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
            TraceStream s = engine.Stream;
            _wireStream = new TraceStream(s.StreamId + "/wire", s.SessionId, s.TraceId, s.Hop, s.Actor, clock);
        }

        /// <summary>Called on a pool thread with each piece of application data the engine delivers.</summary>
        public Action<AppChunk> OnApp { get; set; }

        public IFuture<PumpResult> Run()
        {
            Append(StartEngine());
            Observed(AsyncProxy.Run(OutboxLoop()));
            Observed(AsyncProxy.Run(ReadLoop()));
            return _result.Future;
        }

        public IFuture Enqueue(EngineCommand command)
        {
            EngineOutput output;
            lock (_lock) output = _engine.Command(command);
            Append(output);
            return Drained();
        }

        EngineOutput StartEngine()
        {
            lock (_lock) return _engine.Start();
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
                yield return Drained();
                if (IsEnded || EngineEnded) yield break;

                IFuture<int> read = _link.Read(buffer, 0, buffer.Length);
                foreach (IFuture wait in AwaitRead(read)) yield return wait;
                if (!read.IsCompleted)
                {
                    NetSecError deadline = NetSecError.Of(ErrorCodes.LinkDeadline, "no bytes for " + _deadlineMs + " ms");
                    deadline.CheckName = "read deadline";
                    End(deadline);
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

        IEnumerable<IFuture> AwaitRead(IFuture<int> read)
        {
            if (_deadlineMs <= 0) { yield return Futures.Observe(read); yield break; }
            IGateState gate = _gate as IGateState;
            if (gate == null) { yield return Futures.WhenAny(read, Futures.Delay(_deadlineMs)); yield break; }

            // A learner can read one event for an hour, so the clock restarts while the gate holds an event.
            // A read that stays open with nothing at the gate has no one left to wake it: a flipped length byte does that.
            int waited = 0;
            while (!read.IsCompleted && waited < _deadlineMs)
            {
                int slice = Math.Min(DeadlineSliceMs, _deadlineMs - waited);
                yield return Futures.WhenAny(read, Futures.Delay(slice));
                waited = gate.IsHolding ? 0 : waited + slice;
            }
        }

        void Take(byte[] buffer, int count)
        {
            EngineOutput output;
            if (count == 0)
            {
                lock (_lock) output = _engine.Command(EngineCommand.PeerClosed);
            }
            else
            {
                _bytesReceived += count;
                byte[] chunk = new byte[count];
                Buffer.BlockCopy(buffer, 0, chunk, 0, count);
                TraceEvent arrival = WireEvent("wire.received", _engine.Peer, _engine.Stream.Actor, null, chunk, null, null);
                lock (_lock)
                {
                    _received.Enqueue(arrival);
                    output = _engine.Feed(buffer, 0, count);
                }
            }
            Append(output);
        }

        IEnumerable<IFuture> OutboxLoop()
        {
            while (true)
            {
                TraceEvent arrival = null;
                EngineOutput output = null;
                IFuture wake = null;
                bool finish = false;
                lock (_lock)
                {
                    if (_received.Count > 0) arrival = _received.Dequeue();
                    else if (_outbox.Count > 0) output = _outbox.Dequeue();
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
            IFuture write = _link.Write(wire, 0, wire.Length);
            yield return Futures.Observe(write);
            if (write.IsFaulted || write.IsCanceled)
            {
                _linkError = NetSecError.Of(ErrorCodes.LinkLost, write.IsFaulted ? write.Exception.Message : "write canceled");
                yield break;
            }
            _bytesSent += wire.Length;
            _sink.Write(sent);
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

        void Append(EngineOutput output)
        {
            Promise wake;
            lock (_lock)
            {
                _outbox.Enqueue(output);
                wake = _outboxWake;
                _outboxWake = null;
            }
            if (wake != null) wake.TrySetResult();
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
            End(_linkError);
        }

        /// <summary>Ends the run once. A link error wins over the engine's status, because the engine never saw the failure.</summary>
        void End(NetSecError linkError)
        {
            Promise wake, drained;
            lock (_lock)
            {
                if (_ended) return;
                _ended = true;
                wake = _outboxWake; _outboxWake = null;
                drained = _drained; _drained = null;
            }
            _link.Close();
            if (wake != null) wake.TrySetResult();
            if (drained != null) drained.TrySetResult();
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
