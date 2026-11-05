using System;
using System.Collections.Generic;
using System.Net.Sockets;
using MMP.AsyncProxy;
using NetSec.Errors;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Ssh;
using NetSec.Trace;

namespace NetSec.Io
{
    /// <summary>
    /// Joins one SSH engine to one link through EnginePump, and gives the code above it channels. The engine reports up through control
    /// notes in the app chunk stream, so the pump stays free of SSH. On the server role this class also carries each allowed tunnel
    /// to its target, because the engine holds no socket.
    /// </summary>
    public sealed class GlassSshSession : ISshChannel
    {
        const int RelayBuffer = 16384;

        readonly EnginePump _pump;
        readonly ChannelInfo _info;
        readonly Func<string, int, IFuture<IByteLink>> _openTarget;
        readonly object _lock = new object();
        readonly Promise _opened = new Promise(PromiseOptions.RunContinuationsAsynchronously);
        readonly Promise<PumpResult> _finished = new Promise<PumpResult>(PromiseOptions.RunContinuationsAsynchronously);
        readonly Queue<AppChunk> _chunks = new Queue<AppChunk>();
        readonly Queue<Promise<AppChunk>> _readers = new Queue<Promise<AppChunk>>();
        readonly Dictionary<int, Promise<int>> _opening = new Dictionary<int, Promise<int>>();
        readonly Dictionary<int, Relay> _relays = new Dictionary<int, Relay>();
        string _learnedLine;
        int _nextChannel;
        bool _ended;

        sealed class Relay
        {
            public IByteLink Link;
            public IFuture Tail;
            public Promise Room;
        }

        /// <param name="openTarget">Opens the far end of an allowed tunnel. Null when this side never receives one.</param>
        public GlassSshSession(SshEngine engine, IByteLink link, ITraceSink sink, IStepGate gate, ITamperHook tamper, int deadlineMs, IClock clock, Func<string, int, IFuture<IByteLink>> openTarget)
        {
            if (engine == null) throw new ArgumentNullException("engine");
            _openTarget = openTarget;
            _pump = new EnginePump(engine, new ResetEndsStreamLink(link), sink, gate, tamper, deadlineMs, clock ?? new MonotonicClock());
            _pump.OnApp = OnChunk;
            _info = new ChannelInfo();
            _info.Protocol = "SSH-2.0";
            _info.Suite = engine.Algorithms.CipherAndMac;
            _info.Group = engine.Algorithms.Kex;
            _info.PeerName = engine.Peer;
        }

        public ChannelInfo Info { get { return _info; } }

        /// <summary>Set only after a trust-on-first-use connect: the known_hosts line to store and pass back on each later connect.</summary>
        public string LearnedKnownHostsLine { get { lock (_lock) return _learnedLine; } }

        /// <summary>Completes when the user is authenticated. Faults with the named error when the session ends first.</summary>
        public IFuture Opened { get { return _opened.Future; } }

        /// <summary>Completes when the pump ends, with the engine's status and its named error.</summary>
        public IFuture<PumpResult> Finished { get { return _finished.Future; } }

        public void Run()
        {
            IFuture<PumpResult> run = _pump.Run();
            run.ContinueOnAnyThread().OnCompleted(delegate { OnEnded(run.Result); });
        }

        public IFuture<int> OpenExec(string command) { return Open(EngineCommandKind.Exec, command); }

        public IFuture<int> OpenTunnel(string host, int port) { return Open(EngineCommandKind.OpenChannel, host + ":" + port); }

        IFuture<int> Open(EngineCommandKind kind, string text)
        {
            Promise<int> ready = new Promise<int>(PromiseOptions.RunContinuationsAsynchronously);
            int channel;
            lock (_lock)
            {
                if (_ended) return Futures.FromException<int>(EndedException(null));
                channel = _nextChannel++;
                _opening[channel] = ready;
            }
            _pump.Enqueue(new EngineCommand(kind, channel, null, text));
            return ready.Future;
        }

        /// <summary>Empty bytes end the channel: EOF, then close.</summary>
        public IFuture Send(int channel, byte[] bytes)
        {
            return _pump.Enqueue(new EngineCommand(EngineCommandKind.Send, channel, bytes, null));
        }

        /// <summary>The next piece of data. Empty Bytes mean that channel ended. Faults when the session has ended and nothing is left.</summary>
        public IFuture<AppChunk> Receive()
        {
            AppChunk ready;
            lock (_lock)
            {
                if (_chunks.Count == 0)
                {
                    if (_ended) return Futures.FromException<AppChunk>(EndedException(null));
                    Promise<AppChunk> waiter = new Promise<AppChunk>(PromiseOptions.RunContinuationsAsynchronously);
                    _readers.Enqueue(waiter);
                    return waiter.Future;
                }
                ready = _chunks.Dequeue();
            }
            Consumed(ready);
            return Futures.FromResult<AppChunk>(ready);
        }

        /// <summary>The read is what grants window back, so a reader that stops makes the peer wait.</summary>
        void Consumed(AppChunk chunk)
        {
            if (chunk.Bytes.Length > 0) _pump.Enqueue(new EngineCommand(EngineCommandKind.Consumed, chunk.Channel, chunk.Bytes, null));
        }

        /// <summary>Sends Disconnect when the session is open, then ends. It waits for the pump.</summary>
        public IFuture Close()
        {
            bool ended;
            lock (_lock) ended = _ended;
            if (!ended) _pump.Enqueue(new EngineCommand(EngineCommandKind.Close, 0, null, "disconnect"));
            return Finished;
        }

        void OnChunk(AppChunk chunk)
        {
            if (chunk.Channel == SshControl.Channel) { OnControl(chunk.Bytes); return; }
            Relay relay;
            lock (_lock) _relays.TryGetValue(chunk.Channel, out relay);
            if (relay != null) { ToRelay(chunk.Channel, relay, chunk.Bytes); return; }
            Promise<AppChunk> waiter = null;
            lock (_lock)
            {
                if (_readers.Count > 0) waiter = _readers.Dequeue();
                else _chunks.Enqueue(chunk);
            }
            if (waiter == null) return;
            Consumed(chunk);
            waiter.TrySetResult(chunk);
        }

        void OnControl(byte[] note)
        {
            int channel = SshControl.ChannelOf(note);
            switch (SshControl.Kind(note))
            {
                case SshControl.Authenticated: _opened.TrySetResult(); break;
                case SshControl.ChannelReady: ChannelReady(channel); break;
                case SshControl.TunnelRequested: StartRelay(channel, SshControl.Text(note)); break;
                case SshControl.PeerEof: PeerFinished(channel); break;
                case SshControl.HostKeyLearned: lock (_lock) _learnedLine = SshControl.Text(note); break;
                case SshControl.WindowFull: SetRoom(channel, false); break;
                case SshControl.WindowOpen: SetRoom(channel, true); break;
            }
        }

        /// <summary>A relay stops reading its target while the peer's window is full, so a fast target cannot fill this side's memory.</summary>
        void SetRoom(int channel, bool hasRoom)
        {
            Promise wake = null;
            lock (_lock)
            {
                Relay relay;
                if (!_relays.TryGetValue(channel, out relay)) return;
                if (!hasRoom) relay.Room = new Promise(PromiseOptions.RunContinuationsAsynchronously);
                else { wake = relay.Room; relay.Room = null; }
            }
            if (wake != null) wake.TrySetResult();
        }

        /// <summary>The peer sent all it will send. IByteLink has no half close, so the target closes whole, and its read then ends the channel from this side.</summary>
        void PeerFinished(int channel)
        {
            Relay relay;
            lock (_lock) _relays.TryGetValue(channel, out relay);
            if (relay != null) ToRelay(channel, relay, new byte[0]);
        }

        void ChannelReady(int channel)
        {
            Promise<int> ready;
            lock (_lock)
            {
                if (!_opening.TryGetValue(channel, out ready)) return;
                _opening.Remove(channel);
            }
            ready.TrySetResult(channel);
        }

        void OnEnded(PumpResult result)
        {
            Promise<AppChunk>[] readers;
            Promise<int>[] opening;
            Relay[] relays;
            lock (_lock)
            {
                _ended = true;
                readers = _readers.ToArray();
                _readers.Clear();
                opening = new Promise<int>[_opening.Count];
                _opening.Values.CopyTo(opening, 0);
                _opening.Clear();
                relays = new Relay[_relays.Count];
                _relays.Values.CopyTo(relays, 0);
                _relays.Clear();
            }
            Exception ended = EndedException(result.Error);
            _opened.TrySetException(ended);
            for (int i = 0; i < readers.Length; i++) readers[i].TrySetException(ended);
            for (int i = 0; i < opening.Length; i++) opening[i].TrySetException(ended);
            for (int i = 0; i < relays.Length; i++) CloseRelay(relays[i]);
            _finished.TrySetResult(result);
        }

        static Exception EndedException(NetSecError error)
        {
            return new NetSecException(error ?? NetSecError.Of(ErrorCodes.LinkLost, "the SSH session has ended"));
        }

        // ---------------------------------------------------------------- server role: an allowed tunnel to its target

        /// <summary>Bytes can arrive before the target connects. Each write waits for the one before it, and the first waits for the connect.</summary>
        void StartRelay(int channel, string target)
        {
            if (_openTarget == null) { Send(channel, new byte[0]); return; }
            int colon = target.LastIndexOf(':');
            IFuture<IByteLink> connecting = _openTarget(target.Substring(0, colon), int.Parse(target.Substring(colon + 1)));
            Relay relay = new Relay();
            lock (_lock) _relays[channel] = relay;
            relay.Tail = AsyncProxy.Run(RelayConnect(channel, relay, connecting));
        }

        IEnumerable<IFuture> RelayConnect(int channel, Relay relay, IFuture<IByteLink> connecting)
        {
            yield return Futures.Observe(connecting);
            if (connecting.IsFaulted || connecting.IsCanceled)
            {
                Send(channel, new byte[0]);
                yield break;
            }
            relay.Link = connecting.Result;
            AsyncProxy.Run(RelayRead(channel, relay));
        }

        IEnumerable<IFuture> RelayRead(int channel, Relay relay)
        {
            byte[] buffer = new byte[RelayBuffer];
            while (true)
            {
                Promise room;
                lock (_lock) room = relay.Room;
                if (room != null) yield return room.Future;
                IFuture<int> read = relay.Link.Read(buffer, 0, buffer.Length);
                yield return Futures.Observe(read);
                if (read.IsFaulted || read.IsCanceled || read.Result == 0)
                {
                    Send(channel, new byte[0]);
                    yield break;
                }
                byte[] chunk = new byte[read.Result];
                Buffer.BlockCopy(buffer, 0, chunk, 0, chunk.Length);
                yield return Futures.Observe(Send(channel, chunk));
            }
        }

        void ToRelay(int channel, Relay relay, byte[] bytes)
        {
            lock (_lock)
            {
                if (bytes.Length == 0) _relays.Remove(channel);
                relay.Tail = AsyncProxy.Run(RelayWrite(channel, relay, relay.Tail, bytes));
            }
        }

        IEnumerable<IFuture> RelayWrite(int channel, Relay relay, IFuture before, byte[] bytes)
        {
            yield return Futures.Observe(before);
            if (relay.Link == null) yield break;
            if (bytes.Length == 0)
            {
                relay.Link.Close();
                yield break;
            }
            yield return Futures.Observe(relay.Link.Write(bytes, 0, bytes.Length));
            _pump.Enqueue(new EngineCommand(EngineCommandKind.Consumed, channel, bytes, null));
        }

        static void CloseRelay(Relay relay)
        {
            if (relay.Room != null) relay.Room.TrySetResult();
            if (relay.Link != null) relay.Link.Close();
        }
    }

    /// <summary>
    /// Windows ssh.exe can end with a TCP reset after its last packet. Read here, that reset is the end of the stream, so the engine decides
    /// what it means: a finished session closes cleanly, and an unfinished one names PEER_CLOSED_EARLY. Any other fault stays a fault.
    /// </summary>
    internal sealed class ResetEndsStreamLink : IByteLink
    {
        const int ConnectionReset = 10054;

        readonly IByteLink _inner;

        public ResetEndsStreamLink(IByteLink inner) { _inner = inner; }

        public IFuture Write(byte[] b, int off, int n) { return _inner.Write(b, off, n); }
        public void Close() { _inner.Close(); }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            return AsyncProxy.Run<int>(delegate(Return<int> ret) { return ReadBody(b, off, n, ret); });
        }

        IEnumerable<IFuture> ReadBody(byte[] b, int off, int n, Return<int> ret)
        {
            IFuture<int> read = _inner.Read(b, off, n);
            yield return Futures.Observe(read);
            if (read.IsFaulted && IsReset(read.Exception)) { ret.Value = 0; yield break; }
            ret.Value = read.Result;
        }

        static bool IsReset(Exception e)
        {
            for (Exception at = e; at != null; at = at.InnerException)
            {
                SocketException socket = at as SocketException;
                if (socket != null && socket.ErrorCode == ConnectionReset) return true;
            }
            return false;
        }
    }

    /// <summary>What a client does with an open session. A lab and a probe run the same steps.</summary>
    public static class SshScript
    {
        /// <summary>Reads one channel into a list until it ends, or until the list holds atLeast bytes when atLeast is above zero.</summary>
        public static IEnumerable<IFuture> Collect(ISecureChannel session, int channel, int atLeast, List<byte> into)
        {
            while (true)
            {
                IFuture<AppChunk> next = session.Receive();
                yield return Futures.Observe(next);
                if (next.IsFaulted || next.IsCanceled) yield break;
                if (next.Result.Channel != channel) continue;
                if (next.Result.Bytes.Length == 0) yield break;
                into.AddRange(next.Result.Bytes);
                if (atLeast > 0 && into.Count >= atLeast) yield break;
            }
        }

        public static IEnumerable<IFuture> Exec(ISshChannel session, string command, List<byte> output)
        {
            IFuture<int> open = session.OpenExec(command);
            yield return Futures.Observe(open);
            if (open.IsFaulted || open.IsCanceled) yield break;
            foreach (IFuture step in Collect(session, open.Result, 0, output)) yield return step;
        }

        /// <summary>Sends the bytes down a tunnel, reads as many back, ends the channel, and waits for the end.</summary>
        public static IEnumerable<IFuture> Tunnel(ISshChannel session, string host, int port, byte[] send, List<byte> output)
        {
            IFuture<int> open = session.OpenTunnel(host, port);
            yield return Futures.Observe(open);
            if (open.IsFaulted || open.IsCanceled) yield break;
            int channel = open.Result;
            if (send != null && send.Length > 0)
            {
                session.Send(channel, send);
                foreach (IFuture step in Collect(session, channel, send.Length, output)) yield return step;
            }
            session.Send(channel, new byte[0]);
            foreach (IFuture step in Collect(session, channel, 0, new List<byte>())) yield return step;
        }
    }
}
