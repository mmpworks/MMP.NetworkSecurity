using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Crypto;
using NetSec.Io;
using NetSec.Bridge;
using NetSec.Machine;
using NetSec.Trace;

namespace Acceptance
{
    /// <summary>
    /// An IByteLink written by the acceptance author over a plain blocking socket. It is not the product's SocketLink,
    /// so the engines are tested through an independent transport. It records every byte in both directions.
    /// </summary>
    public sealed class RecordingSocketLink : IByteLink
    {
        readonly Socket _s;
        readonly object _gate = new object();
        readonly MemoryStream _sent = new MemoryStream();
        readonly MemoryStream _received = new MemoryStream();

        public RecordingSocketLink(Socket s) { _s = s; }

        public byte[] Sent { get { lock (_gate) { return _sent.ToArray(); } } }
        public byte[] Received { get { lock (_gate) { return _received.ToArray(); } } }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            return Futures.Run<int>(delegate ()
            {
                int got;
                try { got = _s.Receive(b, off, n, SocketFlags.None); }
                catch (SocketException) { return 0; }
                catch (ObjectDisposedException) { return 0; }
                if (got > 0) lock (_gate) { _received.Write(b, off, got); }
                return got;
            });
        }

        public IFuture Write(byte[] b, int off, int n)
        {
            return Futures.Run(delegate ()
            {
                int done = 0;
                while (done < n)
                {
                    int w = _s.Send(b, off + done, n - done, SocketFlags.None);
                    if (w <= 0) throw new IOException("socket closed during write");
                    done += w;
                }
                lock (_gate) { _sent.Write(b, off, n); }
            });
        }

        public void Close() { try { _s.Shutdown(SocketShutdown.Both); } catch (SocketException) { } _s.Close(); }

        public static RecordingSocketLink ConnectTo(int port)
        {
            Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            s.NoDelay = true;
            s.Connect(IPAddress.Loopback, port);
            return new RecordingSocketLink(s);
        }
    }

    /// <summary>A trace sink that keeps every event. The clauses read it after the run.</summary>
    public sealed class RecordingSink : ITraceSink
    {
        readonly List<TraceEvent> _events = new List<TraceEvent>();
        public void Write(TraceEvent e) { lock (_events) { _events.Add(e); } }
        public TraceEvent[] Events { get { lock (_events) { return _events.ToArray(); } } }

        /// <summary>The code of the last failed check, or null when no check failed.</summary>
        public string FailedCheckCode
        {
            get
            {
                TraceEvent[] all = Events;
                for (int i = all.Length - 1; i >= 0; i--)
                    if (all[i].Check != null && !all[i].Check.Passed) return all[i].Check.Code;
                return null;
            }
        }

        public TraceSecret[] AllSecrets
        {
            get
            {
                List<TraceSecret> r = new List<TraceSecret>();
                foreach (TraceEvent e in Events) if (e.Secrets != null) r.AddRange(e.Secrets);
                return r.ToArray();
            }
        }
    }

    /// <summary>Releases every event at once. The engines run free, with no step gate.</summary>
    public sealed class OpenGate : IStepGate
    {
        public IFuture Pass(TraceEvent e) { return Futures.Completed; }
    }

    /// <summary>A repeatable byte source for the engines. Not for real keys. The seed fixes every random byte.</summary>
    public sealed class TestRandom : IRandomSource
    {
        readonly Rng _rng;
        public TestRandom(ulong seed) { _rng = new Rng(seed); }
        public void Fill(byte[] b, int off, int n) { lock (_rng) { byte[] x = _rng.Bytes(n); Array.Copy(x, 0, b, off, n); } }
    }

    public static class Futs
    {
        /// <summary>Waits for a future and fails the clause when it does not finish in time.</summary>
        public static T Get<T>(IFuture<T> f, int ms, string what)
        {
            if (!f.Wait(ms)) throw new FailException(what + " did not finish in " + ms + " ms");
            return f.Result;
        }

        public static void Done(IFuture f, int ms, string what)
        {
            if (!f.Wait(ms)) throw new FailException(what + " did not finish in " + ms + " ms");
            if (f.IsFaulted) throw new FailException(what + " failed: " + f.Exception);
        }
    }
}
