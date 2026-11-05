using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using MMP.AsyncProxy;

namespace NetSec.Io
{
    public interface IByteLink
    {
        IFuture<int> Read(byte[] b, int off, int n);
        IFuture Write(byte[] b, int off, int n);
        void Close();
    }

    /// <summary>A TCP socket behind IByteLink. All four Begin pairs run through Futures.FromAsync on both builds.</summary>
    public sealed class SocketLink : IByteLink
    {
        readonly Socket _socket;
        int _beginSends, _beginReceives;

        internal SocketLink(Socket socket, int beginConnects)
        {
            _socket = socket;
            BeginConnects = beginConnects;
            _socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, true);
        }

        public int BeginConnects { get; private set; }
        public int BeginSends { get { return _beginSends; } }
        public int BeginReceives { get { return _beginReceives; } }

        public static IFuture<SocketLink> Connect(IPEndPoint endpoint)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            return AsyncProxy.Run<SocketLink>(delegate(Return<SocketLink> ret) { return ConnectBody(socket, endpoint, ret); });
        }

        static IEnumerable<IFuture> ConnectBody(Socket socket, IPEndPoint endpoint, Return<SocketLink> ret)
        {
            IFuture<bool> connected = Futures.FromAsync<bool>(
                delegate(AsyncCallback cb, object st) { return socket.BeginConnect(endpoint, cb, st); },
                delegate(IAsyncResult ar) { socket.EndConnect(ar); return true; });
            yield return connected;
            ret.Value = new SocketLink(socket, 1);
        }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            _beginReceives++;
            return Futures.FromAsync<int>(
                delegate(AsyncCallback cb, object st) { return _socket.BeginReceive(b, off, n, SocketFlags.None, cb, st); },
                _socket.EndReceive);
        }

        public IFuture Write(byte[] b, int off, int n)
        {
            return AsyncProxy.Run(WriteBody(b, off, n));
        }

        IEnumerable<IFuture> WriteBody(byte[] b, int off, int n)
        {
            while (n > 0)
            {
                _beginSends++;
                int at = off, left = n;
                IFuture<int> sent = Futures.FromAsync<int>(
                    delegate(AsyncCallback cb, object st) { return _socket.BeginSend(b, at, left, SocketFlags.None, cb, st); },
                    _socket.EndSend);
                yield return sent;
                off += sent.Result;
                n -= sent.Result;
            }
        }

        public void Close()
        {
            try { _socket.Shutdown(SocketShutdown.Both); }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            _socket.Close();
        }
    }

    public sealed class LinkListener
    {
        readonly Socket _socket;
        int _beginAccepts;

        public LinkListener(IPEndPoint endpoint)
        {
            _socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            _socket.Bind(endpoint);
            _socket.Listen(8);
            Port = ((IPEndPoint)_socket.LocalEndPoint).Port;
        }

        public int Port { get; private set; }
        public int BeginAccepts { get { return _beginAccepts; } }

        public IFuture<SocketLink> Accept()
        {
            _beginAccepts++;
            return Futures.FromAsync<SocketLink>(
                delegate(AsyncCallback cb, object st) { return _socket.BeginAccept(cb, st); },
                delegate(IAsyncResult ar) { return new SocketLink(_socket.EndAccept(ar), 0); });
        }

        public void Close() { _socket.Close(); }
    }

    /// <summary>A pair of linked in-process byte pipes, so a pump test needs no port.</summary>
    public sealed class MemoryLink : IByteLink
    {
        readonly object _gate = new object();
        readonly Queue<byte> _incoming = new Queue<byte>();
        MemoryLink _other;
        Promise<int> _pendingRead;
        byte[] _readBuffer;
        int _readOffset, _readCount;
        bool _closed;

        MemoryLink() { }

        public static MemoryLink[] Pair()
        {
            MemoryLink a = new MemoryLink(), b = new MemoryLink();
            a._other = b;
            b._other = a;
            return new MemoryLink[] { a, b };
        }

        public IFuture<int> Read(byte[] b, int off, int n)
        {
            lock (_gate)
            {
                if (_incoming.Count > 0) return Futures.FromResult<int>(Drain(b, off, n));
                if (_closed) return Futures.FromResult<int>(0);
                _pendingRead = new Promise<int>(PromiseOptions.RunContinuationsAsynchronously);
                _readBuffer = b; _readOffset = off; _readCount = n;
                return _pendingRead.Future;
            }
        }

        public IFuture Write(byte[] b, int off, int n)
        {
            _other.Arrive(b, off, n);
            return Futures.Completed;
        }

        public void Close()
        {
            Finish();
            _other.Finish();
        }

        void Arrive(byte[] b, int off, int n)
        {
            Promise<int> ready = null;
            int count = 0;
            lock (_gate)
            {
                for (int i = 0; i < n; i++) _incoming.Enqueue(b[off + i]);
                if (_pendingRead != null)
                {
                    ready = _pendingRead;
                    _pendingRead = null;
                    count = Drain(_readBuffer, _readOffset, _readCount);
                }
            }
            if (ready != null) ready.TrySetResult(count);
        }

        void Finish()
        {
            Promise<int> ready;
            lock (_gate)
            {
                _closed = true;
                ready = _pendingRead;
                _pendingRead = null;
            }
            if (ready != null) ready.TrySetResult(0);
        }

        int Drain(byte[] b, int off, int n)
        {
            int count = Math.Min(n, _incoming.Count);
            for (int i = 0; i < count; i++) b[off + i] = _incoming.Dequeue();
            return count;
        }
    }
}
