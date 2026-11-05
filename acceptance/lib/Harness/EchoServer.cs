using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Acceptance
{
    /// <summary>A loopback TCP server that sends back every byte it reads. The tunnel clauses ask the peer to connect to it.</summary>
    public sealed class EchoServer : IDisposable
    {
        readonly TcpListener _l;
        readonly Thread _t;
        volatile bool _stop;
        public int Port;
        public int Connections;
        public long BytesEchoed;

        public EchoServer()
        {
            _l = new TcpListener(IPAddress.Loopback, 0);
            _l.Start();
            Port = ((IPEndPoint)_l.LocalEndpoint).Port;
            _t = new Thread(Loop);
            _t.IsBackground = true;
            _t.Start();
        }

        void Loop()
        {
            while (!_stop)
            {
                TcpClient c;
                try { c = _l.AcceptTcpClient(); }
                catch (SocketException) { return; }
                catch (ObjectDisposedException) { return; }
                Interlocked.Increment(ref Connections);
                Thread w = new Thread(delegate ()
                {
                    using (c)
                    {
                        NetworkStream s = c.GetStream();
                        byte[] buf = new byte[4096];
                        int n;
                        try
                        {
                            while ((n = s.Read(buf, 0, buf.Length)) > 0)
                            {
                                s.Write(buf, 0, n);
                                Interlocked.Add(ref BytesEchoed, n);
                            }
                        }
                        catch (System.IO.IOException) { }
                    }
                });
                w.IsBackground = true;
                w.Start();
            }
        }

        public void Dispose() { _stop = true; try { _l.Stop(); } catch (SocketException) { } }
    }
}
