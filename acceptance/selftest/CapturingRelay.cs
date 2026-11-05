using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

namespace Acceptance
{
    /// <summary>A TCP relay for the self-test: forwards one connection to a port and keeps the bytes of both directions.</summary>
    public sealed class CapturingRelay : IDisposable
    {
        readonly TcpListener _l;
        readonly int _to;
        readonly MemoryStream _c2s = new MemoryStream(), _s2c = new MemoryStream();
        public int Port;

        public CapturingRelay(int toPort)
        {
            _to = toPort;
            _l = new TcpListener(IPAddress.Loopback, 0);
            _l.Start();
            Port = ((IPEndPoint)_l.LocalEndpoint).Port;
            Thread t = new Thread(Run);
            t.IsBackground = true;
            t.Start();
        }

        void Run()
        {
            try
            {
                TcpClient a = _l.AcceptTcpClient();
                TcpClient b = new TcpClient();
                b.Connect(IPAddress.Loopback, _to);
                Thread t1 = new Thread(delegate () { Pump(a, b, _c2s); }), t2 = new Thread(delegate () { Pump(b, a, _s2c); });
                t1.IsBackground = true; t2.IsBackground = true;
                t1.Start(); t2.Start();
            }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
        }

        static void Pump(TcpClient from, TcpClient to, MemoryStream log)
        {
            byte[] buf = new byte[8192];
            try
            {
                NetworkStream fs = from.GetStream(), ts = to.GetStream();
                int n;
                while ((n = fs.Read(buf, 0, buf.Length)) > 0)
                {
                    lock (log) { log.Write(buf, 0, n); }
                    ts.Write(buf, 0, n);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }

        public byte[] ClientToServer { get { lock (_c2s) { return _c2s.ToArray(); } } }
        public byte[] ServerToClient { get { lock (_s2c) { return _s2c.ToArray(); } } }
        public void Dispose() { try { _l.Stop(); } catch (SocketException) { } }
    }
}
