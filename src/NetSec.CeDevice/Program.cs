using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.CeDevice
{
    /// <summary>
    /// S0 holds the startup contract and the socket loop. --socket-loop runs an EchoEngine pair through EnginePump over loopback,
    /// and uses all four Begin pairs. The PIN relay over an IDeviceLink arrives in S5.
    /// </summary>
    static class Program
    {
        static int Main(string[] args)
        {
            int pool = IntOption(args, "--pool", DeviceProfile.Ce.PoolThreads);
            bool capped = ThreadPool.SetMaxThreads(pool, pool);
            int workers, ports;
            ThreadPool.GetMaxThreads(out workers, out ports);
            Console.WriteLine("CE-READY pool=" + workers + "/" + ports + " ptr=" + IntPtr.Size + " clr=" + Environment.Version + " capped=" + (capped ? "true" : "false"));

            if (HasFlag(args, "--socket-loop")) return SocketLoop();

            Console.WriteLine("CE-RESULT {\"ok\":false,\"code\":" + MiniJson.Quote(ErrorCodes.CeLinkNotBuilt) + "}");
            return 1;
        }

        static int SocketLoop()
        {
            IFuture<string> run = AsyncProxy.Run<string>(delegate(Return<string> ret) { return LoopBody(ret); });
            if (!run.Wait(30000))
            {
                Console.WriteLine("CE-RESULT {\"ok\":false,\"code\":" + MiniJson.Quote(ErrorCodes.LinkDeadline) + "}");
                return 1;
            }
            if (run.IsFaulted)
            {
                Console.WriteLine("CE-RESULT {\"ok\":false,\"code\":" + MiniJson.Quote(ErrorCodes.LinkLost) + ",\"detail\":" + MiniJson.Quote(run.Exception.Message) + "}");
                return 1;
            }
            Console.WriteLine("CE-RESULT " + run.Result);
            return run.Result.IndexOf("\"ok\":true") >= 0 ? 0 : 1;
        }

        static IEnumerable<IFuture> LoopBody(Return<string> ret)
        {
            byte[] message = Encoding.UTF8.GetBytes("hello from a CF binary");
            IClock clock = new MonotonicClock();
            LinkListener listener = new LinkListener(new IPEndPoint(IPAddress.Loopback, 0));
            IFuture<SocketLink> accepted = listener.Accept();
            IFuture<SocketLink> connected = SocketLink.Connect(new IPEndPoint(IPAddress.Loopback, listener.Port));
            yield return accepted;
            yield return connected;
            listener.Close();

            SocketLink serverLink = accepted.Result, clientLink = connected.Result;
            EchoEngine server = EchoEngine.Server(new TraceStream("ce/server/echo", "ce", "ce", null, "server", clock), null);
            EchoEngine client = EchoEngine.Client(message, new TraceStream("ce/client/echo", "ce", "ce", null, "client", clock), null);
            IFuture<PumpResult> serverRun = new EnginePump(server, serverLink, null, null, null, 15000).Run();
            IFuture<PumpResult> clientRun = new EnginePump(client, clientLink, null, null, null, 15000).Run();
            yield return clientRun;
            yield return serverRun;

            bool ok = clientRun.Result.Error == null && serverRun.Result.Error == null;
            ret.Value = "{\"ok\":" + (ok ? "true" : "false")
                + ",\"beginConnect\":" + clientLink.BeginConnects
                + ",\"beginAccept\":" + listener.BeginAccepts
                + ",\"beginSend\":" + (clientLink.BeginSends + serverLink.BeginSends)
                + ",\"beginReceive\":" + (clientLink.BeginReceives + serverLink.BeginReceives)
                + ",\"bytesSent\":" + (clientRun.Result.BytesSent + serverRun.Result.BytesSent)
                + ",\"gcTotalBytes\":" + GC.GetTotalMemory(false) + "}";
        }

        static bool HasFlag(string[] args, string name)
        {
            return Array.IndexOf(args, name) >= 0;
        }

        static int IntOption(string[] args, string name, int fallback)
        {
            int at = Array.IndexOf(args, name);
            return at >= 0 && at + 1 < args.Length ? int.Parse(args[at + 1]) : fallback;
        }
    }
}
