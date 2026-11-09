using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using System.Threading;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Machine;
using NetSec.Platform;
using NetSec.Trace;

namespace NetSec.CeDevice
{
    /// <summary>
    /// The CE process: a CF-compiled exe on the desktop CLR. It takes a sealed PIN envelope from the PIN pad and relays it through a device link.
    /// --socket-loop runs an EchoEngine pair through EnginePump over loopback, and uses all four Begin pairs. Nothing here has run on CE.
    /// </summary>
    static class Program
    {
        const int RunLimitMs = 60000;

        static int Main(string[] args)
        {
            int pool = IntOption(args, "--pool", DeviceProfile.Ce.PoolThreads);
            bool capped = ThreadPool.SetMaxThreads(pool, pool);
            int workers, ports;
            ThreadPool.GetMaxThreads(out workers, out ports);
            Console.WriteLine("CE-READY pool=" + workers + "/" + ports + " ptr=" + IntPtr.Size + " clr=" + Environment.Version + " capped=" + (capped ? "true" : "false"));

            if (HasFlag(args, "--socket-loop")) return SocketLoop();
            return Relay(args);
        }

        static int Relay(string[] args)
        {
            string pad = Option(args, "--pinpad"), gateway = Option(args, "--gateway");
            if (pad == null || gateway == null) return Result(false, ErrorCodes.CeRelayArgsMissing, null, "--pinpad and --gateway are required");

            CeRunOptions options = new CeRunOptions();
            options.PinPad = new IPEndPoint(IPAddress.Loopback, int.Parse(pad));
            options.Gateway = new IPEndPoint(IPAddress.Loopback, int.Parse(gateway));
            options.LinkKind = Option(args, "--link") ?? CeDeviceFlow.LinkExternalForward;
            options.Clock = new MonotonicClock();
            options.Suite = Option(args, "--suite") == "legacy" ? SshSuite.Legacy : SshSuite.Modern;
            string seed = Option(args, "--seed");
            options.Random = seed != null ? (IRandomSource)new SeededRandom((int)long.Parse(seed)) : new OsRandom();
            options.Keys = new TrainingKeySource();
            string traceFile = Option(args, "--trace-file");
            options.Sink = traceFile != null ? (ITraceSink)new NdjsonFileSink(traceFile) : new NullSink();

            IFuture<CeRunResult> run = CeDeviceFlow.Run(options);
            if (!run.Wait(RunLimitMs)) return Result(false, ErrorCodes.LinkDeadline, null, null);
            if (run.IsFaulted) return Result(false, ErrorCodes.LinkLost, null, run.Exception.Message);
            CeRunResult done = run.Result;
            return Result(done.Ok, done.Code, done.TraceId, null);
        }

        static int Result(bool ok, string code, string traceId, string detail)
        {
            StringBuilder line = new StringBuilder("CE-RESULT {\"ok\":").Append(ok ? "true" : "false");
            if (!string.IsNullOrEmpty(code)) line.Append(",\"code\":").Append(MiniJson.Quote(code));
            if (traceId != null) line.Append(",\"traceId\":").Append(MiniJson.Quote(traceId));
            if (detail != null) line.Append(",\"detail\":").Append(MiniJson.Quote(detail));
            line.Append(",\"gcTotalBytes\":").Append(GC.GetTotalMemory(false)).Append("}");
            Console.WriteLine(line.ToString());
            return ok ? 0 : 1;
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
            EnginePump clientPump = new EnginePump(client, clientLink, null, null, null, 15000);
            clientPump.OpenedLink = true;
            IFuture<PumpResult> clientRun = clientPump.Run();
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

        static string Option(string[] args, string name)
        {
            int at = Array.IndexOf(args, name);
            return at >= 0 && at + 1 < args.Length ? args[at + 1] : null;
        }

        static int IntOption(string[] args, string name, int fallback)
        {
            string value = Option(args, name);
            return value != null ? int.Parse(value) : fallback;
        }
    }
}
