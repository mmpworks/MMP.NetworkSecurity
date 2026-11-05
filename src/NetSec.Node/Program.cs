using System.Net;
using System.Text.Json;
using MMP.AsyncProxy;
using NetSec.Bridge;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Errors;
using NetSec.Io;
using NetSec.Keys;
using NetSec.Platform;
using NetSec.Trace;

// One process of the bridge lab, by role. It prints READY port=<p> first and a final RESULT {json} line, and writes its trace to --trace-file.
// acceptance/CONTRACT.md section 3 holds the command lines.
const int NoSuchRole = 2;

string role = Option("--role") ?? "";
switch (role)
{
    case "pinpad": return PinPad();
    case "bankhsm": return BankHsm();
    case "gateway": return Gateway();
    case "server": return Server();
    default:
        Console.Error.WriteLine("NODE_ROLE_UNKNOWN: use --role pinpad, bankhsm, gateway, or server.");
        return NoSuchRole;
}

string? Option(string name)
{
    int at = Array.IndexOf(args, name);
    return at >= 0 && at + 1 < args.Length ? args[at + 1] : null;
}

IRandomSource Random() => long.TryParse(Option("--seed"), out long seed) ? new SeededRandom((int)seed) : new OsRandom();

ITraceSink Sink() => Option("--trace-file") is { } path ? new NdjsonFileSink(path) : new NullSink();

LinkListener Listen() => new(new IPEndPoint(IPAddress.Loopback, int.TryParse(Option("--listen"), out int port) ? port : 0));

int PinPad()
{
    string pin = Option("--pin") ?? "1234", pan = Option("--pan") ?? "4111111111111111";
    IRandomSource random = Random();
    ITraceSink sink = Sink();
    LinkListener listener = Listen();
    Console.WriteLine($"READY port={listener.Port}");

    byte[] idBytes = new byte[8];
    random.Fill(idBytes, 0, idBytes.Length);
    string traceId = "t" + Hex.Encode(idBytes);
    DukptPinPad pad = new(Hex.Decode(PinPadCore.InjectedInitialKey), Hex.Decode(PinPadCore.InjectedKeyId));

    SocketLink ce = Take(listener.Accept());
    PadSale sale = PinPadCore.Sell(pad, traceId, pin, pan, random);
    TraceStream stream = new(traceId + "/reader/bridge", traceId, traceId, null, "reader", new MonotonicClock());
    sink.Write(stream.Stamp(new TraceEventDraft { Type = "pin.block.locked", Message = "PinEnvelope", Plain = sale.Envelope.Bytes }));
    Finish(FrameIo.WriteFrame(ce, sale.Envelope.Bytes));
    Console.WriteLine("RESULT " + JsonSerializer.Serialize(new { ksn = Hex.Encode(sale.Envelope.Ksn), pinBlockHex = Hex.Encode(sale.ClearField) }));

    // The reply is advice for the pad's screen. The sale's result line is out already.
    IFuture<byte[]> reply = FrameIo.ReadFrame(ce);
    reply.Wait(30000);
    ce.Close();
    return 0;
}

// Accepts one connection after another and serves each on its own, until the process ends.
int ServeForever(Func<SocketLink, IFuture> serve)
{
    LinkListener listener = Listen();
    Console.WriteLine($"READY port={listener.Port}");
    while (true)
    {
        IFuture<SocketLink> accepted = listener.Accept();
        accepted.Wait();
        if (accepted.IsFaulted) return 1;
        serve(accepted.Result);
    }
}

int FlagMissing(string flag)
{
    Console.Error.WriteLine($"NODE_FLAG_MISSING: role {role} needs {flag} with a port.");
    return NoSuchRole;
}

HopServerOptions HopOptions() => new() { Keys = new TrainingKeySource(), Random = Random(), Sink = Sink() };

int Gateway()
{
    if (!int.TryParse(Option("--server"), out int next)) return FlagMissing("--server");
    bool flip = Array.IndexOf(args, "--tamper-envelope") >= 0;
    HopServerOptions options = HopOptions();
    return ServeForever(link => BridgeHopServers.ServeGateway(link, options, next, flip));
}

int Server()
{
    if (!int.TryParse(Option("--bank"), out int bank)) return FlagMissing("--bank");
    HopServerOptions options = HopOptions();
    return ServeForever(link => BridgeHopServers.ServeServer(link, options, bank));
}

int BankHsm()
{
    byte[] bdk = new TrainingKeySource().Find(KeyIds.DukptBdk128).CopyMaterial();
    KsnLedger ledger = new();
    ITraceSink sink = Sink();
    LinkListener listener = Listen();
    Console.WriteLine($"READY port={listener.Port}");
    while (true)
    {
        SocketLink peer = Take(listener.Accept());
        _ = Task.Run(() => Serve(peer, bdk, ledger, sink));
    }
}

void Serve(SocketLink peer, byte[] bdk, KsnLedger ledger, ITraceSink sink)
{
    try
    {
        while (true)
        {
            byte[]? envelope = Take(FrameIo.ReadFrame(peer));
            if (envelope is null) return;
            BankDecision decision;
            lock (ledger) decision = BankHsmCore.Decide(bdk, ledger, envelope);
            TraceBank(sink, decision);
            Console.WriteLine("RESULT " + JsonSerializer.Serialize(new
            {
                pinBlockHex = decision.ClearField is null ? "" : Hex.Encode(decision.ClearField),
                code = decision.Ok ? "OK" : decision.Code,
                check = decision.Check ?? "",
            }));
            Finish(FrameIo.WriteFrame(peer, BankReply.Build(decision)));
        }
    }
    catch (Exception e) when (e is IOException or System.Net.Sockets.SocketException or ObjectDisposedException or ParseFailure)
    {
        Console.Error.WriteLine("BANK_LINK_LOST: " + e.Message);
    }
    finally
    {
        peer.Close();
    }
}

void TraceBank(ITraceSink sink, BankDecision d)
{
    string traceId = d.TraceId ?? "unread";
    TraceStream stream = new(traceId + "/bank/bridge", traceId, traceId, null, "bank", new MonotonicClock());
    if (d.Ok)
    {
        sink.Write(stream.Stamp(new TraceEventDraft
        {
            Type = "secret.derived",
            Secrets = [new TraceSecret { Holder = "bank", Name = "dukpt.pin-key", Bytes = d.PinKey, DerivedFrom = ["dukpt.bdk"] }],
        }));
    }
    sink.Write(stream.Stamp(new TraceEventDraft
    {
        Type = "check.result",
        Message = d.Check ?? BankHsmCore.MacCheck,
        Check = new TraceCheck { Id = d.Code ?? ErrorCodes.DukptMacMismatch, Name = d.Check ?? BankHsmCore.MacCheck, Passed = d.Ok, Code = d.Code, Detail = d.Detail },
    }));
}

// Waits on a future and rethrows its fault, for this process's plain top-level flow.
static T Take<T>(IFuture<T> future)
{
    future.Wait();
    return future.Result;
}

static void Finish(IFuture future)
{
    future.Wait();
    if (future.IsFaulted) throw future.Exception;
}
