using System.Collections.Generic;
using NetSec.Errors;
using NetSec.Trace;

namespace NetSec.Machine
{
    public enum EngineStatus { Handshaking, Open, Closed, Failed }
    public enum EngineCommandKind { Send, Close, PeerClosed, OpenChannel, Exec, Consumed, Abort }

    public sealed class EngineCommand
    {
        public readonly EngineCommandKind Kind;
        public readonly int Channel;
        public readonly byte[] Bytes;
        public readonly string Text;

        public EngineCommand(EngineCommandKind kind, int channel, byte[] bytes, string text)
        {
            Kind = kind; Channel = channel; Bytes = bytes; Text = text;
        }

        public static readonly EngineCommand PeerClosed = new EngineCommand(EngineCommandKind.PeerClosed, 0, null, null);
        public static readonly EngineCommand Close = new EngineCommand(EngineCommandKind.Close, 0, null, null);

        /// <summary>Ends the session as a failure with this code. The engine sends a fatal alert, because data was lost and a clean close would say otherwise. Text holds "code|detail".</summary>
        public static EngineCommand Abort(string code, string detail) { return new EngineCommand(EngineCommandKind.Abort, 0, null, code + "|" + detail); }

        public string AbortCode { get { return Text.Substring(0, Text.IndexOf('|')); } }
        public string AbortDetail { get { return Text.Substring(Text.IndexOf('|') + 1); } }
    }

    /// <summary>One event, and the bytes to put on the wire right after it, when the event is a send.</summary>
    public sealed class OutputItem
    {
        public readonly TraceEvent Event;
        public readonly byte[] Wire;
        public OutputItem(TraceEvent e, byte[] wire) { Event = e; Wire = wire; }
    }

    public sealed class DeliveredChunk
    {
        public readonly int Channel;
        public readonly byte[] Bytes;
        public DeliveredChunk(int channel, byte[] bytes) { Channel = channel; Bytes = bytes; }
    }

    public sealed class EngineOutput
    {
        public readonly OutputItem[] Items;
        public readonly DeliveredChunk[] App;
        public readonly EngineStatus Status;
        public readonly NetSecError Error;

        public EngineOutput(OutputItem[] items, DeliveredChunk[] app, EngineStatus status, NetSecError error)
        {
            Items = items; App = app; Status = status; Error = error;
        }

        public TraceEvent[] Events
        {
            get
            {
                TraceEvent[] events = new TraceEvent[Items.Length];
                for (int i = 0; i < Items.Length; i++) events[i] = Items[i].Event;
                return events;
            }
        }

        /// <summary>All wire bytes of this output, joined. EngineDuel passes this to the other engine.</summary>
        public byte[] Wire
        {
            get
            {
                List<byte> bytes = new List<byte>();
                for (int i = 0; i < Items.Length; i++)
                    if (Items[i].Wire != null) bytes.AddRange(Items[i].Wire);
                return bytes.ToArray();
            }
        }
    }

    /// <summary>Bytes in, bytes out, no socket, no thread, no future.</summary>
    public interface IProtocolEngine
    {
        EngineStatus Status { get; }
        TraceStream Stream { get; }
        string Peer { get; }
        EngineOutput Start();
        EngineOutput Feed(byte[] b, int off, int n);
        EngineOutput Command(EngineCommand c);
    }

    /// <summary>What Probe reads from a TLS engine after a run. One session loop then serves each TLS version.</summary>
    public interface ITlsEngine : IProtocolEngine
    {
        bool ReachedOpen { get; }
        string VersionName { get; }
        string SuiteName { get; }
        string GroupName { get; }

        /// <summary>The alert number the peer sent, or -1.</summary>
        int AlertReceived { get; }
        string[] KeyLogLines { get; }
    }

    public enum TamperPoint { Plain, Wire }

    public sealed class TamperResult
    {
        public readonly byte[] Bytes;
        TamperResult(byte[] bytes) { Bytes = bytes; }

        public static readonly TamperResult Unchanged = new TamperResult(null);
        public static TamperResult Replace(byte[] bytes) { return new TamperResult(bytes); }
    }

    public interface ITamperHook
    {
        TamperResult Apply(TamperPoint point, string streamId, long streamSeq, string message, byte[] bytes);
    }

    public static class EngineDuel
    {
        /// <summary>Passes wire bytes between two engines on one thread, in a plain loop, until neither has more to say.</summary>
        public static void Run(IProtocolEngine client, IProtocolEngine server)
        {
            byte[] toClient = server.Start().Wire;
            byte[] toServer = client.Start().Wire;
            while (toServer.Length > 0 || toClient.Length > 0)
            {
                byte[] fromServer = toServer.Length > 0 ? server.Feed(toServer, 0, toServer.Length).Wire : new byte[0];
                byte[] fromClient = toClient.Length > 0 ? client.Feed(toClient, 0, toClient.Length).Wire : new byte[0];
                toServer = fromClient;
                toClient = fromServer;
            }
        }
    }
}
