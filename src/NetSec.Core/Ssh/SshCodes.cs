namespace NetSec.Ssh
{
    /// <summary>Stable failure codes of the SSH engine. Callers branch on these, never on message text.</summary>
    public static class SshCodes
    {
        public const string Version = "SSH_VERSION";
        public const string NoCommonAlg = "SSH_NO_COMMON_ALG";
        public const string HostKeyChanged = "SSH_HOST_KEY_CHANGED";
        public const string HostKeyUnknown = "SSH_HOST_KEY_UNKNOWN";
        public const string HostKeyBad = "SSH_HOST_KEY_BAD";
        public const string KexZeroSecret = "SSH_KEX_ZERO_SECRET";
        public const string ExchangeSignature = "SSH_EXCHANGE_SIGNATURE";
        public const string PacketMac = "SSH_PACKET_MAC";
        public const string PacketLength = "SSH_PACKET_LENGTH";
        public const string AuthRefused = "SSH_AUTH_REFUSED";
        public const string ExecRefused = "SSH_EXEC_REFUSED";
        public const string TunnelRefused = "SSH_TUNNEL_REFUSED";
        public const string ChannelUnknown = "SSH_CHANNEL_UNKNOWN";
        public const string ChannelWindow = "SSH_CHANNEL_WINDOW";
        public const string RekeyUnsupported = "SSH_REKEY_UNSUPPORTED";
        public const string PeerDisconnect = "SSH_PEER_DISCONNECT";
        public const string HostKeyRevoked = "SSH_HOST_KEY_REVOKED";
        public const string ChannelQueueFull = "SSH_CHANNEL_QUEUE_FULL";
        public const string ChannelLimit = "SSH_CHANNEL_LIMIT";
        public const string AuthTries = "SSH_AUTH_TRIES";
        public const string SequenceExhausted = "SSH_SEQUENCE_EXHAUSTED";
        public const string KexStrict = "SSH_KEX_STRICT";
    }

    /// <summary>The names a tour and a test bind to. docs/lesson-ssh-names.md lists them.</summary>
    public static class SshChecks
    {
        public const string Version = "version line";
        public const string Algorithm = "algorithm match";
        public const string KnownHosts = "known_hosts match";
        public const string HostKeyShape = "host key shape";
        public const string ZeroSecret = "x25519 result not zero";
        public const string ExchangeSignature = "exchange signature";
        public const string PacketMac = "packet MAC";
        public const string PacketLength = "packet length";
        public const string AuthAccepted = "userauth accepted";
        public const string AuthSignature = "userauth signature verify";
        public const string ExecAccepted = "exec accepted";
        public const string TunnelAllowList = "tunnel allow list";
        public const string TunnelAccepted = "tunnel accepted";
        public const string ChannelKnown = "channel number known";
        public const string ChannelWindow = "channel window";
        public const string NoRekey = "no rekey in this lab";
        public const string PeerStayed = "peer stayed until the end";
        public const string ChannelQueue = "channel send queue";
        public const string ChannelLimit = "channel limit";
        public const string AuthTries = "userauth tries";
        public const string Sequence = "sequence number";
        public const string StrictKex = "strict kex";
    }

    /// <summary>Message numbers of RFC 4253 section 12, RFC 4252 section 6 and RFC 4254 section 9.</summary>
    public static class SshMsg
    {
        public const int Disconnect = 1, Ignore = 2, Unimplemented = 3, Debug = 4, ServiceRequest = 5, ServiceAccept = 6, ExtInfo = 7;
        public const int KexInit = 20, NewKeys = 21, KexClientShare = 30, KexReply = 31;
        public const int UserauthRequest = 50, UserauthFailure = 51, UserauthSuccess = 52, UserauthBanner = 53, UserauthPkOk = 60;
        public const int GlobalRequest = 80, RequestSuccess = 81, RequestFailure = 82;
        public const int ChannelOpen = 90, ChannelConfirmation = 91, ChannelOpenFailure = 92, ChannelWindowAdjust = 93;
        public const int ChannelData = 94, ChannelExtendedData = 95, ChannelEof = 96, ChannelClose = 97, ChannelRequest = 98, ChannelSuccess = 99, ChannelFailure = 100;

        /// <summary>A version line is no packet. This number sits outside the one byte a packet type can hold.</summary>
        public const int VersionLine = 1000;
    }

    public static class SshNames
    {
        public const string VersionLine = "VersionLine", KexInit = "KexInit", NewKeys = "NewKeys";
        public const string KexEcdhInit = "KexEcdhInit", KexEcdhReply = "KexEcdhReply", KexdhInit = "KexdhInit", KexdhReply = "KexdhReply";
        public const string ServiceRequest = "ServiceRequest", ServiceAccept = "ServiceAccept";
        public const string UserauthQuery = "UserauthQuery", UserauthSigned = "UserauthSigned", UserauthOther = "UserauthOther";
        public const string UserauthFailure = "UserauthFailure", UserauthSuccess = "UserauthSuccess", UserauthBanner = "UserauthBanner", UserauthPkOk = "UserauthPkOk";
        public const string ChannelOpenSession = "ChannelOpenSession", ChannelOpenTunnel = "ChannelOpenTunnel", ChannelOpenOther = "ChannelOpenOther";
        public const string ChannelOpenConfirmation = "ChannelOpenConfirmation", ChannelOpenFailure = "ChannelOpenFailure", ChannelWindowAdjust = "ChannelWindowAdjust";
        public const string ChannelData = "ChannelData", ChannelExtendedData = "ChannelExtendedData", ChannelEof = "ChannelEof", ChannelClose = "ChannelClose";
        public const string ChannelRequestExec = "ChannelRequestExec", ChannelRequestExitStatus = "ChannelRequestExitStatus", ChannelRequestOther = "ChannelRequestOther";
        public const string ChannelSuccess = "ChannelSuccess", ChannelFailure = "ChannelFailure";
        public const string GlobalRequest = "GlobalRequest", RequestSuccess = "RequestSuccess", RequestFailure = "RequestFailure";
        public const string Disconnect = "Disconnect", Ignore = "Ignore", Debug = "Debug", Unimplemented = "Unimplemented", ExtInfo = "ExtInfo", Unknown = "Unknown";
    }
}
