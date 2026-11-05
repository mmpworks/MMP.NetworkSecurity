namespace NetSec.Tls11
{
    /// <summary>The stable failure codes and check names of the TLS 1.1 engine. docs/lesson-tls11-names.md lists them for the tours.</summary>
    public static class Tls11Codes
    {
        public const string AlertProtocolVersion = "TLS11_ALERT_PROTOCOL_VERSION";
        public const string Alert = "TLS11_ALERT";
        public const string VersionRefused = "TLS11_VERSION_REFUSED";
        public const string SuiteRefused = "TLS11_SUITE_REFUSED";
        public const string ServerKeyUnusable = "TLS11_SERVER_KEY_UNUSABLE";
        public const string SkeSignature = "TLS11_SKE_SIGNATURE";
        public const string EcdheZeroShared = "TLS11_ECDHE_ZERO_SHARED";
        public const string FinishedMismatch = "TLS11_FINISHED_MISMATCH";
        public const string RecordMac = "TLS11_RECORD_MAC";
        public const string RecordOverflow = "TLS11_RECORD_OVERFLOW";
        public const string RecordHeader = "TLS11_RECORD_HEADER";
        public const string EngineFault = "TLS11_ENGINE_FAULT";
    }

    public static class Tls11Checks
    {
        public const string CertificateChain = "certificate chain";
        public const string ServerKeyShape = "server key shape";
        public const string SkeSignature = "ServerKeyExchange signature";
        public const string EcdheShared = "ECDHE shared secret";
        public const string FinishedCompare = "Finished compare";
        public const string RecordHmac = "record HMAC";
        public const string ProtocolVersionAlert = "protocol_version alert";
        public const string PeerAlert = "peer alert";
        public const string VersionOffered = "version offered";
        public const string SuiteOffered = "suite offered";
        public const string MessageShape = "message shape";
    }
}
