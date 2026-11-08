using NetSec.Errors;
using NetSec.Pki;

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
        public const string CompressionRefused = "TLS11_COMPRESSION_REFUSED";
        public const string CcsBody = "TLS11_CCS_BODY";
        public const string RenegotiationInfo = "TLS11_RENEGOTIATION_INFO";

        /// <summary>Lesson 7's decrypt-a-recording run: on ECDHE, a stolen server key opens no recorded session, because no stored key made its keys.</summary>
        public const string NoStoredKey = "TLS11_NO_STORED_KEY";

        /// <summary>The alert a failure owes the peer (RFC 4346 section 7.2.2). Internal_error (80) covers a code with no row.</summary>
        public static int AlertFor(string code)
        {
            switch (code)
            {
                case RecordMac: return 20;
                case RecordOverflow: return 22;
                case ErrorCodes.UnexpectedMessage: return 10;
                case VersionRefused: return 70;
                case SuiteRefused: return 40;
                case ChainCheck.NoAnchor: return 48;
                case ChainCheck.Validity: return 45;
                case ChainCheck.Name:
                case ChainCheck.BadSignature: return 42;
                case ServerKeyUnusable: return 43;
                case FinishedMismatch:
                case SkeSignature: return 51;
                case CompressionRefused:
                case CcsBody:
                case EcdheZeroShared:
                case RenegotiationInfo: return 47;
                case ErrorCodes.ParseTruncated:
                case RecordHeader:
                case DerReader.ParseCode: return 50;
                default: return 80;
            }
        }
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
        public const string CompressionOffered = "compression offered";
        public const string MessageShape = "message shape";
    }
}
