using NetSec.Errors;

namespace NetSec.Tls13
{
    /// <summary>The stable failure codes of this engine, each with the check name the learner sees and the alert the engine sends.</summary>
    public static class Tls13Codes
    {
        public const string DowngradeSentinel = "TLS13_DOWNGRADE_SENTINEL";
        public const string VersionRefused = "TLS13_VERSION_REFUSED";
        public const string HrrUnsupported = "TLS13_HRR_UNSUPPORTED";
        public const string CertVerifyBad = "TLS13_CERTVERIFY_BAD";
        public const string FinishedMismatch = "TLS13_FINISHED_MISMATCH";
        public const string AeadTag = "TLS13_AEAD_TAG";
        public const string KeyUpdateUnsupported = "TLS13_KEYUPDATE_UNSUPPORTED";
        public const string RecordOverflow = "TLS13_RECORD_OVERFLOW";
        public const string X25519Zero = "TLS13_X25519_ZERO";
        public const string KeyShareInvalid = "TLS13_KEY_SHARE_INVALID";
        public const string IllegalParameter = "TLS13_ILLEGAL_PARAMETER";
        public const string NoCommonGroup = "TLS13_NO_COMMON_GROUP";
        public const string NoCommonSuite = "TLS13_NO_COMMON_SUITE";
        public const string NoCommonSignature = "TLS13_NO_COMMON_SIGNATURE";
        public const string AlertReceived = "TLS13_ALERT_RECEIVED";
        public const string ClientCertRequired = "TLS13_CLIENT_CERT_REQUIRED";

        sealed class Row
        {
            public readonly string Code, Check;
            public readonly int Alert;
            public Row(string code, string check, int alert) { Code = code; Check = check; Alert = alert; }
        }

        static readonly Row[] Rows =
        {
            new Row(DowngradeSentinel, "downgrade sentinel", 47),
            new Row(VersionRefused, "protocol version", 70),
            new Row(HrrUnsupported, "one key share round", 40),
            new Row(CertVerifyBad, "CertificateVerify signature", 51),
            new Row(FinishedMismatch, "Finished verify_data", 51),
            new Row(AeadTag, "AEAD tag", 20),
            new Row(KeyUpdateUnsupported, "KeyUpdate support", 10),
            new Row(RecordOverflow, "record length", 22),
            new Row(X25519Zero, "X25519 result not zero", 47),
            new Row(KeyShareInvalid, "key share shape", 47),
            new Row(IllegalParameter, "ServerHello matches the offer", 47),
            new Row(NoCommonGroup, "common group", 40),
            new Row(NoCommonSuite, "common cipher suite", 40),
            new Row(NoCommonSignature, "common signature scheme", 40),
            // The check name is the one in ux-design.md section 7 and acceptance/CONTRACT.md. The wire alert follows RFC 8446 section 6: certificate_required, 116.
            new Row(ClientCertRequired, "bad_certificate alert", 116),
            new Row("CHAIN_NO_ANCHOR", "chain to trust anchor", 48),
            new Row("CERT_VALIDITY", "validity window", 45),
            new Row("CERT_NAME", "name match", 42),
            new Row("CERT_SIGNATURE", "signature verify", 42),
            new Row("CERT_PARSE", "certificate parse", 42),
            new Row(ErrorCodes.ParseTruncated, "message parse", 50),
            new Row(ErrorCodes.UnexpectedMessage, "message allowed in this state", 10),
        };

        public static string CheckName(string code)
        {
            for (int i = 0; i < Rows.Length; i++)
                if (Rows[i].Code == code) return Rows[i].Check;
            return "message parse";
        }

        /// <summary>The TLS alert for a failure. Internal_error (80) covers a code with no row.</summary>
        public static int AlertFor(string code)
        {
            for (int i = 0; i < Rows.Length; i++)
                if (Rows[i].Code == code) return Rows[i].Alert;
            return 80;
        }
    }
}
