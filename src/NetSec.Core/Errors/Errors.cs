using System;

namespace NetSec.Errors
{
    /// <summary>A named failure: a stable machine code beside the human message. Callers branch on Code, never on Message.</summary>
    public sealed class NetSecError
    {
        public string Code;
        public string Message;
        public string CheckName;
        public string Step;
        public bool Retryable;
        public string TraceId;

        public static NetSecError Of(string code, string message)
        {
            NetSecError error = new NetSecError();
            error.Code = code;
            error.Message = message;
            return error;
        }
    }

    public sealed class NetSecException : Exception
    {
        public readonly NetSecError Error;
        public NetSecException(NetSecError error) : base(error.Code + ": " + error.Message) { Error = error; }
    }

    public static class ErrorCodes
    {
        public const string UnexpectedMessage = "UNEXPECTED_MESSAGE";
        public const string ParseTruncated = "PARSE_TRUNCATED";
        public const string LinkDeadline = "LINK_DEADLINE";
        public const string LinkLost = "LINK_LOST";
        public const string PeerClosedEarly = "PEER_CLOSED_EARLY";
        public const string EchoMismatch = "ECHO_MISMATCH";
        public const string CeTransportUnavailable = "CE_TRANSPORT_UNAVAILABLE";
        public const string CeLinkNotBuilt = "CE_LINK_NOT_BUILT";
        public const string CeDeviceSilent = "CE_DEVICE_SILENT";
        public const string TransportNotBuilt = "TRANSPORT_NOT_BUILT";
        public const string LessonNotBuilt = "LESSON_NOT_BUILT";
        public const string RealModeNotBuilt = "REAL_MODE_NOT_BUILT";
        public const string DhPeerOutOfRange = "DH_PEER_OUT_OF_RANGE";
        public const string RsaValueOutOfRange = "RSA_VALUE_OUT_OF_RANGE";
        public const string RsaMessageTooLong = "RSA_MESSAGE_TOO_LONG";
        public const string MlKemKeyInvalid = "MLKEM_KEY_INVALID";
        public const string MlKemCiphertextInvalid = "MLKEM_CIPHERTEXT_INVALID";
    }
}
