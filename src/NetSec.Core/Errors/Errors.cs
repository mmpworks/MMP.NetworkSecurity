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
        public const string NativeLibMissing = "NATIVE_LIB_MISSING";
        public const string NativeSampleFailed = "NATIVE_SAMPLE_FAILED";
        public const string TimingNotSeparated = "TIMING_NOT_SEPARATED";
        public const string TimingGuessStopped = "TIMING_GUESS_STOPPED";
        public const string MessageRefused = "MESSAGE_REFUSED";
        public const string AesGcmTag = "AES_GCM_TAG";
        public const string AesGcmNonceReuse = "AES_GCM_NONCE_REUSE";
        public const string SealHashMismatch = "SEAL_HASH_MISMATCH";
        public const string SealKeyedHashMismatch = "SEAL_KEYED_HASH_MISMATCH";
        public const string SealHmacMismatch = "SEAL_HMAC_MISMATCH";
        public const string SealCmacMismatch = "SEAL_CMAC_MISMATCH";
        public const string KexConfirmMismatch = "KEX_CONFIRM_MISMATCH";
        public const string TokenBadAlg = "TOKEN_BAD_ALG";
        public const string TokenBadSignature = "TOKEN_BAD_SIGNATURE";
        public const string TokenMalformed = "TOKEN_MALFORMED";
        public const string TokenExpired = "TOKEN_EXPIRED";
        public const string TokenBadClock = "TOKEN_BAD_CLOCK";
        public const string TokenBadHeader = "TOKEN_BAD_HEADER";
        public const string TokenBadAudience = "TOKEN_BAD_AUDIENCE";
        public const string ChallengeNotIssued = "CHALLENGE_NOT_ISSUED";
        public const string DeviceNotEnrolled = "DEVICE_NOT_ENROLLED";
        public const string DpopMalformed = "DPOP_MALFORMED";
        public const string DpopBadKey = "DPOP_BAD_JWK";
        public const string DpopBadSignature = "DPOP_BAD_SIGNATURE";
        public const string DpopHtmMismatch = "DPOP_HTM_MISMATCH";
        public const string DpopHtuMismatch = "DPOP_HTU_MISMATCH";
        public const string DpopIatWindow = "DPOP_IAT_WINDOW";
        public const string DpopAthMismatch = "DPOP_ATH_MISMATCH";
        public const string DpopJktMismatch = "DPOP_JKT_MISMATCH";
        public const string DpopReplay = "DPOP_REPLAY";
        public const string ChallengeBadSignature = "CHALLENGE_BAD_SIGNATURE";
        public const string ChallengeReplay = "CHALLENGE_REPLAY";
        public const string RoleDenied = "ROLE_DENIED";
        public const string CapabilityDenied = "CAPABILITY_DENIED";
        public const string CeTransportUnavailable = "CE_TRANSPORT_UNAVAILABLE";
        public const string CeLinkNotBuilt = "CE_LINK_NOT_BUILT";
        public const string CeDeviceSilent = "CE_DEVICE_SILENT";
        public const string TransportNotBuilt = "TRANSPORT_NOT_BUILT";
        public const string ChannelBufferFull = "CHANNEL_BUFFER_FULL";
        public const string LessonNotBuilt = "LESSON_NOT_BUILT";
        public const string OsTransportNotBuilt = "OS_TRANSPORT_NOT_BUILT";
        public const string OsTransportNoPeer = "OS_TRANSPORT_NO_PEER";
        public const string OsTransportFailed = "OS_TRANSPORT_FAILED";
        public const string KeylogNotKept = "KEYLOG_NOT_KEPT";
        public const string KeysHidden = "KEYS_HIDDEN";
        public const string TransportUnknown = "TRANSPORT_UNKNOWN";
        public const string DhPeerOutOfRange = "DH_PEER_OUT_OF_RANGE";
        public const string HkdfPrkTooShort = "HKDF_PRK_TOO_SHORT";
        public const string RsaValueOutOfRange = "RSA_VALUE_OUT_OF_RANGE";
        public const string RsaMessageTooLong = "RSA_MESSAGE_TOO_LONG";
        public const string MlKemKeyInvalid = "MLKEM_KEY_INVALID";
        public const string MlKemCiphertextInvalid = "MLKEM_CIPHERTEXT_INVALID";
        public const string TrainingKeyUnknown = "TRAINING_KEY_UNKNOWN";
        public const string SecurityTypeNotReady = "SECURITY_TYPE_NOT_READY";
        public const string SecurityTypeNotProven = "SECURITY_TYPE_NOT_PROVEN";
        public const string SecurityTypesDisagree = "SECURITY_TYPES_DISAGREE";
        public const string KeyFileUnreadable = "KEY_FILE_UNREADABLE";
        public const string KeyFileFormat = "KEY_FILE_FORMAT";
        public const string KeyFileEncrypted = "KEY_FILE_ENCRYPTED";
        public const string KeySizeNot2048 = "KEY_SIZE_NOT_2048";
        public const string FileRowNotBuilt = "FILE_ROW_NOT_BUILT";
        public const string KeyAlgorithmNotInEngine = "KEY_ALGORITHM_NOT_IN_ENGINE";
        public const string DukptCounterExhausted = "DUKPT_COUNTER_EXHAUSTED";
        public const string DukptKsnReplay = "DUKPT_KSN_REPLAY";
        public const string DukptMacMismatch = "DUKPT_MAC_MISMATCH";
        public const string EnvelopeMalformed = "ENVELOPE_MALFORMED";
        public const string DukptPinBlockFormat = "DUKPT_PINBLOCK_FORMAT";
        public const string DukptKeyNotHeld = "DUKPT_KEY_NOT_HELD";
        public const string DukptKeySize = "DUKPT_KEY_SIZE";
        public const string DukptKcvMismatch = "DUKPT_KCV_MISMATCH";
        public const string DukptKcvFormat = "DUKPT_KCV_FORMAT";
        public const string AesWalkDiverged = "AES_WALK_DIVERGED";
        public const string WalkNotBuilt = "WALK_NOT_BUILT";
        public const string WalkBadArgument = "WALK_BAD_ARGUMENT";
        public const string WalkWaitingForWire = "WALK_WAITING_FOR_WIRE";
        public const string WalkMessageNotSent = "WALK_MESSAGE_NOT_SENT";
    }
}
