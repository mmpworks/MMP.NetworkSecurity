namespace NetSec.Keys
{
    public enum KeyAlgorithm { Ed25519, X25519, Rsa2048, Aes128, Aes256, Raw }

    /// <summary>A key the glass-box engines may read. Its bytes can leave, because it only ever protects a lesson (D5).</summary>
    public interface ITrainingKey
    {
        string KeyId { get; }
        KeyAlgorithm Algorithm { get; }
        byte[] CopyMaterial();
        byte[] CopyPublic();
    }

    /// <summary>A real key. It offers operations and never exports. The glass-box factory cannot take one, by type (D5).</summary>
    public interface IKeyHandle
    {
        string KeyId { get; }
        KeyAlgorithm Algorithm { get; }
        byte[] Public();
        byte[] Sign(byte[] message);
    }

    public interface ITrainingKeySource
    {
        ITrainingKey Find(string keyId);
    }

    public interface IKeyHandleSource
    {
        IKeyHandle Find(string keyId);
    }

    public static class KeyIds
    {
        public const string CaRoot = "ca-root";
        public const string ServerTlsEd25519 = "server-tls-ed25519";
        public const string ServerTls11Rsa = "server-tls11-rsa";
        public const string SshHostEd25519 = "ssh-host-ed25519";
        public const string SshHostRsa = "ssh-host-rsa";
        public const string SshClient = "ssh-client";
        public const string DukptBdk128 = "dukpt-bdk-128";
        public const string DukptBdk256 = "dukpt-bdk-256";
        public const string TokenIssuer = "token-issuer";
        public const string AttackerEd25519 = "attacker-ed25519";
    }
}
