using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;

namespace NetSec.Keys
{
    /// <summary>
    /// The made-up keys the labs use. Each symmetric key and Ed25519 seed is SHAKE256("MMP.NetworkSecurity training" + keyId).
    /// The RSA keys are literal hex in TrainingRsaKeys. Anyone can read all of them in this source, so they protect nothing real (D5).
    /// </summary>
    public sealed class TrainingKeySource : ITrainingKeySource
    {
        const string Label = "MMP.NetworkSecurity training";

        /// <summary>Returns the key for a KeyIds value. An unknown id throws TRAINING_KEY_UNKNOWN.</summary>
        public ITrainingKey Find(string keyId)
        {
            switch (keyId)
            {
                case KeyIds.CaRoot:
                case KeyIds.ServerTlsEd25519:
                case KeyIds.ClientTlsEd25519:
                case KeyIds.SshHostEd25519:
                case KeyIds.SshClient:
                case KeyIds.TokenIssuer:
                case KeyIds.AttackerEd25519:
                    byte[] seed = Derive(keyId, 32);
                    return new TrainingKey(keyId, KeyAlgorithm.Ed25519, seed, Ed25519.PublicFrom(seed));
                case KeyIds.DukptBdk128:
                    return new TrainingKey(keyId, KeyAlgorithm.Aes128, Derive(keyId, 16), new byte[0]);
                case KeyIds.DukptBdk256:
                    return new TrainingKey(keyId, KeyAlgorithm.Aes256, Derive(keyId, 32), new byte[0]);
                case KeyIds.ServerTls11Rsa:
                    return new TrainingKey(keyId, KeyAlgorithm.Rsa2048, Hex.Decode(TrainingRsaKeys.ServerTls11Private), Hex.Decode(TrainingRsaKeys.ServerTls11Public));
                case KeyIds.SshHostRsa:
                    return new TrainingKey(keyId, KeyAlgorithm.Rsa2048, Hex.Decode(TrainingRsaKeys.SshHostPrivate), Hex.Decode(TrainingRsaKeys.SshHostPublic));
                default:
                    throw new NetSecException(NetSecError.Of(ErrorCodes.TrainingKeyUnknown, "No training key has the id '" + keyId + "'."));
            }
        }

        static byte[] Derive(string keyId, int length)
        {
            byte[] input = Encoding.UTF8.GetBytes(Label + keyId);
            Shake shake = Shake.New256();
            shake.Absorb(input, 0, input.Length);
            byte[] output = new byte[length];
            shake.Squeeze(output, 0, length);
            return output;
        }

        sealed class TrainingKey : ITrainingKey
        {
            readonly string _keyId;
            readonly KeyAlgorithm _algorithm;
            readonly byte[] _material;
            readonly byte[] _public;

            public TrainingKey(string keyId, KeyAlgorithm algorithm, byte[] material, byte[] publicPart)
            {
                _keyId = keyId;
                _algorithm = algorithm;
                _material = material;
                _public = publicPart;
            }

            public string KeyId { get { return _keyId; } }
            public KeyAlgorithm Algorithm { get { return _algorithm; } }
            public byte[] CopyMaterial() { return (byte[])_material.Clone(); }

            /// <summary>The public part. A symmetric key has none, so it gives an empty array.</summary>
            public byte[] CopyPublic() { return (byte[])_public.Clone(); }
        }
    }
}
