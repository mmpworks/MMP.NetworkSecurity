using System;
using System.Linq;
using NetSec.Crypto;
using NetSec.Keys;
using NetSec.Labs;
using NetSec.Machine;
using NetSec.Pki;
using NetSec.Tls13;
using Xunit;

namespace NetSec.Tests
{
    /// <summary>
    /// RFC 8446 receiver MUSTs from docs/conformance-matrix.md section 4. Each test states the alert the RFC names, beside a control
    /// that the same message without the fault still passes or keeps its own alert.
    /// </summary>
    public class Tls13ReceiverMustTests
    {
        const int IllegalParameter = 47, DecodeError = 50, HandshakeFailure = 40, ProtocolVersion = 70, BadCertificate = 42, MissingExtension = 109, UnsupportedExtension = 110;
        const int ExtServerName = 0, ExtSupportedGroups = 10, ExtSignatureAlgorithms = 13, ExtSupportedVersions = 43, ExtKeyShare = 51, ExtUnknown = 0x7A7A;
        const int ClientHelloCompressionLengthAt = 45;

        static string Describe(EngineOutput o) => o.Error == null ? "no error, status " + o.Status : "alert " + Tls13Codes.AlertFor(o.Error.Code) + " (" + o.Error.Code + ")";

        static void AssertAlert(int alert, EngineOutput o) => Assert.True(o.Error != null && Tls13Codes.AlertFor(o.Error.Code) == alert, "the RFC names alert " + alert + ", and the engine gave " + Describe(o));

        // ---------------------------------------------------------------- building messages

        static byte[] ClientHelloBytes() => Tls13Messages.ClientHello(TlsKit.Bytes32(8), "localhost", Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5)));

        static byte[] ServerHelloBytes() => Tls13Messages.ServerHello(TlsKit.Bytes32(9), new byte[0], Tls13Suite.Aes128, Tls13Group.X25519, X25519.MultBase(TlsKit.Bytes32(5)));

        static int ExtensionsLengthAt(byte[] message)
        {
            int at = 4 + 2 + 32;
            at += 1 + message[at];
            if (message[0] == HandshakeType.ClientHello)
            {
                at += 2 + ((message[at] << 8) | message[at + 1]);
                at += 1 + message[at];
            }
            else
            {
                at += 2 + 1;
            }
            return at;
        }

        /// <summary>Puts new extensions bytes in place and repairs the two lengths that cover them.</summary>
        static byte[] WithExtensions(byte[] message, byte[] extensions)
        {
            int at = ExtensionsLengthAt(message);
            byte[] rebuilt = message.Take(at).Concat(new[] { (byte)(extensions.Length >> 8), (byte)extensions.Length }).Concat(extensions).ToArray();
            return WithBodyLength(rebuilt);
        }

        static byte[] WithBodyLength(byte[] message)
        {
            int body = message.Length - 4;
            message[1] = (byte)(body >> 16);
            message[2] = (byte)(body >> 8);
            message[3] = (byte)body;
            return message;
        }

        static byte[] Extensions(byte[] message)
        {
            int at = ExtensionsLengthAt(message);
            return message.Skip(at + 2).ToArray();
        }

        static byte[] Extension(int type, params byte[] body) => new[] { (byte)(type >> 8), (byte)type, (byte)(body.Length >> 8), (byte)body.Length }.Concat(body).ToArray();

        static byte[] WithoutExtension(byte[] message, int type)
        {
            byte[] all = Extensions(message);
            byte[] kept = new byte[0];
            for (int at = 0; at < all.Length;)
            {
                int length = 4 + ((all[at + 2] << 8) | all[at + 3]);
                if (((all[at] << 8) | all[at + 1]) != type) kept = kept.Concat(all.Skip(at).Take(length)).ToArray();
                at += length;
            }
            return WithExtensions(message, kept);
        }

        static byte[] WithExtra(byte[] message, byte[] extension) => WithExtensions(message, Extensions(message).Concat(extension).ToArray());

        // ---------------------------------------------------------------- driving the engines

        static EngineOutput FeedServer(byte[] handshake)
        {
            Tls13Engine server = TlsKit.Server(Tls13Group.X25519);
            server.Start();
            byte[] record = TlsKit.Plain(handshake);
            return server.Feed(record, 0, record.Length);
        }

        static EngineOutput FeedClient(byte[] handshake)
        {
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            client.Start();
            byte[] record = TlsKit.Plain(handshake);
            return client.Feed(record, 0, record.Length);
        }

        /// <summary>A full handshake flight to a client, with one server message swapped before it is sealed.</summary>
        static EngineOutput ClientGetsFlightWith(string message, byte[] replacement)
        {
            Tls13Options o = TlsKit.Common("server", "client", Tls13Group.X25519, 2);
            ITrainingKey key = TlsKit.Keys.Find(KeyIds.ServerTlsEd25519);
            o.CertificateChain = new[] { TrainingPki.ServerCertificate(new TrainingCa(TlsKit.Keys), key) };
            o.SigningSeed = key.CopyMaterial();
            o.Tamper = new TamperPlan { Point = TamperPoint.Plain, Message = message, Replacement = replacement };
            Tls13Engine server = Tls13Engine.CreateServer(o);
            Tls13Engine client = TlsKit.Client(Tls13Group.X25519);
            server.Start();
            byte[] hello = client.Start().Wire;
            byte[] flight = server.Feed(hello, 0, hello.Length).Wire;
            return client.Feed(flight, 0, flight.Length);
        }

        static byte[] EncryptedExtensionsWith(byte[] extensions) => WithBodyLength(new byte[] { HandshakeType.EncryptedExtensions, 0, 0, 0, (byte)(extensions.Length >> 8), (byte)extensions.Length }.Concat(extensions).ToArray());

        // ---------------------------------------------------------------- section 4.1.2, compression

        [Fact]
        public void Control_an_untouched_client_hello_passes()
        {
            Assert.Null(FeedServer(ClientHelloBytes()).Error);
        }

        [Fact]
        public void A_client_hello_compression_value_other_than_zero_gets_illegal_parameter()
        {
            byte[] hello = ClientHelloBytes();
            Assert.Equal(1, hello[ClientHelloCompressionLengthAt]);
            hello[ClientHelloCompressionLengthAt + 1] = 1;
            AssertAlert(IllegalParameter, FeedServer(hello));
        }

        [Fact]
        public void A_client_hello_with_two_compression_bytes_gets_illegal_parameter()
        {
            byte[] hello = ClientHelloBytes();
            byte[] longer = hello.Take(ClientHelloCompressionLengthAt).Concat(new byte[] { 2, 0, 0 }).Concat(hello.Skip(ClientHelloCompressionLengthAt + 2)).ToArray();
            AssertAlert(IllegalParameter, FeedServer(WithBodyLength(longer)));
        }

        // ---------------------------------------------------------------- section 4.2, extensions a client did not ask for

        [Fact]
        public void Control_an_untouched_server_hello_passes()
        {
            Assert.Null(FeedClient(ServerHelloBytes()).Error);
        }

        [Fact]
        public void A_server_hello_extension_the_client_did_not_request_gets_unsupported_extension()
        {
            AssertAlert(UnsupportedExtension, FeedClient(WithExtra(ServerHelloBytes(), Extension(ExtUnknown))));
        }

        [Fact]
        public void An_encrypted_extensions_entry_the_client_did_not_request_gets_unsupported_extension()
        {
            AssertAlert(UnsupportedExtension, ClientGetsFlightWith("EncryptedExtensions", EncryptedExtensionsWith(Extension(ExtUnknown))));
        }

        [Fact]
        public void A_recognised_extension_in_the_wrong_message_gets_illegal_parameter()
        {
            AssertAlert(IllegalParameter, FeedClient(WithExtra(ServerHelloBytes(), Extension(ExtServerName))));
            AssertAlert(IllegalParameter, ClientGetsFlightWith("EncryptedExtensions", EncryptedExtensionsWith(Extension(ExtKeyShare))));
        }

        [Theory]
        [InlineData(ExtServerName)]
        [InlineData(ExtSupportedGroups)]
        public void Control_encrypted_extensions_may_answer_what_the_client_asked(int type)
        {
            // The swap also breaks the transcript, so a later check may fail. The extension itself must not be the refusal.
            EngineOutput o = ClientGetsFlightWith("EncryptedExtensions", EncryptedExtensionsWith(Extension(type)));
            Assert.True(o.Error == null || (Tls13Codes.AlertFor(o.Error.Code) != UnsupportedExtension && Tls13Codes.AlertFor(o.Error.Code) != IllegalParameter), Describe(o));
        }

        // ---------------------------------------------------------------- section 4.2.3, signature_algorithms

        [Fact]
        public void A_client_hello_with_no_signature_algorithms_gets_missing_extension()
        {
            AssertAlert(MissingExtension, FeedServer(WithoutExtension(ClientHelloBytes(), ExtSignatureAlgorithms)));
        }

        [Fact]
        public void Control_signature_algorithms_with_no_common_scheme_keeps_handshake_failure()
        {
            byte[] hello = WithoutExtension(ClientHelloBytes(), ExtSignatureAlgorithms);
            hello = WithExtra(hello, Extension(ExtSignatureAlgorithms, 0, 2, 0x04, 0x03));
            AssertAlert(HandshakeFailure, FeedServer(hello));
        }

        // ---------------------------------------------------------------- section 4.2.1, supported_versions

        [Theory]
        [InlineData(0x0305)]
        [InlineData(0x0303)]
        public void A_server_hello_version_the_client_did_not_offer_gets_illegal_parameter(int version)
        {
            byte[] hello = WithoutExtension(ServerHelloBytes(), ExtSupportedVersions);
            hello = WithExtra(hello, Extension(ExtSupportedVersions, (byte)(version >> 8), (byte)version));
            AssertAlert(IllegalParameter, FeedClient(hello));
        }

        [Fact]
        public void Control_a_server_hello_with_no_supported_versions_keeps_protocol_version()
        {
            AssertAlert(ProtocolVersion, FeedClient(WithoutExtension(ServerHelloBytes(), ExtSupportedVersions)));
        }

        // ---------------------------------------------------------------- section 4.4.2.4, an empty server Certificate

        [Fact]
        public void An_empty_server_certificate_gets_decode_error()
        {
            AssertAlert(DecodeError, ClientGetsFlightWith("Certificate", Tls13Messages.CertificateMessage(new byte[0][])));
        }

        [Fact]
        public void Control_a_certificate_that_does_not_verify_keeps_bad_certificate()
        {
            byte[] stranger = new TrainingCa(new OtherRoot()).RootCertificateDer;
            AssertAlert(BadCertificate, ClientGetsFlightWith("Certificate", Tls13Messages.CertificateMessage(new[] { stranger })));
        }

        sealed class OtherRoot : ITrainingKeySource
        {
            public ITrainingKey Find(string keyId) => new TrainingKeySource().Find(KeyIds.AttackerEd25519);
        }
    }
}
