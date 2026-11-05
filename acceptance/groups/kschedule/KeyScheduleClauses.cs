using System;



namespace Acceptance
{
    /// <summary>
    /// A4: the TLS 1.3 key schedule matches the RFC 8448 section 3 trace byte for byte.
    /// Values: acceptance/vectors/tls13-rfc8448.nsv (every octet count checked against the RFC text).
    /// The engine route (feeding the RFC server flight to the glass client) is not used. The glass client sends its own
    /// ClientHello, which differs from the RFC's, so its transcript and secrets differ by design. The pure schedule class
    /// is what the design says A4 runs on ("Tls13KeySchedule is pure"). Its members are ASSUMED, see CONTRACT.md.
    /// </summary>
    public static class KeyScheduleClauses
    {
        const string Suite = "TLS_AES_128_GCM_SHA256";

        static VectorRecord Rfc(Ctx c) { return c.Vectors("tls13-rfc8448.nsv", "tls13-rfc8448-1rtt")[0]; }

        [Clause("A4.rfc8448.early-secret", PerBuild = true)]
        public static string EarlySecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            Check.Bytes("early secret (no PSK)", r.Bytes("early_secret"), ks.EarlySecret(null));
            return "early secret " + Hex.Short(r.Bytes("early_secret"));
        }

        [Clause("A4.rfc8448.handshake-secret", PerBuild = true)]
        public static string HandshakeSecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            Check.Bytes("handshake secret", r.Bytes("handshake_secret"), ks.HandshakeSecret(r.Bytes("early_secret"), r.Bytes("ecdhe_shared")));
            // Control pair: one flipped bit in the ECDHE input must change the result.
            byte[] bad = r.Bytes("ecdhe_shared");
            bad[0] ^= 0x01;
            Check.True(!Hex.Eq(r.Bytes("handshake_secret"), ks.HandshakeSecret(r.Bytes("early_secret"), bad)), "handshake secret ignored a changed ECDHE input");
            return "handshake secret";
        }

        [Clause("A4.rfc8448.x25519-shared-secret", PerBuild = true)]
        public static string X25519Shared(Ctx c)
        {
            VectorRecord r = Rfc(c);
            // The RFC derives the x25519 shared secret too: client private key with server public key, and the reverse.
            Check.Bytes("x25519 shared secret", r.Bytes("ecdhe_shared"), KSubject.X25519(r.Bytes("client_private"), r.Bytes("server_public")));
            Check.Bytes("x25519 shared secret (server side)", r.Bytes("ecdhe_shared"), KSubject.X25519(r.Bytes("server_private"), r.Bytes("client_public")));
            return "x25519 shared secret, both sides";
        }

        [Clause("A4.rfc8448.handshake-traffic-secrets", PerBuild = true)]
        public static string HandshakeTrafficSecrets(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            byte[] hs = r.Bytes("handshake_secret"), hash = r.Bytes("hash_client_hello_to_server_hello");
            Check.Bytes("client handshake traffic secret", r.Bytes("c_hs_traffic"), ks.DeriveSecret(hs, "c hs traffic", hash));
            Check.Bytes("server handshake traffic secret", r.Bytes("s_hs_traffic"), ks.DeriveSecret(hs, "s hs traffic", hash));
            return "c hs traffic and s hs traffic";
        }

        [Clause("A4.rfc8448.master-secret", PerBuild = true)]
        public static string MasterSecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            Check.Bytes("master secret", r.Bytes("master_secret"), ks.MasterSecret(r.Bytes("handshake_secret")));
            return "master secret";
        }

        [Clause("A4.rfc8448.application-traffic-secrets", PerBuild = true)]
        public static string ApplicationTrafficSecrets(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            byte[] master = r.Bytes("master_secret"), hash = r.Bytes("hash_to_server_finished");
            Check.Bytes("client application traffic secret 0", r.Bytes("c_ap_traffic"), ks.DeriveSecret(master, "c ap traffic", hash));
            Check.Bytes("server application traffic secret 0", r.Bytes("s_ap_traffic"), ks.DeriveSecret(master, "s ap traffic", hash));
            return "c ap traffic and s ap traffic";
        }

        [Clause("A4.rfc8448.exporter-and-resumption", PerBuild = true)]
        public static string ExporterAndResumption(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            byte[] master = r.Bytes("master_secret");
            Check.Bytes("exporter master secret", r.Bytes("exp_master"), ks.DeriveSecret(master, "exp master", r.Bytes("hash_to_server_finished")));
            Check.Bytes("resumption master secret", r.Bytes("res_master"), ks.DeriveSecret(master, "res master", r.Bytes("hash_to_client_finished")));
            Check.Bytes("resumption secret", r.Bytes("resumption_secret"), ks.ExpandLabel(r.Bytes("res_master"), "resumption", r.Bytes("ticket_nonce"), 32));
            return "exp master, res master, resumption";
        }

        [Clause("A4.rfc8448.traffic-keys-and-ivs", PerBuild = true)]
        public static string TrafficKeysAndIvs(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            Check.Bytes("server handshake key", r.Bytes("s_hs_key"), ks.TrafficKey(r.Bytes("s_hs_traffic")));
            Check.Bytes("server handshake iv", r.Bytes("s_hs_iv"), ks.TrafficIv(r.Bytes("s_hs_traffic")));
            Check.Bytes("server application key", r.Bytes("s_ap_key"), ks.TrafficKey(r.Bytes("s_ap_traffic")));
            Check.Bytes("server application iv", r.Bytes("s_ap_iv"), ks.TrafficIv(r.Bytes("s_ap_traffic")));
            Check.Bytes("client application key", r.Bytes("c_ap_key"), ks.TrafficKey(r.Bytes("c_ap_traffic")));
            Check.Bytes("client application iv", r.Bytes("c_ap_iv"), ks.TrafficIv(r.Bytes("c_ap_traffic")));
            return "6 keys and IVs";
        }

        [Clause("A4.rfc8448.finished", PerBuild = true)]
        public static string Finished(Ctx c)
        {
            VectorRecord r = Rfc(c);
            KSubject ks = new KSubject(Suite);
            Check.Bytes("server finished key", r.Bytes("s_finished_key"), ks.FinishedKey(r.Bytes("s_hs_traffic")));
            Check.Bytes("client finished key", r.Bytes("c_finished_key"), ks.FinishedKey(r.Bytes("c_hs_traffic")));
            // verify_data = HMAC(finished key, transcript hash). The RFC prints the transcript messages, so we hash them here.
            byte[] upToCv = Hex.Concat(r.Bytes("client_hello"), r.Bytes("server_hello"), r.Bytes("encrypted_extensions"), r.Bytes("certificate"), r.Bytes("certificate_verify"));
            byte[] upToSf = Hex.Concat(upToCv, r.Bytes("server_finished"));
            Check.Bytes("server verify_data", r.Bytes("s_finished_verify_data"), KSubject.HmacSha256(r.Bytes("s_finished_key"), Sha(upToCv)));
            Check.Bytes("client verify_data", r.Bytes("c_finished_verify_data"), KSubject.HmacSha256(r.Bytes("c_finished_key"), Sha(upToSf)));
            return "finished keys and verify_data";
        }

        [Clause("A4.rfc8448.transcript-hashes", PerBuild = true)]
        public static string TranscriptHashes(Ctx c)
        {
            VectorRecord r = Rfc(c);
            byte[] ch = r.Bytes("client_hello"), sh = r.Bytes("server_hello");
            byte[] toSh = Hex.Concat(ch, sh);
            byte[] toSf = Hex.Concat(toSh, r.Bytes("encrypted_extensions"), r.Bytes("certificate"), r.Bytes("certificate_verify"), r.Bytes("server_finished"));
            byte[] toCf = Hex.Concat(toSf, r.Bytes("client_finished"));
            Check.Bytes("hash through ServerHello", r.Bytes("hash_client_hello_to_server_hello"), Sha(toSh));
            Check.Bytes("hash through server Finished", r.Bytes("hash_to_server_finished"), Sha(toSf));
            Check.Bytes("hash through client Finished", r.Bytes("hash_to_client_finished"), Sha(toCf));
            Check.Bytes("hash of the empty string", r.Bytes("empty_hash"), Sha(new byte[0]));
            return "4 transcript hashes";
        }

        static byte[] Sha(byte[] data)
        {
            return KSubject.Sha256(data);
        }
    }
}
