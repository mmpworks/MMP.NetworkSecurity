using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A4: the TLS 1.3 key schedule matches the RFC 8448 section 3 trace byte for byte. The seam is
    /// Tls13KeySchedule.Derive(hash, shared secret, hash through ServerHello, hash through server Finished) (design section 11).
    /// Values: acceptance/vectors/tls13-rfc8448.nsv (every octet count checked against the RFC text).
    /// The engine route (feeding the RFC server flight to the glass client) is not used. The glass client sends its own
    /// ClientHello, which differs from the RFC's, so its transcript and secrets differ by design.
    /// The resumption secrets need Tls13KeySchedule.Resume (ASSUMED, CONTRACT.md). Without it the exporter-and-resumption clause is NOT RUN DERIVE_LACKS_RESUMPTION.
    /// Traffic keys, IVs and Finished keys come from the secrets Derive returned, through HKDF-Expand-Label built here on the product's Hkdf and Hmac (A2 checks those).
    /// </summary>
    public static class KeyScheduleClauses
    {
        static VectorRecord Rfc(Ctx c) { return c.Vectors("tls13-rfc8448.nsv", "tls13-rfc8448-1rtt")[0]; }

        static Dictionary<string, byte[]> Derived(VectorRecord r, byte[] shared)
        {
            return KSubject.Derive(shared, r.Bytes("hash_client_hello_to_server_hello"), r.Bytes("hash_to_server_finished"));
        }

        static byte[] Need(Dictionary<string, byte[]> got, string key)
        {
            byte[] v;
            if (!got.TryGetValue(key, out v) || v == null) throw new NotRunException("PRODUCT_MISSING", "Tls13Secrets has no member for " + key);
            return v;
        }

        static void Same(VectorRecord r, Dictionary<string, byte[]> got, string what, string key) { Check.Bytes(what, r.Bytes(key), Need(got, key)); }

        [Clause("A4.rfc8448.early-secret", PerBuild = true)]
        public static string EarlySecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Same(r, Derived(r, r.Bytes("ecdhe_shared")), "early secret (no PSK)", "early_secret");
            return "early secret " + Hex.Short(r.Bytes("early_secret"));
        }

        [Clause("A4.rfc8448.handshake-secret", PerBuild = true)]
        public static string HandshakeSecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Same(r, Derived(r, r.Bytes("ecdhe_shared")), "handshake secret", "handshake_secret");
            // Control pair: one flipped bit in the ECDHE input must change the result.
            byte[] bad = r.Bytes("ecdhe_shared");
            bad[0] ^= 0x01;
            Check.True(!Hex.Eq(r.Bytes("handshake_secret"), Need(Derived(r, bad), "handshake_secret")), "handshake secret ignored a changed ECDHE input");
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
            Dictionary<string, byte[]> got = Derived(r, r.Bytes("ecdhe_shared"));
            Same(r, got, "client handshake traffic secret", "c_hs_traffic");
            Same(r, got, "server handshake traffic secret", "s_hs_traffic");
            // Control pair: the handshake secrets do not depend on the server Finished hash, and the application secrets do.
            byte[] later = r.Bytes("hash_to_server_finished");
            later[0] ^= 0x01;
            Dictionary<string, byte[]> moved = KSubject.Derive(r.Bytes("ecdhe_shared"), r.Bytes("hash_client_hello_to_server_hello"), later);
            Check.True(Hex.Eq(Need(got, "c_hs_traffic"), Need(moved, "c_hs_traffic")), "the client handshake traffic secret changed when only the server Finished hash changed");
            Check.True(!Hex.Eq(Need(got, "c_ap_traffic"), Need(moved, "c_ap_traffic")), "the client application traffic secret ignored the server Finished hash");
            return "c hs traffic and s hs traffic";
        }

        [Clause("A4.rfc8448.master-secret", PerBuild = true)]
        public static string MasterSecret(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Same(r, Derived(r, r.Bytes("ecdhe_shared")), "master secret", "master_secret");
            return "master secret";
        }

        [Clause("A4.rfc8448.application-traffic-secrets", PerBuild = true)]
        public static string ApplicationTrafficSecrets(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Dictionary<string, byte[]> got = Derived(r, r.Bytes("ecdhe_shared"));
            Same(r, got, "client application traffic secret 0", "c_ap_traffic");
            Same(r, got, "server application traffic secret 0", "s_ap_traffic");
            return "c ap traffic and s ap traffic";
        }

        [Clause("A4.rfc8448.exporter-and-resumption", PerBuild = true)]
        public static string ExporterAndResumption(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Same(r, Derived(r, r.Bytes("ecdhe_shared")), "exporter master secret", "exp_master");
            // The resumption secrets need the client Finished hash, which Derive does not take. Until the product offers
            // Tls13KeySchedule.Resume (CONTRACT.md), this clause is NOT RUN with a named reason and never PASS.
            byte[] resMaster, resumption;
            KSubject.Resume(r.Bytes("master_secret"), r.Bytes("hash_to_client_finished"), r.Bytes("ticket_nonce"), out resMaster, out resumption);
            Check.Bytes("resumption master secret", r.Bytes("res_master"), resMaster);
            Check.Bytes("resumption secret", r.Bytes("resumption_secret"), resumption);
            return "exp master, res master, resumption";
        }

        [Clause("A4.rfc8448.traffic-keys-and-ivs", PerBuild = true)]
        public static string TrafficKeysAndIvs(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Dictionary<string, byte[]> got = Derived(r, r.Bytes("ecdhe_shared"));
            Check.Bytes("server handshake key", r.Bytes("s_hs_key"), KSubject.ExpandLabel(Need(got, "s_hs_traffic"), "key", new byte[0], 16));
            Check.Bytes("server handshake iv", r.Bytes("s_hs_iv"), KSubject.ExpandLabel(Need(got, "s_hs_traffic"), "iv", new byte[0], 12));
            Check.Bytes("server application key", r.Bytes("s_ap_key"), KSubject.ExpandLabel(Need(got, "s_ap_traffic"), "key", new byte[0], 16));
            Check.Bytes("server application iv", r.Bytes("s_ap_iv"), KSubject.ExpandLabel(Need(got, "s_ap_traffic"), "iv", new byte[0], 12));
            Check.Bytes("client application key", r.Bytes("c_ap_key"), KSubject.ExpandLabel(Need(got, "c_ap_traffic"), "key", new byte[0], 16));
            Check.Bytes("client application iv", r.Bytes("c_ap_iv"), KSubject.ExpandLabel(Need(got, "c_ap_traffic"), "iv", new byte[0], 12));
            return "6 keys and IVs from the secrets Derive returned";
        }

        [Clause("A4.rfc8448.finished", PerBuild = true)]
        public static string Finished(Ctx c)
        {
            VectorRecord r = Rfc(c);
            Dictionary<string, byte[]> got = Derived(r, r.Bytes("ecdhe_shared"));
            byte[] sKey = KSubject.ExpandLabel(Need(got, "s_hs_traffic"), "finished", new byte[0], 32);
            byte[] cKey = KSubject.ExpandLabel(Need(got, "c_hs_traffic"), "finished", new byte[0], 32);
            Check.Bytes("server finished key", r.Bytes("s_finished_key"), sKey);
            Check.Bytes("client finished key", r.Bytes("c_finished_key"), cKey);
            // verify_data = HMAC(finished key, transcript hash). The RFC prints the transcript messages, so we hash them here.
            byte[] upToCv = Hex.Concat(r.Bytes("client_hello"), r.Bytes("server_hello"), r.Bytes("encrypted_extensions"), r.Bytes("certificate"), r.Bytes("certificate_verify"));
            byte[] upToSf = Hex.Concat(upToCv, r.Bytes("server_finished"));
            Check.Bytes("server verify_data", r.Bytes("s_finished_verify_data"), KSubject.HmacSha256(sKey, KSubject.Sha256(upToCv)));
            Check.Bytes("client verify_data", r.Bytes("c_finished_verify_data"), KSubject.HmacSha256(cKey, KSubject.Sha256(upToSf)));
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
            Check.Bytes("hash through ServerHello", r.Bytes("hash_client_hello_to_server_hello"), KSubject.Sha256(toSh));
            Check.Bytes("hash through server Finished", r.Bytes("hash_to_server_finished"), KSubject.Sha256(toSf));
            Check.Bytes("hash through client Finished", r.Bytes("hash_to_client_finished"), KSubject.Sha256(toCf));
            Check.Bytes("hash of the empty string", r.Bytes("empty_hash"), KSubject.Sha256(new byte[0]));
            return "4 transcript hashes";
        }
    }
}
