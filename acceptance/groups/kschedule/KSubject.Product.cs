using System;
using System.Collections.Generic;
using System.Reflection;
using NetSec.Crypto;
using NetSec.Tls13;

namespace Acceptance
{
    /// <summary>
    /// Product mapping for A4: Tls13KeySchedule.Derive (design section 11). The fields of Tls13Secrets are "named per RFC 8446".
    /// The spelling is not fixed, so each secret is found by name with case, underscores and digits ignored. A secret with no matching
    /// member is NOT RUN, with the member name the suite looked for.
    /// </summary>
    static class KSubject
    {
        static readonly string[][] Names = new string[][]
        {
            new string[] { "early_secret", "earlysecret" },
            new string[] { "handshake_secret", "handshakesecret" },
            new string[] { "c_hs_traffic", "clienthandshaketrafficsecret", "chandshaketrafficsecret" },
            new string[] { "s_hs_traffic", "serverhandshaketrafficsecret", "shandshaketrafficsecret" },
            new string[] { "master_secret", "mastersecret" },
            new string[] { "c_ap_traffic", "clientapplicationtrafficsecret", "clienttrafficsecret" },
            new string[] { "s_ap_traffic", "serverapplicationtrafficsecret", "servertrafficsecret" },
            new string[] { "exp_master", "exportermastersecret", "exportersecret" },
        };

        static string Norm(string s)
        {
            System.Text.StringBuilder sb = new System.Text.StringBuilder();
            foreach (char ch in s) if (char.IsLetter(ch)) sb.Append(char.ToLowerInvariant(ch));
            return sb.ToString();
        }

        public static Dictionary<string, byte[]> Derive(byte[] shared, byte[] helloHash, byte[] serverFinishedHash)
        {
            Tls13Secrets s = Tls13KeySchedule.Derive(Hashes.Sha256, shared, helloHash, serverFinishedHash);
            Dictionary<string, byte[]> r = new Dictionary<string, byte[]>();
            foreach (string[] n in Names)
            {
                for (int i = 1; i < n.Length && !r.ContainsKey(n[0]); i++)
                {
                    foreach (MemberInfo m in typeof(Tls13Secrets).GetMembers(BindingFlags.Public | BindingFlags.Instance))
                    {
                        if (m.MemberType != MemberTypes.Field && m.MemberType != MemberTypes.Property) continue;
                        if (Norm(m.Name) != n[i]) continue;
                        FieldInfo f = m as FieldInfo; PropertyInfo p = m as PropertyInfo;
                        byte[] v = (byte[])(f != null ? f.GetValue(s) : p.GetValue(s, null));
                        r[n[0]] = v;
                        break;
                    }
                }
            }
            return r;
        }

        public static byte[] Sha256(byte[] data)
        {
            IHash h = Hashes.Sha256();
            h.Update(data, 0, data.Length);
            return h.Finish();
        }

        public static byte[] X25519(byte[] scalar, byte[] u) { return NetSec.Crypto.X25519.Mult(scalar, u); }

        /// <summary>
        /// ASSUMED seam: public static Tls13Resumption Resume(Func&lt;IHash&gt; h, byte[] masterSecret, byte[] clientFinishedHash, byte[] ticketNonce)
        /// with byte[] fields or properties ResumptionMasterSecret and ResumptionSecret. Found by reflection, so a missing seam NOT RUNs
        /// this one clause and does not stop the group from compiling.
        /// </summary>
        public static void Resume(byte[] master, byte[] hashToClientFinished, byte[] nonce, out byte[] resMaster, out byte[] resumption)
        {
            System.Reflection.MethodInfo m = typeof(Tls13KeySchedule).GetMethod("Resume", BindingFlags.Public | BindingFlags.Static);
            if (m == null) throw new NotRunException("DERIVE_LACKS_RESUMPTION", "Tls13KeySchedule has no static Resume(hash, masterSecret, clientFinishedHash, ticketNonce); the resumption secrets cannot be checked (CONTRACT.md)");
            Func<IHash> h = Hashes.Sha256;
            object res = m.Invoke(null, new object[] { h, master, hashToClientFinished, nonce });
            resMaster = Member(res, "resumptionmastersecret");
            resumption = Member(res, "resumptionsecret");
        }

        static byte[] Member(object o, string normName)
        {
            foreach (MemberInfo mi in o.GetType().GetMembers(BindingFlags.Public | BindingFlags.Instance))
            {
                if (mi.MemberType != MemberTypes.Field && mi.MemberType != MemberTypes.Property) continue;
                if (Norm(mi.Name) != normName) continue;
                FieldInfo f = mi as FieldInfo; PropertyInfo p = mi as PropertyInfo;
                return (byte[])(f != null ? f.GetValue(o) : p.GetValue(o, null));
            }
            throw new NotRunException("DERIVE_LACKS_RESUMPTION", "the Resume result has no member " + normName);
        }

        public static byte[] HmacSha256(byte[] key, byte[] data) { return Hmac.Compute(Hashes.Sha256, key, data); }

        /// <summary>HKDF-Expand-Label (RFC 8446 section 7.1) built on the product's Hkdf.Expand.</summary>
        public static byte[] ExpandLabel(byte[] secret, string label, byte[] context, int length)
        {
            byte[] full = System.Text.Encoding.ASCII.GetBytes("tls13 " + label);
            byte[] info = Hex.Concat(new byte[] { (byte)(length >> 8), (byte)length, (byte)full.Length }, full, new byte[] { (byte)context.Length }, context);
            return Hkdf.Expand(Hashes.Sha256, secret, info, length);
        }
    }
}
