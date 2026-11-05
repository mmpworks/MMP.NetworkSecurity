using System;
using System.Collections.Generic;
using System.Text;
using NetSec.Bytes;
using NetSec.Crypto;
using NetSec.Errors;
using NetSec.Keys;

namespace NetSec.Auth
{
    /// <summary>A rule's answer. A refusal names its code and the check that made it. A rule keeps no state, so the caller records a jti or a challenge.</summary>
    public sealed class AuthDecision
    {
        public bool Allowed;
        public string Code, CheckName;
        public string Detail;
        public Dictionary<string, object> Claims;
        public string Jti;

        internal static AuthDecision Refuse(string code, string checkName, string detail)
        {
            AuthDecision refused = new AuthDecision();
            refused.Code = code;
            refused.CheckName = checkName;
            refused.Detail = detail;
            return refused;
        }

        internal static AuthDecision Allow(Dictionary<string, object> claims, string jti)
        {
            AuthDecision allowed = new AuthDecision();
            allowed.Allowed = true;
            allowed.Claims = claims;
            allowed.Jti = jti;
            return allowed;
        }
    }

    /// <summary>One compact JWS split into its three parts, with its header read. Only an EdDSA signature counts here.</summary>
    internal sealed class CompactJws
    {
        public readonly string HeaderPart, ClaimsPart, SignaturePart;
        public readonly Dictionary<string, object> Header;
        public readonly byte[] Signature;

        CompactJws(string header, string claims, string signature, Dictionary<string, object> headerJson, byte[] signatureBytes)
        {
            HeaderPart = header; ClaimsPart = claims; SignaturePart = signature; Header = headerJson; Signature = signatureBytes;
        }

        /// <summary>The bytes the signature covers: the header and claims parts as ASCII, so a change of any character breaks it.</summary>
        public byte[] SigningInput { get { return Encoding.UTF8.GetBytes(HeaderPart + "." + ClaimsPart); } }

        public Dictionary<string, object> ReadClaims()
        {
            byte[] json = Base64Url.Decode(ClaimsPart);
            return (MiniJsonReader.Parse(Encoding.UTF8.GetString(json, 0, json.Length)) as Dictionary<string, object>)
                ?? Throw("the claims are not a JSON object");
        }

        /// <summary>Throws ParseFailure when the text is not a compact JWS.</summary>
        public static CompactJws Split(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            string[] parts = text.Split('.');
            if (parts.Length != 3) throw new ParseFailure(MiniJsonReader.Malformed, "a compact JWS has three parts, and this one has " + parts.Length);
            byte[] header = Base64Url.Decode(parts[0]);
            Dictionary<string, object> headerJson = (MiniJsonReader.Parse(Encoding.UTF8.GetString(header, 0, header.Length)) as Dictionary<string, object>)
                ?? Throw("the header is not a JSON object");
            return new CompactJws(parts[0], parts[1], parts[2], headerJson, Base64Url.Decode(parts[2]));
        }

        public static string Sign(byte[] seed, string headerJson, string claimsJson)
        {
            string input = Base64Url.Encode(Encoding.UTF8.GetBytes(headerJson)) + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(claimsJson));
            return input + "." + Base64Url.Encode(Ed25519.Sign(seed, Encoding.UTF8.GetBytes(input)));
        }

        static Dictionary<string, object> Throw(string why)
        {
            throw new ParseFailure(MiniJsonReader.Malformed, why);
        }
    }

    /// <summary>A signed token (a compact JWS over EdDSA, RFC 8037). Built to show the parts. Do not copy.</summary>
    public static class Token
    {
        public const string SignatureCheck = "token signature";
        public const string FormatCheck = "token format";
        public const string ExpiryCheck = "token expiry";
        public const string AudienceCheck = "token audience";
        const string Header = "{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}";

        /// <summary>How many characters the token's first part holds, so a tamper plan can aim past it.</summary>
        public static int HeaderPartLength { get { return Base64Url.Encode(Encoding.UTF8.GetBytes(Header)).Length; } }

        public static string Issue(ITrainingKey k, string claimsJson)
        {
            if (k == null) throw new ArgumentNullException("k");
            if (claimsJson == null) throw new ArgumentNullException("claimsJson");
            if (k.Algorithm != KeyAlgorithm.Ed25519) throw new ArgumentException("a token here is signed with an Ed25519 key", "k");
            return CompactJws.Sign(k.CopyMaterial(), Header, claimsJson);
        }

        /// <summary>
        /// Checks the signature before it reads a claim. A rule: the same input gives the same answer. A clock value with no zone is refused,
        /// because DateTime subtraction ignores Kind and a local value would move the expiry.
        /// </summary>
        public static AuthDecision Verify(byte[] pub, string jws, DateTime now)
        {
            if (pub == null) throw new ArgumentNullException("pub");
            if (now.Kind == DateTimeKind.Unspecified)
                return AuthDecision.Refuse(ErrorCodes.TokenBadClock, ExpiryCheck, "the clock value names no zone");
            try
            {
                CompactJws parts = CompactJws.Split(jws);
                object alg;
                if (!parts.Header.TryGetValue("alg", out alg) || !"EdDSA".Equals(alg))
                    return AuthDecision.Refuse(ErrorCodes.TokenBadAlg, FormatCheck, "the header must name EdDSA");
                if (parts.Header.ContainsKey("crit"))
                    return AuthDecision.Refuse(ErrorCodes.TokenBadHeader, FormatCheck, "this verifier knows no critical header extension");
                if (!Ed25519.Verify(pub, parts.SigningInput, parts.Signature))
                    return AuthDecision.Refuse(ErrorCodes.TokenBadSignature, SignatureCheck, "the signature does not fit this key and these claims");
                Dictionary<string, object> claims = parts.ReadClaims();
                object exp;
                if (!claims.TryGetValue("exp", out exp) || !(exp is long))
                    return AuthDecision.Refuse(ErrorCodes.TokenMalformed, ExpiryCheck, "the claims have no whole-number exp");
                if (AuthTime.ToUnix(now) >= (long)exp)
                    return AuthDecision.Refuse(ErrorCodes.TokenExpired, ExpiryCheck, "exp has passed");
                return AuthDecision.Allow(claims, null);
            }
            catch (ParseFailure failure)
            {
                return AuthDecision.Refuse(ErrorCodes.TokenMalformed, FormatCheck, failure.Message);
            }
            catch (ArgumentException failure)
            {
                return AuthDecision.Refuse(ErrorCodes.TokenMalformed, FormatCheck, failure.Message);
            }
        }
    }

    public static class AuthTime
    {
        static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        /// <summary>Unix seconds. A local value converts first. A value with no zone throws, because guessing its zone would move an expiry.</summary>
        public static long ToUnix(DateTime when)
        {
            if (when.Kind == DateTimeKind.Unspecified) throw new ArgumentException("the clock value names no zone", "when");
            return (when.ToUniversalTime() - Epoch).Ticks / TimeSpan.TicksPerSecond;
        }

        public static DateTime FromUnix(long seconds) { return Epoch.AddSeconds(seconds); }
    }

    /// <summary>A DPoP proof (RFC 9449): the client signs each call with a key the token is bound to, so a stolen token alone does nothing.</summary>
    public static class DpopProof
    {
        public const string SignatureCheck = "proof signature";
        public const string BindingCheck = "proof binding";
        public const string AgeCheck = "proof age";
        public const string ReplayCheck = "jti already used";
        public const int MaxAgeSeconds = 60;

        // RFC 7517 and RFC 7518 private key members. RFC 9449 section 4.3 step 7 refuses a jwk that holds a private key.
        static readonly string[] PrivateMembers = { "d", "p", "q", "dp", "dq", "qi", "oth", "k" };

        static string JwkJson(byte[] pub)
        {
            // These members in this order are the RFC 7638 thumbprint input for an OKP key.
            return "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"" + Base64Url.Encode(pub) + "\"}";
        }

        /// <summary>The RFC 7638 thumbprint of a public key, the value a token's cnf.jkt holds.</summary>
        public static string Thumbprint(byte[] pub)
        {
            return Base64Url.Encode(Sha256(Encoding.UTF8.GetBytes(JwkJson(pub))));
        }

        public static string Create(byte[] seed, string htm, string htu, long iat, string jti, string accessToken)
        {
            string header = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":" + JwkJson(Ed25519.PublicFrom(seed)) + "}";
            string claims = "{\"jti\":" + MiniJson.Quote(jti) + ",\"htm\":" + MiniJson.Quote(htm) + ",\"htu\":" + MiniJson.Quote(htu)
                + ",\"iat\":" + iat + ",\"ath\":\"" + Base64Url.Encode(Sha256(Encoding.UTF8.GetBytes(accessToken))) + "\"}";
            return CompactJws.Sign(seed, header, claims);
        }

        /// <summary>
        /// Runs these steps of RFC 9449 section 4.3, in this order: 2, 4, 5, the shape of the jwk, 6, 7, 3, 8, 9, 11, 12. Step 3 runs after step 6 so no
        /// unsigned claim is read. Not run: step 1, because this method takes one proof and counting header fields belongs to an HTTP server; and
        /// step 10, because this lab supplies no nonce, which sections 8 and 9 make optional. Step 9 compares the whole htu, so a query is refused where
        /// the RFC says to ignore it. Replay stays with the caller, which holds the seen ids, and a real server keeps them for the whole iat window.
        /// A pass returns the jti.
        /// </summary>
        public static AuthDecision Check(string proof, string htm, string htu, long now, string accessToken, string expectedJkt)
        {
            try
            {
                return CheckParts(CompactJws.Split(proof), htm, htu, now, accessToken, expectedJkt);
            }
            catch (ParseFailure failure)
            {
                return AuthDecision.Refuse(ErrorCodes.DpopMalformed, SignatureCheck, failure.Message);
            }
            catch (ArgumentException failure)
            {
                return AuthDecision.Refuse(ErrorCodes.DpopMalformed, SignatureCheck, failure.Message);
            }
        }

        static AuthDecision CheckParts(CompactJws parts, string htm, string htu, long now, string accessToken, string expectedJkt)
        {
            if (!"dpop+jwt".Equals(Member(parts.Header, "typ")) || !"EdDSA".Equals(Member(parts.Header, "alg")) || parts.Header.ContainsKey("crit"))
                return AuthDecision.Refuse(ErrorCodes.DpopMalformed, SignatureCheck, "the header must say dpop+jwt and EdDSA, and hold no crit");
            Dictionary<string, object> jwk = Member(parts.Header, "jwk") as Dictionary<string, object>;
            byte[] pub = PublicFrom(jwk);
            if (pub == null) return AuthDecision.Refuse(ErrorCodes.DpopBadKey, SignatureCheck, "the header holds no Ed25519 key");
            if (!Ed25519.Verify(pub, parts.SigningInput, parts.Signature))
                return AuthDecision.Refuse(ErrorCodes.DpopBadSignature, SignatureCheck, "the key in the header did not sign this proof");
            for (int i = 0; i < PrivateMembers.Length; i++)
                if (jwk.ContainsKey(PrivateMembers[i]))
                    return AuthDecision.Refuse(ErrorCodes.DpopBadKey, SignatureCheck, "the key in the header holds the private member " + PrivateMembers[i]);
            Dictionary<string, object> claims = parts.ReadClaims();
            string jti = Member(claims, "jti") as string;
            if (string.IsNullOrEmpty(jti) || !(Member(claims, "iat") is long))
                return AuthDecision.Refuse(ErrorCodes.DpopMalformed, SignatureCheck, "the claims need a jti and a whole-number iat");
            if (!htm.Equals(Member(claims, "htm"))) return AuthDecision.Refuse(ErrorCodes.DpopHtmMismatch, BindingCheck, "the proof names another method");
            if (!htu.Equals(Member(claims, "htu"))) return AuthDecision.Refuse(ErrorCodes.DpopHtuMismatch, BindingCheck, "the proof names another address");
            long age = now - (long)Member(claims, "iat");
            if (age > MaxAgeSeconds || age < -MaxAgeSeconds) return AuthDecision.Refuse(ErrorCodes.DpopIatWindow, AgeCheck, "iat is " + age + " seconds from now");
            string ath = Base64Url.Encode(Sha256(Encoding.UTF8.GetBytes(accessToken)));
            if (!ath.Equals(Member(claims, "ath"))) return AuthDecision.Refuse(ErrorCodes.DpopAthMismatch, BindingCheck, "the proof names another token");
            if (Thumbprint(pub) != expectedJkt) return AuthDecision.Refuse(ErrorCodes.DpopJktMismatch, BindingCheck, "the token is bound to another key");
            return AuthDecision.Allow(claims, jti);
        }

        static byte[] PublicFrom(Dictionary<string, object> jwk)
        {
            if (jwk == null || !"OKP".Equals(Member(jwk, "kty")) || !"Ed25519".Equals(Member(jwk, "crv"))) return null;
            string x = Member(jwk, "x") as string;
            if (x == null) return null;
            byte[] pub = Base64Url.Decode(x);
            return pub.Length == 32 ? pub : null;
        }

        static object Member(Dictionary<string, object> members, string name)
        {
            object value;
            return members.TryGetValue(name, out value) ? value : null;
        }

        static byte[] Sha256(byte[] bytes)
        {
            IHash hash = Hashes.Sha256();
            hash.Update(bytes, 0, bytes.Length);
            return hash.Finish();
        }
    }

    /// <summary>A passkey-shaped challenge: a device key signs a fresh number and the origin. It shows the idea. It is not WebAuthn.</summary>
    public static class Challenge
    {
        public const string SignatureCheck = "challenge signature";
        public const string ReplayCheck = "challenge already used";
        public const string IssuedCheck = "challenge issued";
        public const string EnrolledCheck = "device enrolled";

        static byte[] Input(byte[] challenge, string origin)
        {
            return new ByteWriter().Put(Encoding.UTF8.GetBytes(origin)).U8(0).Put(challenge).ToArray();
        }

        public static byte[] Sign(byte[] seed, byte[] challenge, string origin)
        {
            return Ed25519.Sign(seed, Input(challenge, origin));
        }

        public static AuthDecision Verify(byte[] devicePublicKey, byte[] challenge, string origin, byte[] signature)
        {
            return Ed25519.Verify(devicePublicKey, Input(challenge, origin), signature)
                ? AuthDecision.Allow(null, null)
                : AuthDecision.Refuse(ErrorCodes.ChallengeBadSignature, SignatureCheck, "the device key did not sign this challenge and origin");
        }
    }

    /// <summary>Who may do what. A role names a job and grants a fixed set of actions. A capability names one action, so the token grants only that action.</summary>
    public static class AccessRules
    {
        public const string PermissionCheck = "permission check";

        public static AuthDecision Decide(string[] roles, string[] capabilities, string action)
        {
            if (action == "read-totals")
                return Holds(roles, "cashier") || Holds(roles, "manager")
                    ? AuthDecision.Allow(null, null)
                    : AuthDecision.Refuse(ErrorCodes.RoleDenied, PermissionCheck, "reading totals needs the role cashier or manager");
            return Holds(capabilities, action)
                ? AuthDecision.Allow(null, null)
                : AuthDecision.Refuse(ErrorCodes.CapabilityDenied, PermissionCheck, "the token holds no capability named " + action);
        }

        static bool Holds(string[] names, string name)
        {
            return names != null && Array.IndexOf(names, name) >= 0;
        }

        /// <summary>A JSON array of strings from a claim. Anything else gives an empty list, which grants nothing.</summary>
        public static string[] Names(Dictionary<string, object> claims, string member)
        {
            object value;
            List<object> items = claims.TryGetValue(member, out value) ? value as List<object> : null;
            if (items == null) return new string[0];
            List<string> names = new List<string>();
            for (int i = 0; i < items.Count; i++)
                if (items[i] is string) names.Add((string)items[i]);
            return names.ToArray();
        }
    }
}
