using System;
using NetSec.Crypto;

namespace Acceptance
{
    /// <summary>One product state object (CbcChain or CtrCounter) and the Modes overload that takes it, bound through AoSeams.</summary>
    public sealed class ProductChain : IAoChain
    {
        readonly AoSeams.StreamSeam _s;
        public ProductChain(AoSeams.StreamSeam s) { _s = s; }
        public void Init(byte[] b, int offset) { _s.Init(b, offset); }
        public void Clear() { _s.Clear(); }
        public void Call(byte[] i, int io, int n, byte[] o, int oo) { _s.Call(i, io, n, o, oo); }
    }

    /// <summary>The product's streamed forms and caller-buffer Verify forms. A form that does not exist makes Has(op) false.</summary>
    public sealed class ProductStream : IAoStream
    {
        readonly Func<AesKey, byte[], int, int, byte[], int, bool> _verify = AoSeams.TryCmacVerifyInto();
        public string Name { get { return "product"; } }

        static string StateType(string kind) { return kind == "ctr" ? "CtrCounter" : "CbcChain"; }
        static string Method(string kind) { return kind == "ctr" ? "Ctr" : kind == "cbc-encrypt" ? "CbcEncrypt" : "CbcDecrypt"; }

        public bool Has(string op)
        {
            AesKey probe = new AesKey(new byte[16]);
            switch (op)
            {
                case "aes-cbc-stream":
                    return AoSeams.TryStream(probe, StateType("cbc-encrypt"), Method("cbc-encrypt")) != null &&
                           AoSeams.TryStream(probe, StateType("cbc-decrypt"), Method("cbc-decrypt")) != null;
                case "aes-ctr-stream": return AoSeams.TryStream(probe, StateType("ctr"), Method("ctr")) != null;
                case "aes-cmac-verify-into": return _verify != null;
                default: return AoSeams.TryCmacKeyVerify(probe) != null;
            }
        }

        public object NewKey(byte[] key) { return new AesKey(key); }
        public IAoChain NewChain(object k, string kind) { return new ProductChain(AoSeams.Stream((AesKey)k, StateType(kind), Method(kind))); }
        public void NullStateCall(object k, string kind, byte[] i, int io, int n, byte[] o, int oo) { AoSeams.StreamNullState((AesKey)k, StateType(kind), Method(kind))(i, io, n, o, oo); }
        public bool CmacVerify(object k, byte[] m, int mo, int n, byte[] t, int to) { return _verify((AesKey)k, m, mo, n, t, to); }
        public bool CmacKeyVerify(object k, byte[] m, int mo, int n, byte[] t, int to) { return AoSeams.CmacKeyVerify((AesKey)k)(m, mo, n, t, to); }
    }

    /// <summary>AO-2 rows for the streamed forms and the caller-buffer Verify forms (S1). Each reads NOT RUN PRODUCT_MISSING until its form exists.</summary>
    public static class AoStreamClauses
    {
        static string Op(Ctx c, string op) { AoSubject.Make(c); return AoStreamDiff.Run(op, new FrozenStream(), new ProductStream(), AoDiff.CasesOf(c)); }

        [Clause("AO-2.aes-cbc-stream", PerBuild = true, TimeoutSec = 3600)] public static string CbcStream(Ctx c) { return Op(c, "aes-cbc-stream"); }
        [Clause("AO-2.aes-ctr-stream", PerBuild = true, TimeoutSec = 3600)] public static string CtrStream(Ctx c) { return Op(c, "aes-ctr-stream"); }
        [Clause("AO-2.aes-cmac-verify-into", PerBuild = true, TimeoutSec = 3600)] public static string CmacVerify(Ctx c) { return Op(c, "aes-cmac-verify-into"); }
        [Clause("AO-2.aes-cmackey-verify-into", PerBuild = true, TimeoutSec = 3600)] public static string CmacKeyVerify(Ctx c) { return Op(c, "aes-cmackey-verify-into"); }
    }
}
