using System;
using NetSec.Crypto;

namespace Acceptance
{
    /// <summary>The product's caller-buffer forms, bound once through AoSeams. A form that does not exist makes Has(op) false.</summary>
    public sealed class ProductInto : IAoInto
    {
        readonly Action<AesKey, byte[], int, int, byte[], int> _ecbE = AoSeams.TryEcbInto(true), _ecbD = AoSeams.TryEcbInto(false), _cmac = AoSeams.TryCmacInto();
        readonly Action<AesKey, byte[], int, byte[], int, int, byte[], int> _cbcE = AoSeams.TryCbcInto(true), _cbcD = AoSeams.TryCbcInto(false), _ctr = AoSeams.TryCtrInto();
        readonly bool _cmacKey, _gcmKey;

        public ProductInto()
        {
            AesKey probe = new AesKey(new byte[16]);
            _cmacKey = AoSeams.TryCmacKeyCompute(probe) != null;
            _gcmKey = AoSeams.TryGcmKeySealInto(probe) != null && AoSeams.TryGcmKeyOpenInto(probe) != null;
        }

        public string Name { get { return "product"; } }

        public bool Has(string op)
        {
            switch (op)
            {
                case "aes-ecb-into": return _ecbE != null && _ecbD != null;
                case "aes-cbc-into": return _cbcE != null && _cbcD != null;
                case "aes-ctr-into": return _ctr != null;
                case "aes-cmac-into": return _cmac != null;
                case "aes-cmackey-into": return _cmacKey;
                default: return _gcmKey;
            }
        }

        public object NewKey(byte[] key) { return new AesKey(key); }
        public void Ecb(object k, bool encrypt, byte[] i, int io, int n, byte[] o, int oo) { (encrypt ? _ecbE : _ecbD)((AesKey)k, i, io, n, o, oo); }
        public void Cbc(object k, bool encrypt, byte[] iv, int ivo, byte[] i, int io, int n, byte[] o, int oo) { (encrypt ? _cbcE : _cbcD)((AesKey)k, iv, ivo, i, io, n, o, oo); }
        public void Ctr(object k, byte[] ctr, int co, byte[] i, int io, int n, byte[] o, int oo) { _ctr((AesKey)k, ctr, co, i, io, n, o, oo); }
        public void Cmac(object k, byte[] m, int mo, int n, byte[] t, int to) { _cmac((AesKey)k, m, mo, n, t, to); }
        public void CmacKey(object k, byte[] m, int mo, int n, byte[] t, int to) { AoSeams.CmacKeyCompute((AesKey)k)(m, mo, n, t, to); }
        public void GcmSeal(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo) { AoSeams.GcmKeySealInto((AesKey)k)(nonce, no, aad, ao, an, i, io, n, o, oo); }
        public bool GcmOpen(object k, byte[] nonce, int no, byte[] aad, int ao, int an, byte[] i, int io, int n, byte[] o, int oo) { return AoSeams.GcmKeyOpenInto((AesKey)k)(nonce, no, aad, ao, an, i, io, n, o, oo); }
    }

    /// <summary>AO-2 rows for the caller-buffer forms (S1). Each reads NOT RUN PRODUCT_MISSING until its form exists.</summary>
    public static class AoIntoClauses
    {
        static string Op(Ctx c, string op) { AoSubject.Make(c); return AoIntoDiff.Run(op, new FrozenInto(), new ProductInto(), AoDiff.CasesOf(c)); }

        [Clause("AO-2.aes-ecb-into", PerBuild = true, TimeoutSec = 3600)] public static string Ecb(Ctx c) { return Op(c, "aes-ecb-into"); }
        [Clause("AO-2.aes-cbc-into", PerBuild = true, TimeoutSec = 3600)] public static string Cbc(Ctx c) { return Op(c, "aes-cbc-into"); }
        [Clause("AO-2.aes-ctr-into", PerBuild = true, TimeoutSec = 3600)] public static string Ctr(Ctx c) { return Op(c, "aes-ctr-into"); }
        [Clause("AO-2.aes-cmac-into", PerBuild = true, TimeoutSec = 3600)] public static string Cmac(Ctx c) { return Op(c, "aes-cmac-into"); }
        [Clause("AO-2.aes-cmackey-into", PerBuild = true, TimeoutSec = 3600)] public static string CmacKey(Ctx c) { return Op(c, "aes-cmackey-into"); }
        [Clause("AO-2.aes-gcm-into", PerBuild = true, TimeoutSec = 3600)] public static string Gcm(Ctx c) { return Op(c, "aes-gcm-into"); }
    }
}
