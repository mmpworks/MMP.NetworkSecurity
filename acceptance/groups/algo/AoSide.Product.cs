using System;
using NetSec.Crypto;
using NetSec.Dukpt;
using NetSec.Tls11;

namespace Acceptance
{
    /// <summary>The one place where the AO clauses touch product code. The members mirror FrozenSide line for line.</summary>
    public sealed class ProductSide : AoSide
    {
        public override string Name { get { return "product"; } }

        sealed class H : IAoHash
        {
            readonly IHash _h;
            public H(IHash h) { _h = h; }
            public void Update(byte[] b, int off, int n) { _h.Update(b, off, n); }
            public byte[] Finish() { return _h.Finish(); }
            public IAoHash Clone() { return new H(_h.Clone()); }
        }

        static Func<IHash> Factory(string alg)
        {
            switch (alg)
            {
                case "md5": return Hashes.Md5;
                case "sha1": return Hashes.Sha1;
                case "sha256": return Hashes.Sha256;
                case "sha384": return Hashes.Sha384;
                case "sha512": return Hashes.Sha512;
                case "sha3-256": return Hashes.Sha3_256;
                case "sha3-512": return Hashes.Sha3_512;
                default: throw new ArgumentException("no hash " + alg);
            }
        }

        public override object NewAes(byte[] key) { return new AesKey(key); }
        public override void AesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((AesKey)k).EncryptBlock(i, io, o, oo); }
        public override void AesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((AesKey)k).DecryptBlock(i, io, o, oo); }
        public override byte[] Ecb(object k, byte[] data) { return Modes.EcbEncrypt((AesKey)k, data); }
        public override byte[] Cbc(object k, byte[] iv, byte[] data, bool encrypt) { return encrypt ? Modes.CbcEncrypt((AesKey)k, iv, data) : Modes.CbcDecrypt((AesKey)k, iv, data); }
        public override byte[] Ctr(object k, byte[] counter, byte[] data) { return Modes.Ctr((AesKey)k, counter, data); }
        public override byte[] GcmSeal(object k, byte[] nonce, byte[] aad, byte[] plain) { return Gcm.Seal((AesKey)k, nonce, aad, plain); }
        public override bool GcmOpen(object k, byte[] nonce, byte[] aad, byte[] sealedBytes, out byte[] plain) { return Gcm.TryOpen((AesKey)k, nonce, aad, sealedBytes, out plain); }
        public override byte[] Cmac(object k, byte[] message) { return NetSec.Crypto.Cmac.Compute((AesKey)k, message); }
        public override bool CmacVerify(object k, byte[] message, byte[] tag) { return NetSec.Crypto.Cmac.Verify((AesKey)k, message, tag); }

        public override object NewTdes(byte[] key) { return new TdesKey(key); }
        public override void TdesEncrypt(object k, byte[] i, int io, byte[] o, int oo) { ((TdesKey)k).EncryptBlock(i, io, o, oo); }
        public override void TdesDecrypt(object k, byte[] i, int io, byte[] o, int oo) { ((TdesKey)k).DecryptBlock(i, io, o, oo); }

        public override IAoHash NewHash(string alg) { return new H(Factory(alg)()); }
        public override byte[] Shake(bool is128, byte[] data, int[] squeezeSizes)
        {
            NetSec.Crypto.Shake s = is128 ? NetSec.Crypto.Shake.New128() : NetSec.Crypto.Shake.New256();
            s.Absorb(data, 0, data == null ? 0 : data.Length);
            return AoSqueeze.All(squeezeSizes, delegate (byte[] b, int off, int n) { s.Squeeze(b, off, n); });
        }
        public override byte[] Hmac(string alg, byte[] key, byte[] data) { return NetSec.Crypto.Hmac.Compute(Factory(alg), key, data); }
        public override bool HmacVerify(string alg, byte[] key, byte[] data, byte[] tag) { return NetSec.Crypto.Hmac.Verify(Factory(alg), key, data, tag); }
        public override byte[] HkdfExtract(string alg, byte[] salt, byte[] ikm) { return Hkdf.Extract(Factory(alg), salt, ikm); }
        public override byte[] HkdfExpand(string alg, byte[] prk, byte[] info, int n) { return Hkdf.Expand(Factory(alg), prk, info, n); }

        public override byte[] PrfDerive(byte[] secret, string label, byte[] seed, int count) { return Tls11Prf.Derive(secret, label, seed, count); }
        public override byte[] PrfMaster(byte[] premaster, byte[] clientRandom, byte[] serverRandom) { return Tls11Prf.MasterSecret(premaster, clientRandom, serverRandom); }
        public override byte[][] PrfKeyBlock(byte[] master, byte[] clientRandom, byte[] serverRandom)
        {
            Tls11KeyBlock b = Tls11Prf.KeyBlock(master, clientRandom, serverRandom);
            return new byte[][] { b.ClientMac, b.ServerMac, b.ClientKey, b.ServerKey };
        }
        public override byte[] PrfFinished(byte[] master, string label, byte[] digest) { return Tls11Prf.FinishedData(master, label, digest); }
        public override byte[] PrfMd5Sha1(byte[] data) { return Tls11Prf.Md5Sha1(data); }

        public override object WalkEncrypt(object k, byte[] block) { return ((AesKey)k).WalkEncrypt(block); }
        public override object WalkDecrypt(object k, byte[] block) { return ((AesKey)k).WalkDecrypt(block); }
        public override object WalkKeyExpansion(object k) { return ((AesKey)k).WalkKeyExpansion(); }
        public override object WalkTables(int rconCount)
        {
            return new object[] { AesKey.SubstitutionTable(), AesKey.InverseSubstitutionTable(), AesKey.ShiftMap(false), AesKey.ShiftMap(true),
                                  AesKey.RoundConstants(rconCount), AesKey.RoundConstantSteps(rconCount) };
        }
        public override object WalkMixTerms(byte[] before, bool inverse) { return AesKey.MixTerms(before, inverse); }

        public override byte[] DukptInitialKey(byte[] bdk, byte[] initialKeyId) { return DukptBank.DeriveInitialKey(bdk, initialKeyId); }
        public override byte[] DukptWorkingKey(byte[] bdk, byte[] ksn, int usage, int type) { return DukptBank.DeriveWorkingKey(bdk, ksn, (DukptKeyUsage)usage, (DukptKeyType)type); }
        public override object NewPinPad(byte[] initialKey, byte[] initialKeyId) { return new DukptPinPad(initialKey, initialKeyId); }
        public override byte[][] PinPadNext(object pad, int[] usages, int type)
        {
            DukptKeyUsage[] u = new DukptKeyUsage[usages.Length];
            for (int i = 0; i < u.Length; i++) u[i] = (DukptKeyUsage)usages[i];
            DukptUse[] uses = ((DukptPinPad)pad).NextTogether(u, (DukptKeyType)type);
            System.Collections.Generic.List<byte[]> r = new System.Collections.Generic.List<byte[]>();
            foreach (DukptUse x in uses) { r.Add(x.Ksn); r.Add(x.Key); }
            return r.ToArray();
        }
        public override byte[][] PinPadHeld(object pad) { return ((DukptPinPad)pad).HeldKeys(); }

        public override byte[] PinEncrypt4(byte[] pinKey, string pin, string pan, byte[] random8) { return PinBlock.EncryptFormat4(pinKey, pin, pan, random8); }
        public override bool PinTryDecrypt4(byte[] pinKey, byte[] block, string pan, out string pin) { return PinBlock.TryDecryptFormat4(pinKey, block, pan, out pin); }
        public override byte[] PinClearField4(string pin, byte[] random8) { return PinBlock.ClearFieldFormat4(pin, random8); }
        public override bool PinTryOpenField4(byte[] pinKey, byte[] block, string pan, out byte[] field) { return PinBlock.TryOpenFieldFormat4(pinKey, block, pan, out field); }
    }

    /// <summary>Reads the product for the seams of later slices. The selftest group has its own copy that finds none.</summary>
    public static class AoSeams
    {
        /// <summary>An internal AesKey constructor that takes the key and more (PRD 7.1 rule 13), or null.</summary>
        public static System.Reflection.ConstructorInfo PortableSeam()
        {
            foreach (System.Reflection.ConstructorInfo k in typeof(AesKey).GetConstructors(System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance))
            {
                System.Reflection.ParameterInfo[] p = k.GetParameters();
                if (p.Length >= 2 && p[0].ParameterType == typeof(byte[])) return k;
            }
            return null;
        }

        /// <summary>
        /// GcmKey.Seal(nonce, aad, plain) on one GcmKey built from k with ctor(AesKey) (PRD 7.3 item 2), as a closed delegate, or null when
        /// no public GcmKey exists. A GcmKey without that constructor or that Seal is NOT RUN SIGNATURE_NOT_CONFIRMED.
        /// </summary>
        public static Func<byte[], byte[], byte[], byte[]> GcmKeySeal(AesKey k)
        {
            Type t = PublicType("GcmKey");
            if (t == null) return null;
            System.Reflection.MethodInfo m = t.GetMethod("Seal", new[] { typeof(byte[]), typeof(byte[]), typeof(byte[]) });
            System.Reflection.ConstructorInfo byAes = t.GetConstructor(new[] { typeof(AesKey) });
            if (m == null || m.ReturnType != typeof(byte[]) || byAes == null)
                throw new Acceptance.NotRunException("SIGNATURE_NOT_CONFIRMED", "GcmKey exists but lacks ctor(AesKey) and byte[] Seal(byte[] nonce, byte[] aad, byte[] plain) (PRD 7.3 item 2)");
            object key = byAes.Invoke(new object[] { k });
            return (Func<byte[], byte[], byte[], byte[]>)Delegate.CreateDelegate(typeof(Func<byte[], byte[], byte[], byte[]>), key, m);
        }

        public static bool HasType(string name) { return PublicType(name) != null; }

        public static Type PublicType(string name)
        {
            foreach (Type t in typeof(AesKey).Assembly.GetTypes()) if (t.Name == name && t.IsPublic) return t;
            return null;
        }

        // ---- caller-buffer forms of PRD 7.3 item 15, bound once as closed delegates (a reflection call allocates its own argument array) ----

        /// <summary>
        /// The method of that name and parameter list as a delegate of type T, or null when no such overload exists. An overload with those
        /// parameters and another return type is NOT RUN SIGNATURE_NOT_CONFIRMED.
        /// </summary>
        static T Bind<T>(Type owner, object target, string name, Type[] ps) where T : class
        {
            if (owner == null) return null;
            System.Reflection.MethodInfo m = owner.GetMethod(name, ps);
            if (m == null) return null;
            try { return (T)(object)(target == null ? Delegate.CreateDelegate(typeof(T), m) : Delegate.CreateDelegate(typeof(T), target, m)); }
            catch (ArgumentException) { throw new Acceptance.NotRunException("SIGNATURE_NOT_CONFIRMED", owner.Name + "." + name + " exists with the parameters of PRD 7.3 item 15 and returns " + m.ReturnType.Name); }
        }

        static T Need<T>(T d, string what) where T : class
        {
            if (d == null) throw new Acceptance.NotRunException("PRODUCT_MISSING", what + " does not exist yet (PRD 7.3 item 15, slice S1)");
            return d;
        }

        static readonly Type B = typeof(byte[]), I = typeof(int), K = typeof(AesKey);

        public static Action<AesKey, byte[], int, int, byte[], int> TryEcbInto(bool encrypt)
        { return Bind<Action<AesKey, byte[], int, int, byte[], int>>(typeof(Modes), null, encrypt ? "EcbEncrypt" : "EcbDecrypt", new[] { K, B, I, I, B, I }); }
        public static Action<AesKey, byte[], int, byte[], int, int, byte[], int> TryCbcInto(bool encrypt)
        { return Bind<Action<AesKey, byte[], int, byte[], int, int, byte[], int>>(typeof(Modes), null, encrypt ? "CbcEncrypt" : "CbcDecrypt", new[] { K, B, I, B, I, I, B, I }); }
        public static Action<AesKey, byte[], int, byte[], int, int, byte[], int> TryCtrInto()
        { return Bind<Action<AesKey, byte[], int, byte[], int, int, byte[], int>>(typeof(Modes), null, "Ctr", new[] { K, B, I, B, I, I, B, I }); }
        public static Action<AesKey, byte[], int, int, byte[], int> TryCmacInto()
        { return Bind<Action<AesKey, byte[], int, int, byte[], int>>(typeof(Cmac), null, "Compute", new[] { K, B, I, I, B, I }); }

        static object NewKeyObject(string typeName, AesKey k)
        {
            Type t = PublicType(typeName);
            if (t == null) return null;
            System.Reflection.ConstructorInfo ctor = t.GetConstructor(new[] { K });
            if (ctor == null) throw new Acceptance.NotRunException("SIGNATURE_NOT_CONFIRMED", typeName + " exists but has no constructor (AesKey) (PRD 7.3 item 15)");
            return ctor.Invoke(new object[] { k });
        }

        public static Action<byte[], int, int, byte[], int> TryCmacKeyCompute(AesKey k)
        {
            object ck = NewKeyObject("CmacKey", k);
            return ck == null ? null : Bind<Action<byte[], int, int, byte[], int>>(ck.GetType(), ck, "Compute", new[] { B, I, I, B, I });
        }

        static readonly Type[] GcmInto = { B, I, B, I, I, B, I, I, B, I };

        public static Action<byte[], int, byte[], int, int, byte[], int, int, byte[], int> TryGcmKeySealInto(AesKey k)
        {
            object gk = NewKeyObject("GcmKey", k);
            return gk == null ? null : Bind<Action<byte[], int, byte[], int, int, byte[], int, int, byte[], int>>(gk.GetType(), gk, "Seal", GcmInto);
        }

        public static Func<byte[], int, byte[], int, int, byte[], int, int, byte[], int, bool> TryGcmKeyOpenInto(AesKey k)
        {
            object gk = NewKeyObject("GcmKey", k);
            return gk == null ? null : Bind<Func<byte[], int, byte[], int, int, byte[], int, int, byte[], int, bool>>(gk.GetType(), gk, "TryOpen", GcmInto);
        }

        public static Action<AesKey, byte[], int, int, byte[], int> EcbInto(bool encrypt) { return Need(TryEcbInto(encrypt), encrypt ? "Modes.EcbEncrypt into" : "Modes.EcbDecrypt into"); }
        public static Action<AesKey, byte[], int, byte[], int, int, byte[], int> CbcInto(bool encrypt) { return Need(TryCbcInto(encrypt), encrypt ? "Modes.CbcEncrypt into" : "Modes.CbcDecrypt into"); }
        public static Action<AesKey, byte[], int, byte[], int, int, byte[], int> CtrInto() { return Need(TryCtrInto(), "Modes.Ctr into"); }
        public static Action<AesKey, byte[], int, int, byte[], int> CmacInto() { return Need(TryCmacInto(), "Cmac.Compute into"); }
        public static Action<byte[], int, int, byte[], int> CmacKeyCompute(AesKey k) { return Need(TryCmacKeyCompute(k), "CmacKey"); }
        public static Action<byte[], int, byte[], int, int, byte[], int, int, byte[], int> GcmKeySealInto(AesKey k) { return Need(TryGcmKeySealInto(k), "GcmKey.Seal into"); }
        public static Func<byte[], int, byte[], int, int, byte[], int, int, byte[], int, bool> GcmKeyOpenInto(AesKey k) { return Need(TryGcmKeyOpenInto(k), "GcmKey.TryOpen into"); }

        // ---- streamed forms and caller-buffer Verify forms of PRD 7.3 item 15 ----

        /// <summary>One new state object (CbcChain or CtrCounter), with its Init and Clear and the Modes overload that takes it, closed over the key.</summary>
        public sealed class StreamSeam
        {
            public Action<byte[], int> Init;
            public Action Clear;
            public Action<byte[], int, int, byte[], int> Call;
        }

        /// <summary>
        /// Null when the state type or the overload Modes.method(AesKey, state, byte[], int, int, byte[], int) does not exist. A state type
        /// with no public parameterless constructor, no void Init(byte[], int), no void Clear(), or an overload that returns a value, is
        /// NOT RUN SIGNATURE_NOT_CONFIRMED.
        /// </summary>
        public static StreamSeam TryStream(AesKey k, string stateType, string method)
        {
            Type t = PublicType(stateType);
            if (t == null) return null;
            System.Reflection.MethodInfo m = typeof(Modes).GetMethod(method, new[] { K, t, B, I, I, B, I });
            if (m == null) return null;
            System.Reflection.ConstructorInfo ctor = t.GetConstructor(Type.EmptyTypes);
            StreamSeam s = new StreamSeam();
            object state = ctor == null ? null : ctor.Invoke(null);
            if (state != null)
            {
                s.Init = Bind<Action<byte[], int>>(t, state, "Init", new[] { B, I });
                s.Clear = Bind<Action>(t, state, "Clear", Type.EmptyTypes);
            }
            if (s.Init == null || s.Clear == null || m.ReturnType != typeof(void))
                throw new Acceptance.NotRunException("SIGNATURE_NOT_CONFIRMED", stateType + " and Modes." + method + " exist but lack a public constructor (), void Init(byte[], int), void Clear(), or the void overload (PRD 7.3 item 15)");
            System.Reflection.MethodInfo close = typeof(AoSeams).GetMethod("CloseStream", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            s.Call = (Action<byte[], int, int, byte[], int>)close.MakeGenericMethod(t).Invoke(null, new object[] { m, k, state });
            return s;
        }

        /// <summary>A typed open delegate on the overload, wrapped so that a call allocates nothing (a reflection call allocates its argument array).</summary>
        static Action<byte[], int, int, byte[], int> CloseStream<TState>(System.Reflection.MethodInfo m, AesKey k, TState state)
        {
            Action<AesKey, TState, byte[], int, int, byte[], int> d =
                (Action<AesKey, TState, byte[], int, int, byte[], int>)Delegate.CreateDelegate(typeof(Action<AesKey, TState, byte[], int, int, byte[], int>), m);
            return delegate (byte[] i, int io, int n, byte[] o, int oo) { d(k, state, i, io, n, o, oo); };
        }

        /// <summary>The same overload, closed over the key and a null state object, or null when the state type or the overload does not exist.</summary>
        public static Action<byte[], int, int, byte[], int> TryStreamNullState(AesKey k, string stateType, string method)
        {
            Type t = PublicType(stateType);
            if (t == null) return null;
            System.Reflection.MethodInfo m = typeof(Modes).GetMethod(method, new[] { K, t, B, I, I, B, I });
            if (m == null) return null;
            if (m.ReturnType != typeof(void))
                throw new Acceptance.NotRunException("SIGNATURE_NOT_CONFIRMED", "Modes." + method + " with a " + stateType + " returns a value (PRD 7.3 item 15)");
            System.Reflection.MethodInfo close = typeof(AoSeams).GetMethod("CloseStream", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static);
            return (Action<byte[], int, int, byte[], int>)close.MakeGenericMethod(t).Invoke(null, new object[] { m, k, null });
        }

        public static Action<byte[], int, int, byte[], int> StreamNullState(AesKey k, string stateType, string method)
        { return Need(TryStreamNullState(k, stateType, method), "Modes." + method + " with a " + stateType); }

        public static Func<AesKey, byte[], int, int, byte[], int, bool> TryCmacVerifyInto()
        { return Bind<Func<AesKey, byte[], int, int, byte[], int, bool>>(typeof(Cmac), null, "Verify", new[] { K, B, I, I, B, I }); }

        public static Func<byte[], int, int, byte[], int, bool> TryCmacKeyVerify(AesKey k)
        {
            object ck = NewKeyObject("CmacKey", k);
            return ck == null ? null : Bind<Func<byte[], int, int, byte[], int, bool>>(ck.GetType(), ck, "Verify", new[] { B, I, I, B, I });
        }

        public static StreamSeam Stream(AesKey k, string stateType, string method) { return Need(TryStream(k, stateType, method), "Modes." + method + " with a " + stateType); }
        public static Func<AesKey, byte[], int, int, byte[], int, bool> CmacVerifyInto() { return Need(TryCmacVerifyInto(), "Cmac.Verify with offsets"); }
        public static Func<byte[], int, int, byte[], int, bool> CmacKeyVerify(AesKey k) { return Need(TryCmacKeyVerify(k), "CmacKey.Verify"); }
    }

    /// <summary>The side under test. The selftest group has its own copy of this class that returns a planted fault.</summary>
    public static class AoSubject
    {
        public static AoSide Make(Ctx c)
        {
            c.RequireProduct();
            ProductSide p = new ProductSide();
            // Load the product here, outside the case loop: a missing DLL then ends the clause by name, never as a million differences.
            p.NewAes(new byte[16]);
            return p;
        }
    }
}
