namespace Acceptance
{
    /// <summary>The worker rows look in the product. The selftest group has its own AoWorkerSource that points at stand-ins.</summary>
    public static class AoWorkerSource
    {
        public static AoWorkerEnv Get(Ctx c)
        {
            AoSubject.Make(c);
            AoWorkerEnv e = new AoWorkerEnv();
            e.Asm = typeof(NetSec.Crypto.AesKey).Assembly;
            e.Ns = null;
            e.AesKeyType = typeof(NetSec.Crypto.AesKey);
            e.NewAesKey = delegate (byte[] k) { return new NetSec.Crypto.AesKey(k); };
            return e;
        }
    }
}
