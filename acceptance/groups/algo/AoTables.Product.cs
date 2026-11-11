using System.Reflection;

namespace Acceptance
{
    /// <summary>AO-3 against the product. Scopes: AES types (name starts Aes, walk and trace types left out) and GHASH types.</summary>
    public static class AoTablesProduct
    {
        static Assembly Product(Ctx c) { AoSubject.Make(c); return typeof(NetSec.Crypto.AesKey).Assembly; }

        [Clause("AO-3.aes.tables-equal-math", PerBuild = true)]
        public static string AesEqual(Ctx c) { return AoTables.EqualsMath(AoTables.TypesIn(Product(c), "NetSec.Crypto", AoTables.AesScope), AoTables.AesMath()); }

        [Clause("AO-3.aes.no-startup-build", PerBuild = true)]
        public static string AesStartup(Ctx c) { return AoTables.NoStartupBuild(AoTables.TypesIn(Product(c), "NetSec.Crypto", AoTables.AesScope)); }

        [Clause("AO-3.ghash.tables-equal-math", PerBuild = true)]
        public static string GhashEqual(Ctx c) { return AoTables.EqualsMath(AoTables.TypesIn(Product(c), "NetSec.Crypto", AoTables.GhashScope), AoTables.GhashMath()); }

        [Clause("AO-3.ghash.no-startup-build", PerBuild = true)]
        public static string GhashStartup(Ctx c) { return AoTables.NoStartupBuild(AoTables.TypesIn(Product(c), "NetSec.Crypto", AoTables.GhashScope)); }
    }
}
