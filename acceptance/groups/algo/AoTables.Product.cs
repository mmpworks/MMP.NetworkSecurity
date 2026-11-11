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

        // PRD 4.3: the hash tables (S3) and the DES tables (S4) get their math with their slice. Until then each row reads NOT RUN.
        [Clause("AO-3.hash.tables-equal-math", PerBuild = true)]
        public static string HashEqual(Ctx c) { Product(c); throw new NotRunException("PRODUCT_MISSING", "the S3 hash tables are not built; their math (FIPS 180-4 roots of primes, RFC 1321 sines, FIPS 202 LFSR) lands with S3"); }

        [Clause("AO-3.des.tables-equal-math", PerBuild = true)]
        public static string DesEqual(Ctx c) { Product(c); throw new NotRunException("PRODUCT_MISSING", "the S4 combined DES tables are not built; their check against FIPS 46-3 S-boxes and P lands with S4"); }

        [Clause("AO-3.ghash.no-startup-build", PerBuild = true)]
        public static string GhashStartup(Ctx c) { return AoTables.NoStartupBuild(AoTables.TypesIn(Product(c), "NetSec.Crypto", AoTables.GhashScope)); }
    }
}
