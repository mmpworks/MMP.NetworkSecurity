using System;
using System.Collections.Generic;

namespace Acceptance
{
    /// <summary>
    /// A3: AES DUKPT matches the ANSI X9.24-3-2017 published vectors for AES-128 and AES-256 base keys,
    /// the PIN pad and the bank agree for 1,000 sales, and used keys are absent from PIN-pad state.
    /// Vectors: acceptance/vectors/x9-24-3-aes-dukpt.nsv, committed (made by extract_x9.py from the PDF that fetch-x9.ps1 downloads; source hash in
    /// sources.lock.json). SELF.x9-vectors-true-copy compares the committed file with a fresh extraction when the PDF is in vectors/_cache.
    /// The tour statement about the managed heap is checked by checks/a3_tour_statement.py.
    /// </summary>
    public static class DukptClauses
    {
        static readonly string[] UseNames = { "kek", "pin", "mac-gen", "mac-ver", "mac-both", "data-enc", "data-dec", "data-both" };
        static readonly int[] UseCodes = { 0x0002, 0x1000, 0x2000, 0x2001, 0x2002, 0x3000, 0x3001, 0x3002 };

        static int CodeOf(string name) { return UseCodes[Array.IndexOf(UseNames, name)]; }

        static string Family(Ctx c, string group, int keyBytes)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("x9-24-3-aes-dukpt.nsv", group))
            {
                byte[] bdk = r.Bytes("bdk"), ikid = r.Bytes("ikid");
                uint counter = (uint)r.Long("counter");
                t.Compare(r.Where + " initial key", r.Bytes("initial_key"), DSubject.InitialKey(bdk, ikid));
                byte[] dk = DSubject.DerivationKey(bdk, ikid, counter);
                if (dk != null) t.Compare(r.Where + " derivation key", r.Bytes("derivation_key"), dk);
                foreach (string use in new string[] { "pin", "mac-gen", "data-enc" })
                    t.Compare(r.Where + " " + use, r.Bytes(use), DSubject.WorkingKey(bdk, ikid, counter, CodeOf(use), keyBytes));
            }
            return t.Done();
        }

        [Clause("A3.vec.aes128-from-aes128", PerBuild = true)]
        public static string Aes128FromAes128(Ctx c) { return Family(c, "dukpt-aes128-from-aes128", 16); }

        [Clause("A3.vec.aes128-from-aes256", PerBuild = true)]
        public static string Aes128FromAes256(Ctx c) { return Family(c, "dukpt-aes128-from-aes256", 16); }

        [Clause("A3.vec.aes256-from-aes256", PerBuild = true)]
        public static string Aes256FromAes256(Ctx c) { return Family(c, "dukpt-aes256-from-aes256", 32); }

        [Clause("A3.vec.all-usages", PerBuild = true)]
        public static string AllUsages(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-all-usages"))
            {
                byte[] bdk = r.Bytes("bdk"), ikid = r.Bytes("ikid");
                uint counter = (uint)r.Long("counter");
                for (int i = 0; i < UseNames.Length; i++)
                    t.Compare(r.Where + " " + UseNames[i], r.Bytes(UseNames[i]), DSubject.WorkingKey(bdk, ikid, counter, UseCodes[i], 16));
            }
            return t.Done();
        }

        [Clause("A3.pinblock.format4", PerBuild = true)]
        public static string PinBlockFormat4(Ctx c)
        {
            Tally t = new Tally();
            foreach (VectorRecord r in c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-pinblock-format4"))
            {
                byte[] key = r.Bytes("pin_key");
                string pin = r.Str("pin"), pan = r.Str("pan");
                byte[] enc = DSubject.PinBlockEncrypt(key, pin, pan, r.Bytes("random"));
                t.Compare(r.Where + " encrypt", r.Bytes("encrypted"), enc);
                string back = DSubject.PinBlockDecrypt(key, r.Bytes("encrypted"), pan);
                t.Expect(r.Where + " decrypt", back == pin, "decrypt gave '" + back + "' not the PIN");
                // Control pair: the same block under another PAN must not give the PIN back.
                string other = DSubject.PinBlockDecrypt(key, r.Bytes("encrypted"), "4111111111111112");
                t.Expect(r.Where + " wrong PAN", other != pin, "decrypt under a different PAN still returned the PIN");
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- 1,000 sales

        [Clause("A3.sales1000.agree", PerBuild = true)]
        public static string Sales1000(Ctx c)
        {
            Tally t = new Tally();
            VectorRecord v128 = c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-aes128-from-aes128")[0];
            VectorRecord v256 = c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-aes256-from-aes256")[0];
            foreach (VectorRecord v in new VectorRecord[] { v128, v256 })
            {
                byte[] bdk = v.Bytes("bdk"), ikid = v.Bytes("ikid");
                int keyBytes = v == v128 ? 16 : 32;
                string label = v == v128 ? "aes128" : "aes256";
                PadSession pad = DSubject.NewPad(bdk, ikid);
                uint last = 0;
                int[] uses = new int[] { 0x1000, 0x2000, 0x3000 };
                for (int sale = 1; sale <= 1000; sale++)
                {
                    int use = uses[sale % 3];
                    PadUse got = pad.Next(use, keyBytes);
                    string where = label + " sale " + sale + " (counter " + got.Counter + ", use 0x" + use.ToString("X4") + ")";
                    t.Expect(where + " counter", got.Counter > last, "counter " + got.Counter + " did not increase from " + last);
                    last = got.Counter;
                    t.Expect(where + " KSN", got.Ksn != null && got.Ksn.Length == 12 && Hex.Eq(Hex.Slice(got.Ksn, 0, 8), ikid), "the KSN does not start with the initial key id");
                    t.Compare(where + " key", DSubject.WorkingKey(bdk, ikid, got.Counter, use, keyBytes), got.Key);
                    // A PIN block locked on the pad side opens on the bank side with the same PIN.
                    if (use == 0x1000 && sale % 24 == 1)
                    {
                        byte[] rnd = new Rng((ulong)sale).Bytes(8);
                        byte[] block = DSubject.PinBlockEncrypt(got.Key, "1234", "4111111111111111", rnd);
                        string pin = DSubject.PinBlockDecrypt(DSubject.WorkingKey(bdk, ikid, got.Counter, 0x1000, keyBytes), block, "4111111111111111");
                        t.Expect(where + " PIN block", pin == "1234", "bank side got '" + pin + "'");
                    }
                }
            }
            return t.Done();
        }

        // ---------------------------------------------------------------- erasure

        /// <summary>True when needle appears anywhere inside any register.</summary>
        static bool Holds(byte[][] registers, byte[] needle)
        {
            foreach (byte[] reg in registers)
            {
                if (reg == null || reg.Length < needle.Length) continue;
                for (int i = 0; i + needle.Length <= reg.Length; i++)
                {
                    int j = 0;
                    while (j < needle.Length && reg[i + j] == needle[j]) j++;
                    if (j == needle.Length) return true;
                }
            }
            return false;
        }

        [Clause("A3.erasure.used-keys-absent", PerBuild = true)]
        public static string ErasureUsedKeysAbsent(Ctx c)
        {
            VectorRecord v = c.Vectors("x9-24-3-aes-dukpt.nsv", "dukpt-aes128-from-aes128")[0];
            byte[] bdk = v.Bytes("bdk"), ikid = v.Bytes("ikid");
            byte[] initial = DSubject.InitialKey(bdk, ikid);
            PadSession pad = DSubject.NewPad(bdk, ikid);
            Tally t = new Tally();
            // The initial key is erased once the pad has loaded it.
            t.Expect("initial key after load", !Holds(pad.State(), initial), "the pad still holds the initial key");
            List<KeyValuePair<uint, byte[]>> used = new List<KeyValuePair<uint, byte[]>>();
            int[] uses = new int[] { 0x1000, 0x2000, 0x3000 };
            for (int sale = 1; sale <= 200; sale++)
            {
                PadUse got = pad.Next(uses[sale % 3], 16);
                // Control: the key just issued may still be held. If the pad holds nothing at all, the check below proves nothing.
                t.Expect("sale " + got.Counter + " control: the pad reports its registers", pad.State().Length > 0, "HeldKeys returned no registers, so the absence checks prove nothing");
                used.Add(new KeyValuePair<uint, byte[]>(got.Counter, got.Key));
                foreach (KeyValuePair<uint, byte[]> old in used)
                    if (old.Key < got.Counter)
                        t.Expect("sale " + got.Counter + " vs key of sale " + old.Key, !Holds(pad.State(), old.Value), "state still holds a working key used in sale " + old.Key);
                t.Expect("sale " + got.Counter + " initial key", !Holds(pad.State(), initial), "the pad holds the initial key again");
            }
            return t.Done();
        }
    }
}
