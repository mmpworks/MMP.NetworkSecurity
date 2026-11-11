using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace NetSec.Bench.Files;

/// <summary>One AO-9 test file, read once, plus a PKCS#7-padded copy for CBC (CBC in NetSec.Core takes whole blocks only).</summary>
sealed class TestFile
{
    public TestFile(string name, byte[] bytes)
    {
        Name = name;
        Bytes = bytes;
        int pad = 16 - bytes.Length % 16;
        Padded = new byte[bytes.Length + pad];
        Buffer.BlockCopy(bytes, 0, Padded, 0, bytes.Length);
        for (int i = bytes.Length; i < Padded.Length; i++) Padded[i] = (byte)pad;
    }

    public string Name { get; }
    public byte[] Bytes { get; }
    public byte[] Padded { get; }
}

/// <summary>
/// Reads bench/files/files.tsv (name, bytes, sha256) and each file it names. A file whose size or SHA-256 differs from the list stops the
/// run (AO-9 rule 1). The check uses the runtime's own SHA-256, so it shares no code with the NetSec.Core code under test.
/// </summary>
static class FileSet
{
    public static List<TestFile> Load(string folder)
    {
        string[] lines = File.ReadAllLines(Path.Combine(folder, "files.tsv"));
        if (lines.Length < 2 || lines[0] != "name\tbytes\tsha256") throw new InvalidDataException("BENCH_FILES_LIST: files.tsv has no header row");
        return lines.Skip(1).Where(l => l.Length > 0).Select(l => Check(folder, l.Split('\t'))).ToList();
    }

    static TestFile Check(string folder, string[] row)
    {
        string name = row[0];
        byte[] bytes = File.ReadAllBytes(Path.Combine(folder, name));
        string sha = Hex(SHA256.Create().ComputeHash(bytes));
        if (bytes.Length.ToString() != row[1] || sha != row[2])
            throw new InvalidDataException("BENCH_FILE_CHANGED: " + name + " is " + bytes.Length + " bytes, sha256 " + sha + "; files.tsv says " + row[1] + ", " + row[2]);
        return new TestFile(name, bytes);
    }

    public static string Hex(byte[] b) => BitConverter.ToString(b).Replace("-", "").ToLowerInvariant();
}
