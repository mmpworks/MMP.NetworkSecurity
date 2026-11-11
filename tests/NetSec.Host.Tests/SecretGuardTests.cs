#nullable enable
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Text;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>tools/secret_guard.py on real temp repositories. The words of a PEM header are joined at run time, so this file holds no block for the guard to find.</summary>
public class SecretGuardTests
{
    static readonly string Marker = "PRIV" + "ATE KEY";
    static readonly string Body = Convert.ToBase64String(new byte[48]);

    static string Block(string kind = "") => $"-----BEGIN {kind}{Marker}-----\n{Body}\n-----END {kind}{Marker}-----\n";

    sealed class Repo : IDisposable
    {
        public readonly string Dir = Path.Combine(Path.GetTempPath(), "netsec-guard-" + Guid.NewGuid().ToString("N"));

        Repo() { }

        /// <summary>A fresh repository with one commit-ready .gitignore. Each git run is async (ProcessWaits).</summary>
        public static async Task<Repo> CreateAsync()
        {
            Repo repo = new();
            Directory.CreateDirectory(repo.Dir);
            await repo.Git("init -q");
            File.WriteAllText(Path.Combine(repo.Dir, ".gitignore"), ".security/\n");
            await repo.Git("add .gitignore");
            return repo;
        }

        public async Task Git(string args)
        {
            (int code, string output) = await Run("git", args);
            Assert.True(code == 0, "git " + args + ": " + output);
        }

        public async Task Stage(string name, byte[] bytes)
        {
            File.WriteAllBytes(Path.Combine(Dir, name), bytes);
            await Git("add -- \"" + name + "\"");
        }

        public Task<(int Code, string Output)> Guard() => Run("python", "-I \"" + GuardPath() + "\"");

        async Task<(int, string)> Run(string exe, string args)
        {
            ProcessStartInfo info = new(exe, args) { WorkingDirectory = Dir, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true, StandardOutputEncoding = Encoding.UTF8 };
            info.Environment["PYTHONUTF8"] = "1";
            using Process p = Process.Start(info)!;
            (bool exited, int code, string output, string errors) = await ProcessWaits.Collect(p, TimeSpan.FromSeconds(60));
            Assert.True(exited, exe + " did not finish in 60 s");
            return (code, output + errors);
        }

        public void Dispose()
        {
            foreach (string f in Directory.GetFiles(Dir, "*", SearchOption.AllDirectories)) File.SetAttributes(f, FileAttributes.Normal);
            TempTree.Delete(Dir);
        }
    }

    static string GuardPath()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "tools", "secret_guard.py");
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("tools/secret_guard.py");
    }

    static async Task AssertCaught(Repo repo, string name)
    {
        (int code, string output) = await repo.Guard();
        Assert.True(code == 1, "the guard passed " + name + ", exit " + code + ": " + output);
        Assert.Contains(name, output);
    }

    [Fact]
    public async Task A_clean_repository_passes_and_prose_that_names_the_header_is_no_key()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("doc.md", Encoding.UTF8.GetBytes("A key file starts with -----BEGIN " + Marker + "-----, and that is all this sentence says.\n"));
        await repo.Stage("public.txt", Encoding.UTF8.GetBytes("-----BEGIN PUBLIC KEY-----\n" + Body + "\n-----END PUBLIC KEY-----\n"));
        (int code, string output) = await repo.Guard();
        Assert.True(code == 0, output);
    }

    [Fact]
    public async Task A_plain_block_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("plain.txt", Encoding.UTF8.GetBytes(Block()));
        await AssertCaught(repo, "plain.txt");
    }

    [Fact]
    public async Task A_staged_key_with_a_clean_working_copy_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("staged.txt", Encoding.UTF8.GetBytes(Block()));
        File.WriteAllText(Path.Combine(repo.Dir, "staged.txt"), "nothing here now\n");
        await AssertCaught(repo, "staged.txt");
    }

    [Fact]
    public async Task An_encrypted_traditional_key_with_headers_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        string text = $"-----BEGIN RSA {Marker}-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n{Body}\n-----END RSA {Marker}-----\n";
        await repo.Stage("enc-trad.txt", Encoding.UTF8.GetBytes(text));
        await AssertCaught(repo, "enc-trad.txt");
    }

    [Fact]
    public async Task A_key_in_a_file_with_a_non_ascii_name_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Git("config core.quotepath true");
        await repo.Stage("café.txt", Encoding.UTF8.GetBytes(Block()));
        await AssertCaught(repo, "café.txt");
    }

    [Fact]
    public async Task A_key_in_an_escaped_string_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("in-string.cs", Encoding.UTF8.GetBytes("const string K = \"" + Block().Replace("\n", "\\n") + "\";\n"));
        await AssertCaught(repo, "in-string.cs");
    }

    [Fact]
    public async Task A_key_after_a_header_named_in_prose_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("prose-then-key.md", Encoding.UTF8.GetBytes("A key starts with -----BEGIN " + Marker + "-----, as below.\n\n" + Block()));
        await AssertCaught(repo, "prose-then-key.md");
    }

    [Fact]
    public async Task A_key_after_a_placeholder_block_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("placeholder-then-key.txt", Encoding.UTF8.GetBytes($"-----BEGIN {Marker}-----\n...\n-----END {Marker}-----\n" + Block()));
        await AssertCaught(repo, "placeholder-then-key.txt");
    }

    [Fact]
    public async Task A_key_in_a_file_over_eight_mebibytes_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("big.txt", Encoding.UTF8.GetBytes(new string('x', 9 * 1024 * 1024) + "\n" + Block()));
        await AssertCaught(repo, "big.txt");
    }

    [Fact]
    public async Task A_utf16_key_file_is_caught()
    {
        using Repo repo = await Repo.CreateAsync();
        await repo.Stage("utf16.txt", Encoding.Unicode.GetPreamble().Concat(Encoding.Unicode.GetBytes(Block())).ToArray());
        await AssertCaught(repo, "utf16.txt");
    }

    [Fact]
    public async Task A_staged_file_in_the_security_folder_is_caught_and_a_golden_trace_is_not()
    {
        using Repo repo = await Repo.CreateAsync();
        Directory.CreateDirectory(Path.Combine(repo.Dir, "acceptance", "golden"));
        await repo.Stage("acceptance/golden/lab-00.ndjson", Encoding.UTF8.GetBytes("{}\n"));
        (int code, string output) = await repo.Guard();
        Assert.True(code == 0, output);
        Directory.CreateDirectory(Path.Combine(repo.Dir, ".security"));
        File.WriteAllText(Path.Combine(repo.Dir, ".security", "modes.json"), "{}");
        await repo.Git("add -f .security/modes.json");
        await AssertCaught(repo, ".security/modes.json");
    }
}
