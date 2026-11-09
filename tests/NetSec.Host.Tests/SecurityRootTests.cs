#nullable enable
using System;
using System.IO;
using NetSec.Host.Security;
using Xunit;

namespace NetSec.Host.Tests;

/// <summary>Where the security folder goes. A shipped app has no .git above it, so that branch runs on a learner's machine and in no e2e run.</summary>
public sealed class SecurityRootTests : IDisposable
{
    readonly string _top = NoGitTop();

    static string? NoEnv(string name) => null;

    /// <summary>
    /// A fresh folder with no .git above it. The machine temp folder comes first; when TMP sits inside a git checkout (a worktree's
    /// own scratch folder, say) the next candidates are the user's local temp folder and the temp folder's drive root.
    /// </summary>
    static string NoGitTop()
    {
        string temp = Path.GetTempPath();
        string[] candidates =
        [
            temp,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Temp"),
            Path.GetPathRoot(Path.GetFullPath(temp))!,
        ];
        foreach (string root in candidates)
        {
            if (!Directory.Exists(root) || GitAbove(root)) continue;
            string top = Path.Combine(root, "ns-root-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(top);
            return top;
        }
        throw new InvalidOperationException("ROOT_TEST_NO_GIT_FREE_TEMP: every candidate temp folder has a .git above it: " + string.Join(", ", candidates));
    }

    static bool GitAbove(string dir)
    {
        for (DirectoryInfo? at = new(dir); at is not null; at = at.Parent)
            if (Directory.Exists(Path.Combine(at.FullName, ".git")) || File.Exists(Path.Combine(at.FullName, ".git"))) return true;
        return false;
    }

    string Nested()
    {
        string dir = Path.Combine(_top, "a", "b");
        Directory.CreateDirectory(dir);
        return dir;
    }

    [Fact]
    public void With_no_git_above_it_the_folder_sits_beside_the_app()
    {
        string dir = Nested();
        Assert.False(GitAbove(dir), "the test needs a temp folder with no .git above it");
        Assert.Equal(Path.Combine(dir, ".security"), SecurityStore.ResolveRoot(NoEnv, dir));
    }

    [Fact]
    public void A_git_folder_above_it_puts_the_folder_at_the_repo_top()
    {
        string dir = Nested();
        Directory.CreateDirectory(Path.Combine(_top, ".git"));
        Assert.Equal(Path.Combine(_top, ".security"), SecurityStore.ResolveRoot(NoEnv, dir));
    }

    /// <summary>A linked worktree holds .git as a file.</summary>
    [Fact]
    public void A_git_file_above_it_puts_the_folder_at_the_repo_top()
    {
        string dir = Nested();
        File.WriteAllText(Path.Combine(_top, ".git"), "gitdir: elsewhere");
        Assert.Equal(Path.Combine(_top, ".security"), SecurityStore.ResolveRoot(NoEnv, dir));
    }

    [Fact]
    public void The_environment_setting_wins_over_a_git_folder()
    {
        string dir = Nested();
        Directory.CreateDirectory(Path.Combine(_top, ".git"));
        Assert.Equal("Z:/set", SecurityStore.ResolveRoot(n => n == "NETSEC_SECURITY_DIR" ? "Z:/set" : null, dir));
    }

    [Fact]
    public void An_empty_environment_setting_counts_as_unset()
    {
        string dir = Nested();
        Directory.CreateDirectory(Path.Combine(_top, ".git"));
        Assert.Equal(Path.Combine(_top, ".security"), SecurityStore.ResolveRoot(n => "", dir));
    }

    public void Dispose() => Directory.Delete(_top, true);
}
