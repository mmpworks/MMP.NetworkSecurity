namespace NetSec.Bench;

/// <summary>The facts of one bench process that every report names. Its own file, so the CLR 2.0 hosts can link it.</summary>
sealed class Run
{
    public string Build, Head, Priority, CfLine;
}
