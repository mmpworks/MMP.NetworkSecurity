namespace NetSec.Host;

/// <summary>
/// Orders trace lines against every other frame (Jared, review of PR #136). A trace line reads the Show keys toggle and goes out
/// under the read side. Every other frame, the flip frame too, goes out under the write side. So a flip frame lands ahead of
/// or behind a whole line, never between the line's read of the toggle and its send. A line picked while ON reaches each
/// socket before the flip to OFF, and the UI's reload from /events then replaces it.
/// </summary>
public sealed class ShowKeysFence(Func<bool> showKeys)
{
    readonly ReaderWriterLockSlim _order = new(LockRecursionPolicy.NoRecursion);

    /// <summary>The toggle now, with no ordering. For a read of stored lines, such as /events.</summary>
    public bool ShowKeys => showKeys();

    /// <summary>Reads the toggle and runs send with it, and no frame under Announce can start in between.</summary>
    public void Pick(Action<bool> send)
    {
        _order.EnterReadLock();
        try { send(showKeys()); }
        finally { _order.ExitReadLock(); }
    }

    /// <summary>Runs send when no Pick is in flight.</summary>
    public void Announce(Action send)
    {
        _order.EnterWriteLock();
        try { send(); }
        finally { _order.ExitWriteLock(); }
    }
}
