using System.Net;
using System.Net.Sockets;

namespace Acceptance
{
    /// <summary>
    /// Proof that the harness waits look one last time after the limit. Each wait gets a limit that has already passed (0 ms) and an
    /// answer that is already there. That is a late wake in a form that repeats on every run. A wait that checks the limit first gives up.
    /// </summary>
    public static class SelfWaits
    {
        [Clause("SELF.waits-look-after-the-limit")]
        public static string WaitsLookAfterTheLimit(Ctx c)
        {
            TcpListener open = new TcpListener(IPAddress.Loopback, 0);
            open.Start();
            try
            {
                int port = ((IPEndPoint)open.LocalEndpoint).Port;
                Check.True(Net.WaitPort(port, 0), "Net.WaitPort with a 0 ms limit should find port " + port + ", which is open");
            }
            finally { open.Stop(); }

            int calls = 0;
            string found = Poll.Until(delegate { calls++; return "READY port=1"; }, 0, 10);
            Check.Equal("Poll.Until with a 0 ms limit and the answer already there", "READY port=1", found);
            Check.True(calls == 1, "Poll.Until should look once and stop, it looked " + calls + " times");
            Check.True(Poll.Until(delegate { return true; }, 0, 10), "Poll.Until (yes or no) with a 0 ms limit should see the yes");
            Check.True(Poll.Until(delegate { return (string)null; }, 50, 10) == null, "Poll.Until should give up with null when the answer never comes");
            return "Net.WaitPort and Poll.Until each see an answer that is there at a limit that has passed, and Poll.Until gives up when none comes";
        }
    }
}
