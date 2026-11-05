using System;

namespace Acceptance
{
    public static class TraceChecks
    {
        /// <summary>
        /// Every trace line carries a hop label (hop1 for CE to gateway, hop2 for gateway to server). Returns null when the labels are as required,
        /// else a sentence that names what is missing. requireHop2 is false for a topology whose hop 2 has no traced end (a Go gateway and a Go TLS
        /// server write no trace file). Hop 2's bytes are still proved from the tap log in that topology, so this check does not weaken that proof.
        /// </summary>
        public static string HopLabelProblem(TraceLine[] trace, bool requireHop2)
        {
            bool hop1 = false, hop2 = false;
            foreach (TraceLine t in trace)
            {
                if (t.Hop == "hop1") hop1 = true;
                if (t.Hop == "hop2") hop2 = true;
            }
            if (hop1 && (hop2 || !requireHop2)) return null;
            return "the trace does not label both hops (hop1 seen: " + hop1 + ", hop2 seen: " + hop2 + (requireHop2 ? "" : "; hop 2 is not required in this topology") + ")";
        }
    }
}
