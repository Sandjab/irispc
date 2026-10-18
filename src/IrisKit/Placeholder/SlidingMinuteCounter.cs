using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Compteur sur fenêtre glissante inclusive de 60 s (R5). Non thread-safe : l'appelant verrouille.</summary>
    public sealed class SlidingMinuteCounter
    {
        private readonly List<DateTime> stamps = new List<DateTime>();

        public void Record(DateTime now)
        {
            Prune(now);
            stamps.Add(now);
        }

        public int Count(DateTime now)
        {
            Prune(now);
            return stamps.Count;
        }

        /// <summary>Garde les instants t tels que now-60 s ≤ t ≤ now.</summary>
        private void Prune(DateTime now)
        {
            DateTime cutoff = now.AddSeconds(-60);
            stamps.RemoveAll(delegate(DateTime t) { return t < cutoff; });
        }
    }
}
