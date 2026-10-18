using System;
using System.Threading;

namespace IrisKit
{
    /// <summary>Purge du journal JSONL à chaque minuit UTC (spec §5.5), en plus de la purge au démarrage ; revue phase 1, mineur 7.</summary>
    public sealed class PurgeScheduler : IDisposable
    {
        private readonly JsonlEventStore store;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private Timer timer;
        private bool disposed;

        public DateTime NextRunUtc { get; private set; }

        public PurgeScheduler(JsonlEventStore store, Func<DateTime> clock)
        {
            if (store == null) throw new ArgumentNullException("store");
            this.store = store;
            this.clock = clock;
            Schedule();
        }

        public static DateTime NextMidnight(DateTime utcNow)
        {
            return DateTime.SpecifyKind(utcNow.Date.AddDays(1).AddSeconds(1), DateTimeKind.Utc);
        }

        private void Schedule()
        {
            DateTime now = clock().ToUniversalTime();
            NextRunUtc = NextMidnight(now);
            TimeSpan due = NextRunUtc - now;
            if (due < TimeSpan.FromSeconds(1)) due = TimeSpan.FromSeconds(1);
            timer = new Timer(delegate { RunNow(); }, null, due, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Purge immédiate puis replanification ; rend le nombre de fichiers supprimés.</summary>
        public int RunNow()
        {
            lock (gate)
            {
                if (disposed) return 0;
                int removed = 0;
                try
                {
                    removed = store.Purge();
                    if (removed > 0) Log.Info("events", removed + " fichier(s) de journal purgé(s)");
                }
                catch (Exception ex) { Log.Warn("events", "purge du journal impossible : " + ex.Message); }
                timer.Dispose();
                Schedule();
                return removed;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                disposed = true;
                if (timer != null) timer.Dispose();
            }
        }
    }
}
