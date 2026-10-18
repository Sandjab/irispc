using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Filtres de `events.query` (SPECS §13.2, spec phase 3 §5) : since, until, kind, host, puis les `Limit` plus récents.</summary>
    public sealed class EventQuery
    {
        public const int MaxLimit = 10000;

        public DateTime? Since;
        public DateTime? Until;
        public int Limit = MaxLimit;
        public ISet<EventKind> Kinds;
        public string Host;

        public bool Matches(Event e)
        {
            if (Since.HasValue && e.Timestamp < Since.Value) return false;
            if (Until.HasValue && e.Timestamp > Until.Value) return false;
            if (Kinds != null && !Kinds.Contains(e.Kind)) return false;
            if (Host != null && e.Host != Host) return false;
            return true;
        }

        /// <summary>Ring, complété par le journal JSONL quand `since` précède le plus ancien event du ring ; dédoublonné par id, trié, tronqué.</summary>
        public IList<Event> Run(EventRing ring, JsonlEventStore store, DateTime now)
        {
            IList<Event> live = ring.All;
            Dictionary<Guid, Event> byId = new Dictionary<Guid, Event>();
            foreach (Event e in live) if (Matches(e)) byId[e.Id] = e;
            bool needJournal = Since.HasValue && store != null && (live.Count == 0 || Since.Value < live[0].Timestamp);
            if (needJournal)
            {
                DateTime today = now.ToUniversalTime().Date;
                DateTime first = Since.Value.ToUniversalTime().Date;
                DateTime oldestKept = today.AddDays(-store.RetentionDays);
                if (first < oldestKept) first = oldestKept;
                for (DateTime day = first; day <= today; day = day.AddDays(1))
                    foreach (Event e in store.Read(day))
                        if (Matches(e) && !byId.ContainsKey(e.Id)) byId[e.Id] = e;
            }
            List<Event> all = new List<Event>(byId.Values);
            all.Sort(delegate(Event a, Event b) { return a.Timestamp.CompareTo(b.Timestamp); });
            if (all.Count > Limit) all = all.GetRange(all.Count - Limit, Limit);
            return all;
        }
    }
}
