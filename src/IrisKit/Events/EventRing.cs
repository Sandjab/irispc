using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Anneau borné d'events (SPECS §19.3) + totaux cumulés par kind (jamais remis à zéro). Thread-safe.</summary>
    public sealed class EventRing
    {
        private readonly object gate = new object();
        private readonly Queue<Event> entries;
        private readonly long[] totals = new long[8];

        public int Capacity { get; private set; }

        public EventRing(int capacity)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException("capacity", "la capacité du ring doit être positive");
            Capacity = capacity;
            entries = new Queue<Event>(capacity);
        }

        public void Append(Event e)
        {
            lock (gate)
            {
                if (entries.Count >= Capacity) entries.Dequeue();
                entries.Enqueue(e);
                totals[(int)e.Kind]++;
            }
        }

        public IList<Event> All
        {
            get { lock (gate) { return new List<Event>(entries); } }
        }

        public IList<Event> Recent(int n)
        {
            lock (gate)
            {
                List<Event> all = new List<Event>(entries);
                if (n <= 0) return new List<Event>();
                if (n >= all.Count) return all;
                return all.GetRange(all.Count - n, n);
            }
        }

        public IList<Event> Since(DateTime at)
        {
            lock (gate)
            {
                List<Event> result = new List<Event>();
                foreach (Event e in entries) if (e.Timestamp >= at) result.Add(e);
                return result;
            }
        }

        public long Count(EventKind kind)
        {
            lock (gate) { return totals[(int)kind]; }
        }

        public int Clear()
        {
            lock (gate)
            {
                int n = entries.Count;
                entries.Clear();
                return n;
            }
        }
    }
}
