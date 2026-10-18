using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Filtres du flux SSE (SPECS §14.3) : since (backlog), kind (liste), host (égalité stricte). Paramètre invalide → FormatException (400).</summary>
    public sealed class SseFilters
    {
        public DateTime? Since { get; private set; }
        public ISet<EventKind> Kinds { get; private set; }
        public string Host { get; private set; }

        public static SseFilters Parse(string target)
        {
            SseFilters f = new SseFilters();
            int q = target.IndexOf('?');
            if (q < 0) return f;
            foreach (string pair in target.Substring(q + 1).Split('&'))
            {
                if (pair.Length == 0) continue;
                int eq = pair.IndexOf('=');
                string key = Uri.UnescapeDataString(eq < 0 ? pair : pair.Substring(0, eq));
                string value = eq < 0 ? "" : Uri.UnescapeDataString(pair.Substring(eq + 1));
                switch (key)
                {
                    case "since":
                        try { f.Since = Json.ParseDate(value); }
                        catch (JsonException ex) { throw new FormatException("since invalide : " + ex.Message); }
                        break;
                    case "kind":
                        {
                            HashSet<EventKind> kinds = new HashSet<EventKind>();
                            foreach (string k in value.Split(','))
                            {
                                if (k.Length == 0) continue;
                                try { kinds.Add(EventWire.ParseKind(k)); }
                                catch (JsonException) { throw new FormatException("kind inconnu : " + k); }
                            }
                            f.Kinds = kinds.Count == 0 ? null : kinds;
                            break;
                        }
                    case "host":
                        f.Host = value;
                        break;
                }
            }
            return f;
        }

        public bool Matches(Event e)
        {
            if (Since.HasValue && e.Timestamp < Since.Value) return false;
            if (Kinds != null && !Kinds.Contains(e.Kind)) return false;
            if (Host != null && e.Host != Host) return false;
            return true;
        }

        /// <summary>Trame SSE d'un event (SPECS §14.2) : `event: <kind>`, `id: <uuid>`, `data: <JSON compact>`, ligne vide.</summary>
        public static string Format(Event e)
        {
            return "event: " + EventWire.KindToWire(e.Kind) + "\nid: " + e.Id.ToString("D") + "\ndata: " + Json.EmitCompact(e.ToJson()) + "\n\n";
        }
    }

    /// <summary>File bornée d'un abonné SSE, alimentée par EventsBus sans jamais bloquer l'émetteur ; au débordement, plus rien n'est accepté.</summary>
    internal sealed class SseSubscriber
    {
        private readonly ConcurrentQueue<Event> queue = new ConcurrentQueue<Event>();
        private readonly SemaphoreSlim signal = new SemaphoreSlim(0);
        private readonly int capacity;
        private int count;
        private int rejected;
        private volatile bool overflowed;

        public SseSubscriber(int capacity) { this.capacity = capacity; }

        public bool Overflowed { get { return overflowed; } }

        public void Offer(Event e)
        {
            if (overflowed) { Interlocked.Increment(ref rejected); return; }
            if (Interlocked.Increment(ref count) > capacity)
            {
                Interlocked.Decrement(ref count);
                Interlocked.Increment(ref rejected);
                overflowed = true;
                signal.Release();
                return;
            }
            queue.Enqueue(e);
            signal.Release();
        }

        public bool TryTake(out Event e)
        {
            if (!queue.TryDequeue(out e)) return false;
            Interlocked.Decrement(ref count);
            return true;
        }

        /// <summary>Attend un event ou le débordement ; false à l'expiration (moment du ping).</summary>
        public Task<bool> WaitAsync(TimeSpan timeout, CancellationToken cancel) { return signal.WaitAsync(timeout, cancel); }

        /// <summary>Events non livrés : refusés + encore en file ; vide la file.</summary>
        public int TakeDropped()
        {
            int n = Interlocked.Exchange(ref rejected, 0);
            Event e;
            while (queue.TryDequeue(out e)) n++;
            return n;
        }
    }
}
