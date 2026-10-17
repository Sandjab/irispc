using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Décorateur LRU (32 valeurs, TTL 5 min) devant un ISecretStore (spec §4.4). Invalidé par Rotate et Delete.</summary>
    public sealed class SecretCache : ISecretStore
    {
        public const int DefaultCapacity = 32;
        public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

        private sealed class Cached
        {
            public byte[] Value;
            public DateTime Expires;
            public LinkedListNode<string> Node;
        }

        private readonly object gate = new object();
        private readonly ISecretStore inner;
        private readonly int capacity;
        private readonly TimeSpan ttl;
        private readonly Func<DateTime> clock;
        private readonly Dictionary<string, Cached> map = new Dictionary<string, Cached>(StringComparer.Ordinal);
        private readonly LinkedList<string> order = new LinkedList<string>(); // tête = plus récent

        public SecretCache(ISecretStore inner) : this(inner, DefaultCapacity, DefaultTtl, delegate { return DateTime.UtcNow; }) { }

        public SecretCache(ISecretStore inner, int capacity, TimeSpan ttl, Func<DateTime> clock)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            if (capacity <= 0) throw new ArgumentOutOfRangeException("capacity");
            this.inner = inner; this.capacity = capacity; this.ttl = ttl; this.clock = clock;
        }

        public int CachedCount { get { lock (gate) { return map.Count; } } }

        public void Invalidate(string name)
        {
            lock (gate)
            {
                Cached c;
                if (name != null && map.TryGetValue(name, out c))
                {
                    order.Remove(c.Node);
                    map.Remove(name);
                    Array.Clear(c.Value, 0, c.Value.Length);
                }
            }
        }

        public void Clear()
        {
            lock (gate)
            {
                foreach (Cached c in map.Values) Array.Clear(c.Value, 0, c.Value.Length);
                map.Clear();
                order.Clear();
            }
        }

        public async Task<byte[]> ValueAsync(string name)
        {
            lock (gate)
            {
                Cached hit;
                if (map.TryGetValue(name, out hit))
                {
                    if (hit.Expires > clock())
                    {
                        order.Remove(hit.Node);
                        order.AddFirst(hit.Node);
                        return (byte[])hit.Value.Clone();
                    }
                    order.Remove(hit.Node);
                    map.Remove(name);
                }
            }
            byte[] value = await inner.ValueAsync(name).ConfigureAwait(false);
            lock (gate)
            {
                Cached c;
                if (map.TryGetValue(name, out c)) order.Remove(c.Node);
                c = new Cached();
                c.Value = (byte[])value.Clone();
                c.Expires = clock() + ttl;
                c.Node = order.AddFirst(name);
                map[name] = c;
                while (map.Count > capacity)
                {
                    string oldest = order.Last.Value;
                    order.RemoveLast();
                    Array.Clear(map[oldest].Value, 0, map[oldest].Value.Length);
                    map.Remove(oldest);
                }
            }
            return value;
        }

        public async Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            Secret s = await inner.RotateAsync(name, newValue).ConfigureAwait(false);
            Invalidate(name);
            return s;
        }

        public async Task DeleteAsync(string name)
        {
            await inner.DeleteAsync(name).ConfigureAwait(false);
            Invalidate(name);
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt) { return inner.AddAsync(name, value, allowedHosts, createdAt); }
        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts) { return inner.UpdateAsync(name, allowedHosts); }
        public Task<Secret> SecretAsync(string name) { return inner.SecretAsync(name); }
        public Task<IList<Secret>> ListAsync() { return inner.ListAsync(); }
        public Task<Secret> RecordUsageAsync(string name, DateTime at) { return inner.RecordUsageAsync(name, at); }
        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined) { return inner.SetQuarantinedAsync(name, quarantined); }
    }
}
