using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Coffre en mémoire : tests et mode `--in-memory-secrets`. Même contrat que KeePassSecretStore.</summary>
    public sealed class InMemorySecretStore : ISecretStore
    {
        private sealed class Entry
        {
            public Secret Meta;
            public byte[] Value;
        }

        private readonly object gate = new object();
        private readonly Dictionary<string, Entry> items = new Dictionary<string, Entry>(StringComparer.Ordinal);

        internal static IList<string> NormalizeHosts(IList<string> hosts)
        {
            List<string> result = new List<string>();
            if (hosts != null)
                foreach (string h in hosts)
                {
                    string n = HostName.Normalize(h);
                    if (n.Length > 0 && !result.Contains(n)) result.Add(n);
                }
            Secret.ValidateAllowedHosts(result);
            return result;
        }

        private Entry Find(string name)
        {
            Entry e;
            if (name == null || !items.TryGetValue(name, out e))
                throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return e;
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt)
        {
            Secret.ValidateName(name);
            IList<string> hosts = NormalizeHosts(allowedHosts);
            lock (gate)
            {
                foreach (string existing in items.Keys)
                    if (string.Equals(existing, name, StringComparison.OrdinalIgnoreCase))
                        throw new SecretStoreException(SecretStoreErrorKind.Duplicate, name, "secret déjà présent : " + existing);
                Entry e = new Entry();
                e.Meta = new Secret(name, hosts, createdAt, null, 0, false);
                e.Value = (byte[])value.Clone();
                items[name] = e;
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts)
        {
            IList<string> hosts = NormalizeHosts(allowedHosts);
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithAllowedHosts(hosts);
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Value = (byte[])newValue.Clone();
                return Task.FromResult(e.Meta);
            }
        }

        public Task DeleteAsync(string name)
        {
            lock (gate)
            {
                Find(name);
                items.Remove(name);
                return Task.FromResult(0);
            }
        }

        public Task<byte[]> ValueAsync(string name)
        {
            lock (gate) { return Task.FromResult((byte[])Find(name).Value.Clone()); }
        }

        public Task<Secret> SecretAsync(string name)
        {
            lock (gate) { return Task.FromResult(Find(name).Meta); }
        }

        public Task<IList<Secret>> ListAsync()
        {
            lock (gate)
            {
                List<Secret> list = new List<Secret>();
                foreach (Entry e in items.Values) list.Add(e.Meta);
                list.Sort(delegate(Secret a, Secret b) { return string.CompareOrdinal(a.Name, b.Name); });
                return Task.FromResult((IList<Secret>)list);
            }
        }

        public Task<Secret> RecordUsageAsync(string name, DateTime at)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithUsage(at, e.Meta.UsageCount + 1);
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithQuarantined(quarantined);
                return Task.FromResult(e.Meta);
            }
        }
    }
}
