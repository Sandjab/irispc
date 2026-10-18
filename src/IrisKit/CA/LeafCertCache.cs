using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace IrisKit
{
    /// <summary>
    /// Feuilles par hôte signées par le CA (spec §6.1) : cache mémoire, jamais sur disque ; renouvelée moins d'un jour avant
    /// expiration ; la clé CNG est supprimée à l'éviction, au renouvellement et au Dispose.
    /// </summary>
    public sealed class LeafCertCache : IDisposable
    {
        public static readonly TimeSpan RenewBefore = TimeSpan.FromDays(1);

        private readonly CAManager ca;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private readonly Dictionary<string, X509Certificate2> cache = new Dictionary<string, X509Certificate2>(StringComparer.Ordinal);

        public LeafCertCache(CAManager ca, Func<DateTime> clock)
        {
            if (ca == null) throw new ArgumentNullException("ca");
            this.ca = ca;
            this.clock = clock;
        }

        public int Count { get { lock (gate) { return cache.Count; } } }

        /// <summary>Feuille valide pour l'hôte (normalisé en minuscules, sans port), frappée au premier usage.</summary>
        public X509Certificate2 Get(string host)
        {
            string key = HostName.Normalize(host);
            DateTime now = clock();
            lock (gate)
            {
                X509Certificate2 existing;
                if (cache.TryGetValue(key, out existing))
                {
                    if (existing.NotAfter.ToUniversalTime() - now > RenewBefore) return existing;
                    cache.Remove(key);
                    CACrypto.DestroyPrivateKey(existing);
                    Log.Info("ca", "feuille renouvelée pour " + key);
                }
                X509Certificate2 leaf = CACrypto.CreateLeafCertificate(key, ca.Certificate, ca.SigningKey, now, CACrypto.LeafValidityDays);
                cache[key] = leaf;
                Log.Debug("ca", "feuille émise pour " + key + ", empreinte " + leaf.Thumbprint.ToLowerInvariant());
                return leaf;
            }
        }

        public bool Evict(string host)
        {
            string key = HostName.Normalize(host);
            lock (gate)
            {
                X509Certificate2 existing;
                if (!cache.TryGetValue(key, out existing)) return false;
                cache.Remove(key);
                CACrypto.DestroyPrivateKey(existing);
                return true;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                foreach (X509Certificate2 leaf in cache.Values) CACrypto.DestroyPrivateKey(leaf);
                cache.Clear();
            }
        }
    }
}
