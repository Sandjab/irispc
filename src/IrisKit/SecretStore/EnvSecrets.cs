using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Mode DEBUG `--in-memory-secrets` (spec §4.3) : `IRIS_SECRET_&lt;NAME&gt;=valeur` et `IRIS_SECRET_&lt;NAME&gt;_HOSTS=h1,h2`.
    /// Un secret sans `_HOSTS` valide est ignoré avec avertissement : jamais de secret sans scoping.
    /// Les messages ne citent jamais la valeur.
    /// </summary>
    public static class EnvSecrets
    {
        public const string Prefix = "IRIS_SECRET_";
        public const string HostsSuffix = "_HOSTS";

        public static int LoadInto(InMemorySecretStore store, IDictionary env, DateTime now)
        {
            int loaded = 0;
            List<string> keys = new List<string>();
            foreach (object k in env.Keys) keys.Add(k.ToString());
            keys.Sort(StringComparer.Ordinal);
            foreach (string key in keys)
            {
                if (!key.StartsWith(Prefix, StringComparison.Ordinal) || key.EndsWith(HostsSuffix, StringComparison.Ordinal)) continue;
                string name = key.Substring(Prefix.Length);
                string value = env[key] as string;
                if (string.IsNullOrEmpty(value)) { Log.Warn("secrets", key + " : valeur vide, ignoré"); continue; }
                if (!Secret.NameRegex.IsMatch(name)) { Log.Warn("secrets", key + " : nom de secret invalide, ignoré"); continue; }
                string hostsRaw = env[key + HostsSuffix] as string;
                if (string.IsNullOrEmpty(hostsRaw)) { Log.Warn("secrets", key + " : " + key + HostsSuffix + " absent, secret ignoré (aucun secret sans allowed_hosts)"); continue; }
                List<string> hosts = new List<string>();
                foreach (string h in hostsRaw.Split(','))
                    if (h.Trim().Length > 0) hosts.Add(h.Trim());
                try
                {
                    store.AddAsync(name, Encoding.UTF8.GetBytes(value), hosts, now).GetAwaiter().GetResult();
                    loaded++;
                    Log.Warn("secrets", "DEBUG : secret " + name + " chargé depuis l'environnement, hôtes : " + hostsRaw.Trim());
                }
                catch (SecretStoreException ex)
                {
                    Log.Warn("secrets", key + " : " + ex.Message + ", ignoré");
                }
            }
            return loaded;
        }
    }
}
