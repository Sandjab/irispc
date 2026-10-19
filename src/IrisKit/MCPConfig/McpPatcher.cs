using System;
using System.Collections.Generic;

namespace IrisKit
{
    public sealed class McpPatchSummary
    {
        public int Patched;
        public int AlreadyCompliant;
        public int Skipped;
    }

    /// <summary>Résultat d'un patch : copie patchée (l'entrée n'est jamais modifiée), compteurs, ajouts lisibles pour --dry-run.</summary>
    public sealed class McpPatchResult
    {
        public OrderedJsonValue Root { get; internal set; }
        public McpPatchSummary Summary { get; internal set; }
        /// <summary>Une ligne par clé ajoutée : `mcpServers.github.env.HTTPS_PROXY = "http://127.0.0.1:8888"`.</summary>
        public IList<string> Additions { get; internal set; }
        /// <summary>Serveurs `type` http ou sse sans `env`, laissés tels quels (règle 3).</summary>
        public IList<string> SkippedServers { get; internal set; }
    }

    /// <summary>
    /// `iris mcp wrap` sans E/S (SPECS §16.1, spec phase 5 §6.1) : pour chaque serveur de `mcpServers` (à la racine, sinon dans le
    /// premier objet de premier niveau qui le contient), ajoute à `env` les six variables proxy/CA absentes, sans jamais écraser une
    /// valeur existante. Écart assumé avec le code Swift : HTTPS_PROXY et HTTP_PROXY ne sont pas traités en bloc (SPECS prime).
    /// </summary>
    public static class McpPatcher
    {
        public static readonly string[] ProxyKeys = { "HTTPS_PROXY", "HTTP_PROXY" };
        public static readonly string[] CaKeys = { "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE" };

        public static McpPatchResult Patch(OrderedJsonValue root, string brokerListen, string caPemPath)
        {
            McpPatchResult r = new McpPatchResult();
            r.Root = root.Clone();
            r.Summary = new McpPatchSummary();
            r.Additions = new List<string>();
            r.SkippedServers = new List<string>();
            string prefix;
            OrderedJsonValue servers = Locate(r.Root, out prefix);
            if (servers == null || !servers.IsObject) return r;
            List<KeyValuePair<string, string>> needed = Needed(brokerListen, caPemPath);
            foreach (KeyValuePair<string, OrderedJsonValue> entry in servers.Pairs)
            {
                OrderedJsonValue server = entry.Value;
                if (!server.IsObject) continue;
                OrderedJsonValue type = server.Get("type");
                bool remote = type != null && type.Kind == OrderedJsonKind.String && (type.Text == "http" || type.Text == "sse");
                OrderedJsonValue env = server.Get("env");
                if (remote && env == null)
                {
                    r.Summary.Skipped++;
                    r.SkippedServers.Add(entry.Key);
                    continue;
                }
                if (env == null || !env.IsObject)
                {
                    // Comme IRIS : `env` absent est créé ; un `env` qui n'est pas un objet ne contient rien d'utilisable et est remplacé.
                    env = OrderedJsonValue.NewObject();
                    server.Set("env", env);
                }
                bool added = false;
                foreach (KeyValuePair<string, string> kv in needed)
                {
                    if (env.Get(kv.Key) != null) continue;
                    env.Set(kv.Key, OrderedJsonValue.FromString(kv.Value));
                    r.Additions.Add(prefix + "." + entry.Key + ".env." + kv.Key + " = " + OrderedJsonWriter.Quote(kv.Value));
                    added = true;
                }
                if (added) r.Summary.Patched++;
                else r.Summary.AlreadyCompliant++;
            }
            return r;
        }

        /// <summary>Les six variables, triées par ordre ordinal (déterminisme, comme IRIS).</summary>
        private static List<KeyValuePair<string, string>> Needed(string brokerListen, string caPemPath)
        {
            List<KeyValuePair<string, string>> needed = new List<KeyValuePair<string, string>>();
            foreach (string k in ProxyKeys) needed.Add(new KeyValuePair<string, string>(k, "http://" + brokerListen));
            foreach (string k in CaKeys) needed.Add(new KeyValuePair<string, string>(k, caPemPath));
            needed.Sort(delegate(KeyValuePair<string, string> a, KeyValuePair<string, string> b) { return string.CompareOrdinal(a.Key, b.Key); });
            return needed;
        }

        private static OrderedJsonValue Locate(OrderedJsonValue root, out string prefix)
        {
            prefix = "mcpServers";
            if (!root.IsObject) return null;
            OrderedJsonValue direct = root.Get("mcpServers");
            if (direct != null) return direct;
            foreach (KeyValuePair<string, OrderedJsonValue> p in root.Pairs)
            {
                if (!p.Value.IsObject) continue;
                OrderedJsonValue nested = p.Value.Get("mcpServers");
                if (nested == null) continue;
                prefix = p.Key + ".mcpServers";
                return nested;
            }
            return null;
        }
    }
}
