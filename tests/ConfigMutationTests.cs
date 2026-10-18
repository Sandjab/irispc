using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Mutations de config.json (spec phase 3 §7) ----------------------------

        private static List<KeyValuePair<string, string>> Updates(params string[] kv)
        {
            List<KeyValuePair<string, string>> list = new List<KeyValuePair<string, string>>();
            for (int i = 0; i < kv.Length; i += 2) list.Add(new KeyValuePair<string, string>(kv[i], kv[i + 1]));
            return list;
        }

        private static void Config_ApplyUpdates_HotAndStructural()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                ConfigSetResult r = store.ApplyUpdates(Updates(
                    "security.on_exfil_attempt", "block_only",
                    "security.max_substitutions_per_minute", "5",
                    "broker.listen", "127.0.0.1:9999",
                    "backups.max_count", "3",
                    "broker.log_level", "debug"), T0.AddMinutes(1));
                Check.Eq("security.on_exfil_attempt,security.max_substitutions_per_minute,backups.max_count", string.Join(",", r.Applied), "clés à chaud");
                Check.Eq("broker.listen,broker.log_level", string.Join(",", r.RequiresRestart), "clés structurelles");
                Check.True(store.Current.Security.OnExfilAttempt == ExfilPolicy.BlockOnly && store.Current.Security.MaxSubstitutionsPerMinute == 5, "sécurité appliquée");
                Check.True(store.Current.Broker.Listen == "127.0.0.1:9999" && store.Current.Broker.LogLevel == LogLevel.Debug && store.Current.Backups.MaxCount == 3, "persisté");
                ConfigStore reread = ConfigStore.Open(dir, T0);
                Check.Eq(5, reread.Current.Security.MaxSubstitutionsPerMinute, "relu depuis le disque");
                Check.Eq(1, Directory.GetFiles(Path.Combine(dir, "backups"), "config-*.json").Length, "backup avant écriture");
                ConfigSetResult admin = store.ApplyUpdates(Updates("broker.admin_pipe", "autre-pipe", "broker.events_listen", "127.0.0.1:9898",
                    "broker.event_retention_days", "3", "broker.event_ring_size", "50"), T0.AddMinutes(2));
                Check.Eq(4, admin.RequiresRestart.Count, "admin_pipe, events_listen, retention, ring : redémarrage");
                Check.Eq("autre-pipe", store.Current.Broker.AdminPipe, "broker.admin_pipe remplace admin_socket");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Config_ApplyUpdates_AtomicOnError()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                string before = File.ReadAllText(store.Path);
                ConfigKeyException k = Check.Throws<ConfigKeyException>(delegate { store.ApplyUpdates(Updates("security.max_substitutions_per_minute", "5", "nope.key", "1"), T0); }, "clé inconnue");
                Check.Eq("nope.key", k.Key, "clé citée");
                Check.Throws<ConfigException>(delegate { store.ApplyUpdates(Updates("security.max_substitutions_per_minute", "abc"), T0); }, "entier illisible");
                Check.Throws<ConfigException>(delegate { store.ApplyUpdates(Updates("security.max_substitutions_per_minute", "0"), T0); }, "valeur refusée par Validate");
                Check.Throws<ConfigException>(delegate { store.ApplyUpdates(Updates("security.on_exfil_attempt", "nope"), T0); }, "politique inconnue");
                Check.Throws<ConfigException>(delegate { store.ApplyUpdates(Updates("broker.listen", "x"), T0); }, "adresse illisible");
                Check.Throws<ConfigException>(delegate { store.ApplyUpdates(Updates("broker.log_level", "verbose"), T0); }, "niveau inconnu");
                Check.Eq(before, File.ReadAllText(store.Path), "rien n'est écrit en cas d'erreur");
                Check.Eq(60, store.Current.Security.MaxSubstitutionsPerMinute, "Current inchangé");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Config_Hosts_AddDelete()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                MITMRule added = store.AddHost("API.Example.com:443", T0.AddHours(1));
                Check.True(added.Host == "api.example.com" && added.Origin == RuleOrigin.User && added.CreatedAt == T0.AddHours(1), "hôte normalisé, origin user");
                MITMRule again = store.AddHost("api.example.com", T0.AddHours(2));
                Check.Eq(T0.AddHours(1), again.CreatedAt, "idempotent : règle existante rendue");
                Check.Eq(2, store.Current.Hosts.Count, "pas de doublon");
                Check.Throws<ConfigException>(delegate { store.AddHost("bad host", T0); }, "hôte invalide");
                Check.True(store.DeleteHost("API.example.com", T0), "suppression d'un hôte user");
                Check.True(!store.DeleteHost("api.example.com", T0), "absent → false");
                ConfigHostProtectedException p = Check.Throws<ConfigHostProtectedException>(delegate { store.DeleteHost("api.anthropic.com", T0); }, "hôte default protégé");
                Check.Eq("api.anthropic.com", p.Host, "hôte cité");
                Check.Eq(1, ConfigStore.Open(dir, T0).Current.Hosts.Count, "persisté");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Config_Reload()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                Config c = store.Current;
                List<MITMRule> hosts = new List<MITMRule>(c.Hosts);
                hosts.Add(new MITMRule("api.github.com", T0, RuleOrigin.User));
                Config edited = new Config(c.Version,
                    new BrokerConfig("127.0.0.1:7777", c.Broker.EventsListen, c.Broker.AdminPipe, c.Broker.LogLevel, c.Broker.EventRetentionDays, c.Broker.EventRingSize),
                    new SecurityConfig(c.Security.OnExfilAttempt, 7), c.Backups, hosts, c.Plugins);
                File.WriteAllText(store.Path, Json.Emit(edited.ToJson()) + "\n", new UTF8Encoding(false));
                IList<string> ignored = store.Reload();
                Check.Eq("broker.listen", string.Join(",", ignored), "champ structurel signalé");
                Check.True(store.Current.Security.MaxSubstitutionsPerMinute == 7 && store.Current.AllowedHosts.Contains("api.github.com"), "sécurité et hôtes rechargés");
                File.WriteAllText(store.Path, "{ corrompu");
                Check.Throws<ConfigReloadException>(delegate { store.Reload(); }, "fichier corrompu");
                Check.Eq(7, store.Current.Security.MaxSubstitutionsPerMinute, "état conservé");
                Check.Eq("{ corrompu", File.ReadAllText(store.Path), "pas de re-seed au rechargement");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
