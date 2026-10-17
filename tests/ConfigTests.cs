using System;
using System.Collections.Generic;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Config ----------------------------------------------------

        private static void Config_DefaultAndWire()
        {
            Config c = Config.Default(T0);
            c.Validate();
            string json = Json.Emit(c.ToJson());
            Check.True(json.Contains("\"listen\": \"127.0.0.1:8888\"") && json.Contains("\"events_listen\": \"127.0.0.1:8899\"") && json.Contains("\"admin_pipe\": \"iris-admin\"") && json.Contains("\"log_level\": \"info\"") && json.Contains("\"event_retention_days\": 7") && json.Contains("\"event_ring_size\": 10000"), "broker par défaut");
            Check.True(json.Contains("\"on_exfil_attempt\": \"block_and_notify\"") && json.Contains("\"max_substitutions_per_minute\": 60") && json.Contains("\"max_count\": 10"), "security et backups par défaut");
            Check.True(json.Contains("\"host\": \"api.anthropic.com\"") && json.Contains("\"origin\": \"default\"") && json.Contains("\"created_at\": \"2023-11-14T22:13:20Z\""), "hôte semé");
            Check.True(json.Contains("\"plugins\": []") && !json.Contains("admin_socket"), "plugins vide, admin_pipe remplace admin_socket");
            Check.Eq("version,broker,security,backups,hosts,plugins", string.Join(",", Json.ParseObject(json).Keys), "ordre des sections comme IRIS");
            Config back = Config.FromJson(Json.ParseObject(json));
            Check.True(back.Version == 1 && back.Broker.Listen == "127.0.0.1:8888" && back.Security.OnExfilAttempt == ExfilPolicy.BlockAndNotify && back.Backups.MaxCount == 10 && back.Hosts.Count == 1 && back.Hosts[0].Origin == RuleOrigin.Default, "relecture (fixture testDefaultRoundTripsThroughJSON)");
            Check.True(back.AllowedHosts.Contains("api.anthropic.com"), "AllowedHosts");
        }

        private static void Config_PluginsPreservedRaw()
        {
            string json = "{\"version\":1,\"broker\":{\"listen\":\"127.0.0.1:8888\",\"events_listen\":\"127.0.0.1:8899\",\"admin_pipe\":\"iris-admin\",\"log_level\":\"debug\",\"event_retention_days\":3,\"event_ring_size\":50},\"security\":{\"on_exfil_attempt\":\"block_only\",\"max_substitutions_per_minute\":5},\"backups\":{\"max_count\":2},\"hosts\":[],\"plugins\":[{\"id\":\"x\",\"enabled\":true,\"extra\":{\"k\":[1,2]}}]}";
            Config c = Config.FromJson(Json.ParseObject(json));
            Check.True(c.Broker.LogLevel == LogLevel.Debug && c.Broker.EventRetentionDays == 3 && c.Security.OnExfilAttempt == ExfilPolicy.BlockOnly && c.Hosts.Count == 0, "valeurs lues");
            Check.Eq(json, Json.EmitCompact(c.ToJson()), "plugins réécrit tel quel, jamais interprété");
            Config noPlugins = Config.FromJson(Json.ParseObject(json.Replace(",\"plugins\":[{\"id\":\"x\",\"enabled\":true,\"extra\":{\"k\":[1,2]}}]", "")));
            Check.True(Json.EmitCompact(noPlugins.ToJson()).EndsWith("\"plugins\":[]}"), "plugins absent → [] (compat IRIS)");
        }

        private static void Config_Validation()
        {
            Config d = Config.Default(T0);
            Action<string, Config> rejects = delegate(string field, Config bad)
            {
                ConfigException ex = Check.Throws<ConfigException>(delegate { bad.Validate(); }, "rejet " + field);
                Check.Eq(field, ex.Field, "champ en cause : " + field);
            };
            rejects("broker.listen", new Config(1, new BrokerConfig("127.0.0.1", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.listen", new Config(1, new BrokerConfig("127.0.0.1:0", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.listen", new Config(1, new BrokerConfig("localhost:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.events_listen", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:70000", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.admin_pipe", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.event_retention_days", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 0, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.event_ring_size", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 0), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("security.max_substitutions_per_minute", new Config(1, d.Broker, new SecurityConfig(ExfilPolicy.BlockOnly, 0), d.Backups, d.Hosts, d.Plugins));
            rejects("backups.max_count", new Config(1, d.Broker, d.Security, new BackupsConfig(0), d.Hosts, d.Plugins));
            rejects("hosts.host", new Config(1, d.Broker, d.Security, d.Backups, new[] { new MITMRule("_not_a_host_", T0, RuleOrigin.User) }, d.Plugins));
            Check.Throws<JsonException>(delegate { Config.FromJson(Json.ParseObject(Json.Emit(d.ToJson()).Replace("\"info\"", "\"warning\""))); }, "log_level inconnu refusé au parse");
            Check.Throws<JsonException>(delegate { Config.FromJson(Json.ParseObject(Json.Emit(d.ToJson()).Replace("block_and_notify", "notify"))); }, "politique inconnue refusée au parse");
            Check.Eq("block_notify_pause", ExfilPolicyWire.ToWire(ExfilPolicyWire.Parse("block_notify_pause")), "politique pause");
        }

        private static void Backups_CopyAndRotate()
        {
            string dir = TestDir.Create();
            try
            {
                string src = Path.Combine(dir, "config.json");
                File.WriteAllText(src, "{}");
                string bdir = Path.Combine(dir, "backups");
                Check.Eq("20261017T074947123Z", Backups.Stamp(new DateTime(2026, 10, 17, 7, 49, 47, 123, DateTimeKind.Utc)), "horodatage triable");
                string first = Backups.CopyWithStamp(src, bdir, "config", ".json", T0);
                Check.True(File.Exists(first) && Path.GetFileName(first).StartsWith("config-20231114T221320000Z-") && first.EndsWith(".json"), "copie horodatée");
                Backups.CopyWithStamp(src, bdir, "config", ".json", T0.AddSeconds(1));
                Backups.CopyWithStamp(src, bdir, "config", ".json", T0.AddSeconds(2));
                File.WriteAllText(Path.Combine(bdir, "config-corrupted-20231114T221320000Z.json"), "x");
                File.WriteAllText(Path.Combine(bdir, "iris-20231114T221320000Z-abcdef01.kdbx"), "x");
                Check.Eq(1, Backups.Rotate(bdir, "config", ".json", 2), "une suppression");
                Check.True(!File.Exists(first), "la plus ancienne est supprimée");
                Check.Eq(2, Directory.GetFiles(bdir, "config-2*.json").Length, "deux conservées");
                Check.True(File.Exists(Path.Combine(bdir, "config-corrupted-20231114T221320000Z.json")), "config-corrupted-* jamais rotée");
                Check.True(File.Exists(Path.Combine(bdir, "iris-20231114T221320000Z-abcdef01.kdbx")), "autre préfixe intact");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_SeedAndLoad()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                Check.True(File.Exists(Path.Combine(dir, "config.json")) && !store.RecoveredFromCorruption, "semé, pas de corruption");
                Check.Eq(T0, store.Current.Hosts[0].CreatedAt, "created_at du hôte semé = maintenant");
                Check.True(!File.Exists(Path.Combine(dir, "config.json.tmp")), "pas de fichier temporaire résiduel");
                ConfigStore again = ConfigStore.Open(dir, T0.AddDays(1));
                Check.Eq(T0, again.Current.Hosts[0].CreatedAt, "relu depuis le disque, pas resemé");
                Check.Eq(Json.Emit(store.Current.ToJson()) + "\n", File.ReadAllText(Path.Combine(dir, "config.json")), "fichier = Emit + LF final");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_SaveBackupsRotation()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                Config c = store.Current;
                Config two = new Config(1, c.Broker, c.Security, new BackupsConfig(2), c.Hosts, c.Plugins);
                store.Save(two, T0.AddSeconds(1));
                store.Save(two.WithHosts(new List<MITMRule>(two.Hosts) { new MITMRule("api.github.com", T0, RuleOrigin.User) }), T0.AddSeconds(2));
                store.Save(two, T0.AddSeconds(3));
                string bdir = Path.Combine(dir, "backups");
                Check.Eq(2, Directory.GetFiles(bdir, "config-2*.json").Length, "rotation à max_count = 2");
                Check.Eq(2, Config.FromJson(Json.ParseObject(File.ReadAllText(Path.Combine(dir, "config.json")))).Backups.MaxCount, "dernier état écrit");
                Check.Throws<ConfigException>(delegate { store.Save(new Config(1, c.Broker, c.Security, new BackupsConfig(0), c.Hosts, c.Plugins), T0); }, "Save valide avant d'écrire");
                Check.Eq(2, store.Current.Backups.MaxCount, "état inchangé après rejet");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_Corrupted_DegradedBoot()
        {
            string dir = TestDir.Create();
            try
            {
                File.WriteAllText(Path.Combine(dir, "config.json"), "{ pas du json");
                ConfigStore store = ConfigStore.Open(dir, T0);
                Check.True(store.RecoveredFromCorruption && store.CorruptionDetail.Length > 0, "corruption détectée");
                string[] saved = Directory.GetFiles(Path.Combine(dir, "backups"), "config-corrupted-*.json");
                Check.Eq(1, saved.Length, "copie de l'original");
                Check.Eq("{ pas du json", File.ReadAllText(saved[0]), "contenu d'origine conservé");
                Check.Eq("127.0.0.1:8888", store.Current.Broker.Listen, "défauts resemés");
                File.WriteAllText(Path.Combine(dir, "config.json"), Json.Emit(Config.Default(T0).ToJson()).Replace("8888", "0"));
                ConfigStore invalid = ConfigStore.Open(dir, T0);
                Check.True(invalid.RecoveredFromCorruption && invalid.CorruptionDetail.Contains("broker.listen"), "valeur invalide = dégradé aussi");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_IOError()
        {
            string dir = TestDir.Create();
            try
            {
                Directory.CreateDirectory(Path.Combine(dir, "config.json"));
                Check.Throws<ConfigIOException>(delegate { ConfigStore.Open(dir, T0); }, "config.json illisible (répertoire) → erreur d'E/S, pas de reseed");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
