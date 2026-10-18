using System;
using System.Collections.Generic;
using System.Globalization;

namespace IrisKit
{
    /// <summary>`config.set` avec une clé que IRIS ne connaît pas : -32602.</summary>
    public sealed class ConfigKeyException : Exception
    {
        public string Key { get; private set; }
        public ConfigKeyException(string key) : base("clé de configuration inconnue : " + key) { Key = key; }
    }

    /// <summary>`rule.delete` d'un hôte semé (`origin: default`) : -32010.</summary>
    public sealed class ConfigHostProtectedException : Exception
    {
        public string Host { get; private set; }
        public ConfigHostProtectedException(string host)
            : base("l'hôte " + host + " (origin: default) est protégé : il ne peut pas être retiré")
        {
            Host = host;
        }
    }

    /// <summary>`config.reload` impossible (fichier illisible ou invalide) : la config courante est conservée, -32012.</summary>
    public sealed class ConfigReloadException : Exception
    {
        public ConfigReloadException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>Résultat de `config.set` : clés appliquées à chaud, clés persistées qui attendent un redémarrage.</summary>
    public sealed class ConfigSetResult
    {
        public IList<string> Applied { get; private set; }
        public IList<string> RequiresRestart { get; private set; }

        public ConfigSetResult(IList<string> applied, IList<string> requiresRestart)
        {
            Applied = applied;
            RequiresRestart = requiresRestart;
        }
    }

    /// <summary>`config.set` d'IRIS (ConfigStore.applyUpdates) : valeurs en chaînes, lot atomique ; `broker.admin_socket` devient `broker.admin_pipe`.</summary>
    public static class ConfigUpdates
    {
        public static readonly string[] HotKeys = { "security.on_exfil_attempt", "security.max_substitutions_per_minute", "backups.max_count" };

        /// <summary>Applique le lot à `current` et rend la nouvelle config, non validée (Save valide). Clé inconnue → ConfigKeyException ; valeur non convertible → ConfigException.</summary>
        public static Config Apply(Config current, IList<KeyValuePair<string, string>> updates, out ConfigSetResult result)
        {
            BrokerConfig b = current.Broker;
            SecurityConfig s = current.Security;
            BackupsConfig k = current.Backups;
            List<string> applied = new List<string>();
            List<string> restart = new List<string>();
            foreach (KeyValuePair<string, string> u in updates)
            {
                string key = u.Key ?? "";
                string value = u.Value ?? "";
                switch (key)
                {
                    case "security.on_exfil_attempt":
                        s = new SecurityConfig(ParsePolicy(key, value), s.MaxSubstitutionsPerMinute);
                        break;
                    case "security.max_substitutions_per_minute":
                        s = new SecurityConfig(s.OnExfilAttempt, ParseInt(key, value));
                        break;
                    case "backups.max_count":
                        k = new BackupsConfig(ParseInt(key, value));
                        break;
                    case "broker.log_level":
                        {
                            LogLevel level;
                            if (!LogLevelWire.TryParse(value, out level)) throw new ConfigException(key, value);
                            b = new BrokerConfig(b.Listen, b.EventsListen, b.AdminPipe, level, b.EventRetentionDays, b.EventRingSize);
                            break;
                        }
                    case "broker.listen":
                        b = new BrokerConfig(value, b.EventsListen, b.AdminPipe, b.LogLevel, b.EventRetentionDays, b.EventRingSize);
                        break;
                    case "broker.events_listen":
                        b = new BrokerConfig(b.Listen, value, b.AdminPipe, b.LogLevel, b.EventRetentionDays, b.EventRingSize);
                        break;
                    case "broker.admin_pipe":
                        b = new BrokerConfig(b.Listen, b.EventsListen, value, b.LogLevel, b.EventRetentionDays, b.EventRingSize);
                        break;
                    case "broker.event_retention_days":
                        b = new BrokerConfig(b.Listen, b.EventsListen, b.AdminPipe, b.LogLevel, ParseInt(key, value), b.EventRingSize);
                        break;
                    case "broker.event_ring_size":
                        b = new BrokerConfig(b.Listen, b.EventsListen, b.AdminPipe, b.LogLevel, b.EventRetentionDays, ParseInt(key, value));
                        break;
                    default:
                        throw new ConfigKeyException(key);
                }
                if (Array.IndexOf(HotKeys, key) >= 0) applied.Add(key); else restart.Add(key);
            }
            result = new ConfigSetResult(applied, restart);
            return new Config(current.Version, b, s, k, current.Hosts, current.Plugins);
        }

        /// <summary>Champs `broker.*` qui diffèrent (ordre d'IRIS) : ils ne prennent effet qu'au redémarrage (`ignored` de config.reload).</summary>
        public static IList<string> StructuralChanges(Config before, Config after)
        {
            List<string> changed = new List<string>();
            BrokerConfig a = before.Broker, b = after.Broker;
            if (a.Listen != b.Listen) changed.Add("broker.listen");
            if (a.EventsListen != b.EventsListen) changed.Add("broker.events_listen");
            if (a.AdminPipe != b.AdminPipe) changed.Add("broker.admin_pipe");
            if (a.EventRetentionDays != b.EventRetentionDays) changed.Add("broker.event_retention_days");
            if (a.EventRingSize != b.EventRingSize) changed.Add("broker.event_ring_size");
            if (a.LogLevel != b.LogLevel) changed.Add("broker.log_level");
            return changed;
        }

        private static int ParseInt(string key, string value)
        {
            int n;
            if (!int.TryParse(value, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out n)) throw new ConfigException(key, value);
            return n;
        }

        private static ExfilPolicy ParsePolicy(string key, string value)
        {
            int index = Array.IndexOf(ExfilPolicyWire.Names, value);
            if (index < 0) throw new ConfigException(key, value);
            return (ExfilPolicy)index;
        }
    }
}
