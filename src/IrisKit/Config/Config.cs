using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Net;

namespace IrisKit
{
    public enum ExfilPolicy { BlockOnly, BlockAndNotify, BlockNotifyPause }

    public static class ExfilPolicyWire
    {
        public static readonly string[] Names = { "block_only", "block_and_notify", "block_notify_pause" };
        public static string ToWire(ExfilPolicy p) { return Names[(int)p]; }
        public static ExfilPolicy Parse(string w) { return (ExfilPolicy)AlertWire.IndexOf(Names, w, "on_exfil_attempt"); }
    }

    /// <summary>Valeur invalide dans config.json : champ en notation pointée (`broker.listen`) et valeur fautive.</summary>
    public sealed class ConfigException : Exception
    {
        public string Field { get; private set; }
        public string Value { get; private set; }

        public ConfigException(string field, string value)
            : base("valeur invalide pour " + field + " : " + value)
        {
            Field = field;
            Value = value;
        }
    }

    public sealed class BrokerConfig
    {
        public string Listen { get; private set; }
        public string EventsListen { get; private set; }
        public string AdminPipe { get; private set; }
        public LogLevel LogLevel { get; private set; }
        public int EventRetentionDays { get; private set; }
        public int EventRingSize { get; private set; }

        public BrokerConfig(string listen, string eventsListen, string adminPipe, LogLevel logLevel, int eventRetentionDays, int eventRingSize)
        {
            Listen = listen; EventsListen = eventsListen; AdminPipe = adminPipe;
            LogLevel = logLevel; EventRetentionDays = eventRetentionDays; EventRingSize = eventRingSize;
        }

        public void Validate()
        {
            ValidateListen(Listen, "broker.listen");
            ValidateListen(EventsListen, "broker.events_listen");
            if (string.IsNullOrEmpty(AdminPipe)) throw new ConfigException("broker.admin_pipe", AdminPipe ?? "null");
            if (EventRetentionDays <= 0) throw new ConfigException("broker.event_retention_days", EventRetentionDays.ToString(CultureInfo.InvariantCulture));
            if (EventRingSize <= 0) throw new ConfigException("broker.event_ring_size", EventRingSize.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>`ip:port`, IP littérale, port 1–65535.</summary>
        public static void ValidateListen(string address, string field)
        {
            string[] parts = (address ?? "").Split(':');
            int port;
            IPAddress ip;
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out ip)
                || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535)
                throw new ConfigException(field, address ?? "null");
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["listen"] = Listen; o["events_listen"] = EventsListen; o["admin_pipe"] = AdminPipe;
            o["log_level"] = LogLevelWire.ToWire(LogLevel);
            o["event_retention_days"] = (long)EventRetentionDays; o["event_ring_size"] = (long)EventRingSize;
            return o;
        }

        public static BrokerConfig FromJson(JsonObject o)
        {
            LogLevel level;
            string wire = o.String("log_level");
            if (!LogLevelWire.TryParse(wire, out level)) throw new JsonException("log_level inconnu : " + wire + " (attendu : " + string.Join(", ", LogLevelWire.Names) + ")");
            return new BrokerConfig(o.String("listen"), o.String("events_listen"), o.String("admin_pipe"), level,
                (int)o.Int("event_retention_days"), (int)o.Int("event_ring_size"));
        }
    }

    public sealed class SecurityConfig
    {
        public ExfilPolicy OnExfilAttempt { get; private set; }
        public int MaxSubstitutionsPerMinute { get; private set; }

        public SecurityConfig(ExfilPolicy onExfilAttempt, int maxSubstitutionsPerMinute)
        {
            OnExfilAttempt = onExfilAttempt; MaxSubstitutionsPerMinute = maxSubstitutionsPerMinute;
        }

        public void Validate()
        {
            if (MaxSubstitutionsPerMinute <= 0) throw new ConfigException("security.max_substitutions_per_minute", MaxSubstitutionsPerMinute.ToString(CultureInfo.InvariantCulture));
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["on_exfil_attempt"] = ExfilPolicyWire.ToWire(OnExfilAttempt);
            o["max_substitutions_per_minute"] = (long)MaxSubstitutionsPerMinute;
            return o;
        }

        public static SecurityConfig FromJson(JsonObject o)
        {
            return new SecurityConfig(ExfilPolicyWire.Parse(o.String("on_exfil_attempt")), (int)o.Int("max_substitutions_per_minute"));
        }
    }

    public sealed class BackupsConfig
    {
        public int MaxCount { get; private set; }
        public BackupsConfig(int maxCount) { MaxCount = maxCount; }

        public void Validate()
        {
            if (MaxCount < 1) throw new ConfigException("backups.max_count", MaxCount.ToString(CultureInfo.InvariantCulture));
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["max_count"] = (long)MaxCount;
            return o;
        }

        public static BackupsConfig FromJson(JsonObject o) { return new BackupsConfig((int)o.Int("max_count")); }
    }

    /// <summary>config.json (SPECS §6, spec socle §5.1). Le daemon est le seul écrivain. `Plugins` est lu et réécrit tel quel.</summary>
    public sealed class Config
    {
        public int Version { get; private set; }
        public BrokerConfig Broker { get; private set; }
        public SecurityConfig Security { get; private set; }
        public BackupsConfig Backups { get; private set; }
        public IList<MITMRule> Hosts { get; private set; }
        public object Plugins { get; private set; }

        public Config(int version, BrokerConfig broker, SecurityConfig security, BackupsConfig backups, IList<MITMRule> hosts, object plugins)
        {
            Version = version; Broker = broker; Security = security; Backups = backups;
            Hosts = new List<MITMRule>(hosts).AsReadOnly();
            Plugins = plugins ?? new List<object>();
        }

        public static Config Default(DateTime seededAt)
        {
            return new Config(1,
                new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000),
                new SecurityConfig(ExfilPolicy.BlockAndNotify, 60),
                new BackupsConfig(10),
                new[] { new MITMRule("api.anthropic.com", seededAt, RuleOrigin.Default) },
                new List<object>());
        }

        public Config WithHosts(IList<MITMRule> hosts) { return new Config(Version, Broker, Security, Backups, hosts, Plugins); }

        public ISet<string> AllowedHosts
        {
            get
            {
                HashSet<string> set = new HashSet<string>(StringComparer.Ordinal);
                foreach (MITMRule r in Hosts) set.Add(r.Host);
                return set;
            }
        }

        public void Validate()
        {
            Broker.Validate();
            Security.Validate();
            Backups.Validate();
            foreach (MITMRule r in Hosts)
                if (!HostName.IsValid(r.Host)) throw new ConfigException("hosts.host", r.Host);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["version"] = (long)Version;
            o["broker"] = Broker.ToJson();
            o["security"] = Security.ToJson();
            o["backups"] = Backups.ToJson();
            List<object> hosts = new List<object>();
            foreach (MITMRule r in Hosts) hosts.Add(r.ToJson());
            o["hosts"] = hosts;
            o["plugins"] = Plugins;
            return o;
        }

        public static Config FromJson(JsonObject o)
        {
            List<MITMRule> hosts = new List<MITMRule>();
            foreach (object h in o.Array("hosts"))
            {
                IDictionary<string, object> dict = h as IDictionary<string, object>;
                if (dict == null) throw new JsonException("hosts : objets attendus");
                hosts.Add(MITMRule.FromJson(new JsonObject(dict)));
            }
            object plugins = o.Has("plugins") ? o.Raw("plugins") : new List<object>();
            return new Config((int)o.Int("version"), BrokerConfig.FromJson(o.Object("broker")), SecurityConfig.FromJson(o.Object("security")),
                BackupsConfig.FromJson(o.Object("backups")), hosts, plugins);
        }
    }
}
