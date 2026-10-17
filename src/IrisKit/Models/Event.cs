using System;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace IrisKit
{
    public enum EventKind { Substituted, PassThrough, NoMatch, ExfilBlocked, Error, SystemAlert, PluginBlocked, PluginResponded }

    [Flags]
    public enum EventFlags { None = 0, BodyTooLarge = 1, NonUtf8 = 2, CompressedBody = 4, Paused = 8 }

    public static class EventWire
    {
        private static readonly string[] Kinds = { "substituted", "passThrough", "noMatch", "exfilBlocked", "error", "systemAlert", "pluginBlocked", "pluginResponded" };
        private static readonly string[] FlagNames = { "bodyTooLarge", "nonUtf8", "compressedBody", "paused" };

        public static string KindToWire(EventKind k) { return Kinds[(int)k]; }
        public static EventKind ParseKind(string w) { return (EventKind)AlertWire.IndexOf(Kinds, w, "kind"); }

        public static List<string> FlagsToWire(EventFlags flags)
        {
            List<string> result = new List<string>();
            for (int i = 0; i < FlagNames.Length; i++)
                if ((flags & (EventFlags)(1 << i)) != 0) result.Add(FlagNames[i]);
            return result;
        }

        public static EventFlags ParseFlags(IList<string> names)
        {
            EventFlags flags = EventFlags.None;
            if (names == null) return flags;
            foreach (string name in names) flags |= (EventFlags)(1 << AlertWire.IndexOf(FlagNames, name, "flags"));
            return flags;
        }
    }

    /// <summary>Event du journal (SPECS §5.3) + drapeaux irispc (spec socle §5.3). Ne porte que des noms de secrets.</summary>
    public sealed class Event
    {
        public Guid Id { get; private set; }
        public DateTime Timestamp { get; private set; }
        public EventKind Kind { get; private set; }
        public string Host { get; private set; }
        public string Method { get; private set; }
        public string Path { get; private set; }
        public int? StatusCode { get; private set; }
        public long? DurationMs { get; private set; }
        public IList<string> SubstitutedSecrets { get; private set; }
        public Alert Alert { get; private set; }
        public SystemAlert SystemAlert { get; private set; }
        public EventFlags Flags { get; private set; }

        public Event(Guid id, DateTime timestamp, EventKind kind, string host, string method, string path, int? statusCode, long? durationMs,
            IList<string> substitutedSecrets, Alert alert, SystemAlert systemAlert, EventFlags flags)
        {
            Id = id;
            Timestamp = timestamp;
            Kind = kind;
            Host = host;
            Method = method;
            Path = path;
            StatusCode = statusCode;
            DurationMs = durationMs;
            SubstitutedSecrets = new List<string>(substitutedSecrets ?? new string[0]).AsReadOnly();
            Alert = alert;
            SystemAlert = systemAlert;
            Flags = flags;
        }

        /// <summary>Event système (démarrage dégradé…) : host = catégorie, method et path = "-".</summary>
        public static Event System(DateTime at, AlertSeverity severity, string category, string message)
        {
            return new Event(Guid.NewGuid(), at, EventKind.SystemAlert, category, "-", "-", null, null, new string[0], null, new SystemAlert(severity, message), EventFlags.None);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["id"] = Id.ToString("D");
            o["timestamp"] = Timestamp;
            o["kind"] = EventWire.KindToWire(Kind);
            o["host"] = Host;
            o["method"] = Method;
            o["path"] = Path;
            if (StatusCode.HasValue) o["status_code"] = (long)StatusCode.Value;
            if (DurationMs.HasValue) o["duration_ms"] = DurationMs.Value;
            o["substituted_secrets"] = new List<string>(SubstitutedSecrets);
            if (Alert != null) o["alert"] = Alert.ToJson();
            if (SystemAlert != null) o["system_alert"] = SystemAlert.ToJson();
            if (Flags != EventFlags.None) o["flags"] = EventWire.FlagsToWire(Flags);
            return o;
        }

        public static Event FromJson(JsonObject o)
        {
            long? status = o.OptionalInt("status_code");
            JsonObject alert = o.OptionalObject("alert");
            JsonObject system = o.OptionalObject("system_alert");
            IList<object> flagsRaw = o.OptionalArray("flags");
            List<string> flagNames = null;
            if (flagsRaw != null)
            {
                flagNames = new List<string>();
                foreach (object f in flagsRaw) flagNames.Add(f as string);
            }
            return new Event(
                new Guid(o.String("id")),
                Json.ParseDate(o.String("timestamp")),
                EventWire.ParseKind(o.String("kind")),
                o.String("host"), o.String("method"), o.String("path"),
                status.HasValue ? (int?)(int)status.Value : null,
                o.OptionalInt("duration_ms"),
                o.StringArray("substituted_secrets"),
                alert == null ? null : Alert.FromJson(alert),
                system == null ? null : SystemAlert.FromJson(system),
                EventWire.ParseFlags(flagNames));
        }
    }
}
