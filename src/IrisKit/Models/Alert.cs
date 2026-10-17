using System;
using System.Collections.Specialized;

namespace IrisKit
{
    public enum AlertSeverity { Low = 0, Medium = 1, High = 2 }
    public enum ExfilRule { HostMismatch, NonCanonicalLocation, MultipleSecrets, SuspiciousContentType, VolumeAnomaly }
    public enum AlertLocation { Header, QueryString, UrlPath, Body }

    /// <summary>Valeurs de fil des énumérations d'alerte, identiques à IRIS (sensibles à la casse).</summary>
    public static class AlertWire
    {
        private static readonly string[] Severities = { "low", "medium", "high" };
        private static readonly string[] Rules = { "hostMismatch", "nonCanonicalLocation", "multipleSecrets", "suspiciousContentType", "volumeAnomaly" };
        private static readonly string[] Locations = { "header", "queryString", "urlPath", "body" };

        public static string SeverityToWire(AlertSeverity s) { return Severities[(int)s]; }
        public static string RuleToWire(ExfilRule r) { return Rules[(int)r]; }
        public static string LocationToWire(AlertLocation l) { return Locations[(int)l]; }
        public static AlertSeverity ParseSeverity(string w) { return (AlertSeverity)IndexOf(Severities, w, "severity"); }
        public static ExfilRule ParseRule(string w) { return (ExfilRule)IndexOf(Rules, w, "rule"); }
        public static AlertLocation ParseLocation(string w) { return (AlertLocation)IndexOf(Locations, w, "detected_at"); }

        internal static int IndexOf(string[] values, string wire, string field)
        {
            int i = Array.IndexOf(values, wire);
            if (i < 0) throw new JsonException(field + " inconnu : " + wire);
            return i;
        }
    }

    /// <summary>Alerte d'exfiltration (SPECS §5.4). Le snippet est pris avant substitution et tronqué à 256 caractères.</summary>
    public sealed class Alert
    {
        public const int SnippetMax = 256;

        public AlertSeverity Severity { get; private set; }
        public ExfilRule Rule { get; private set; }
        public string SecretName { get; private set; }
        public AlertLocation DetectedAt { get; private set; }
        public string Snippet { get; private set; }

        public Alert(AlertSeverity severity, ExfilRule rule, string secretName, AlertLocation detectedAt, string snippet)
        {
            Severity = severity;
            Rule = rule;
            SecretName = secretName;
            DetectedAt = detectedAt;
            Snippet = snippet == null ? "" : (snippet.Length > SnippetMax ? snippet.Substring(0, SnippetMax) : snippet);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["severity"] = AlertWire.SeverityToWire(Severity);
            o["rule"] = AlertWire.RuleToWire(Rule);
            o["secret_name"] = SecretName;
            o["detected_at"] = AlertWire.LocationToWire(DetectedAt);
            o["snippet"] = Snippet;
            return o;
        }

        public static Alert FromJson(JsonObject o)
        {
            return new Alert(AlertWire.ParseSeverity(o.String("severity")), AlertWire.ParseRule(o.String("rule")),
                o.String("secret_name"), AlertWire.ParseLocation(o.String("detected_at")), o.String("snippet"));
        }
    }

    /// <summary>Alerte du daemon sans lien avec une requête (démarrage dégradé) ; même canal que les events.</summary>
    public sealed class SystemAlert
    {
        public AlertSeverity Severity { get; private set; }
        public string Message { get; private set; }

        public SystemAlert(AlertSeverity severity, string message)
        {
            Severity = severity;
            Message = message;
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["severity"] = AlertWire.SeverityToWire(Severity);
            o["message"] = Message;
            return o;
        }

        public static SystemAlert FromJson(JsonObject o)
        {
            return new SystemAlert(AlertWire.ParseSeverity(o.String("severity")), o.String("message"));
        }
    }
}
