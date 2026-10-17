using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;

namespace IrisKit
{
    /// <summary>Métadonnées d'un secret (SPECS §5.1). La valeur n'en fait jamais partie.</summary>
    public sealed class Secret
    {
        public static readonly Regex NameRegex = new Regex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.CultureInvariant);

        public string Name { get; private set; }
        public IList<string> AllowedHosts { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime? LastUsedAt { get; private set; }
        public long UsageCount { get; private set; }
        public bool Quarantined { get; private set; }

        public Secret(string name, IList<string> allowedHosts, DateTime createdAt, DateTime? lastUsedAt, long usageCount, bool quarantined)
        {
            Name = name;
            AllowedHosts = new List<string>(allowedHosts).AsReadOnly();
            CreatedAt = createdAt;
            LastUsedAt = lastUsedAt;
            UsageCount = usageCount;
            Quarantined = quarantined;
        }

        public Secret WithAllowedHosts(IList<string> allowedHosts) { return new Secret(Name, allowedHosts, CreatedAt, LastUsedAt, UsageCount, Quarantined); }
        public Secret WithUsage(DateTime lastUsedAt, long usageCount) { return new Secret(Name, AllowedHosts, CreatedAt, lastUsedAt, usageCount, Quarantined); }
        public Secret WithQuarantined(bool quarantined) { return new Secret(Name, AllowedHosts, CreatedAt, LastUsedAt, UsageCount, quarantined); }

        // ---- Validation --------------------------------------------------

        public static void ValidateName(string name)
        {
            if (name == null || !NameRegex.IsMatch(name))
                throw new SecretStoreException(SecretStoreErrorKind.InvalidName, name, "nom de secret invalide : " + (name ?? "null") + " (attendu : ^[a-zA-Z0-9_-]{1,64}$)");
        }

        public static void ValidateAllowedHosts(IList<string> hosts)
        {
            if (hosts == null || hosts.Count == 0)
                throw new SecretStoreException(SecretStoreErrorKind.InvalidAllowedHosts, null, "allowed_hosts ne peut pas être vide");
            foreach (string host in hosts)
                if (!HostName.IsValid(host))
                    throw new SecretStoreException(SecretStoreErrorKind.InvalidAllowedHosts, null, "hôte invalide dans allowed_hosts : " + host);
        }

        // ---- JSON --------------------------------------------------------

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["name"] = Name;
            o["allowed_hosts"] = new List<string>(AllowedHosts);
            o["created_at"] = CreatedAt;
            if (LastUsedAt.HasValue) o["last_used_at"] = LastUsedAt.Value;
            o["usage_count"] = UsageCount;
            o["quarantined"] = Quarantined;
            return o;
        }

        public static Secret FromJson(JsonObject o)
        {
            string lastUsed = o.OptionalString("last_used_at");
            return new Secret(
                o.String("name"),
                o.StringArray("allowed_hosts"),
                Json.ParseDate(o.String("created_at")),
                lastUsed == null ? (DateTime?)null : Json.ParseDate(lastUsed),
                o.Int("usage_count"),
                o.Bool("quarantined", false));
        }
    }
}
