using System;
using System.Collections.Specialized;

namespace IrisKit
{
    /// <summary>Origine d'une règle MITM : `default` (semée, protégée) ou `user` (ajoutée par rule.add).</summary>
    public enum RuleOrigin { Default, User }

    public static class RuleOriginWire
    {
        public static string ToWire(RuleOrigin origin) { return origin == RuleOrigin.Default ? "default" : "user"; }

        public static RuleOrigin Parse(string wire)
        {
            if (wire == "default") return RuleOrigin.Default;
            if (wire == "user") return RuleOrigin.User;
            throw new JsonException("origin inconnue : " + wire);
        }
    }

    /// <summary>Hôte whitelisté pour le MITM (SPECS §5.2) ; sert aussi d'entrée `hosts[]` de config.json.</summary>
    public sealed class MITMRule
    {
        public string Host { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public RuleOrigin Origin { get; private set; }

        public MITMRule(string host, DateTime createdAt, RuleOrigin origin)
        {
            Host = host;
            CreatedAt = createdAt;
            Origin = origin;
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["host"] = Host;
            o["created_at"] = CreatedAt;
            o["origin"] = RuleOriginWire.ToWire(Origin);
            return o;
        }

        /// <summary>Tolérant comme IRIS : `origin` absent vaut `user`.</summary>
        public static MITMRule FromJson(JsonObject o)
        {
            string origin = o.OptionalString("origin");
            return new MITMRule(o.String("host"), Json.ParseDate(o.String("created_at")),
                origin == null ? RuleOrigin.User : RuleOriginWire.Parse(origin));
        }
    }
}
