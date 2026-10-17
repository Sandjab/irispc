using System;
using System.Collections.Generic;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Modèles ---------------------------------------------------

        private static readonly DateTime T0 = new DateTime(2023, 11, 14, 22, 13, 20, DateTimeKind.Utc); // 1_700_000_000

        private static void Models_HostName()
        {
            foreach (string ok in new[] { "api.anthropic.com", "localhost", "a-b.c1", "x".PadRight(63, 'x') + ".com" })
                Check.True(HostName.IsValid(ok), "hôte valide : " + ok);
            foreach (string bad in new[] { "", "-a.com", "a-.com", "a..b", "a b.com", "_not_a_host_", "é.com", "a:8443", "x".PadRight(64, 'x') + ".com", new string('a', 254) })
                Check.True(!HostName.IsValid(bad), "hôte invalide : " + bad);
            Check.Eq("api.anthropic.com", HostName.Normalize("API.Anthropic.COM:443"), "minuscules, port retiré");
            Check.Eq("api.anthropic.com", HostName.Normalize("  api.anthropic.com "), "espaces retirés");
        }

        private static void Models_SecretValidation()
        {
            Secret.ValidateName("anthropic_api_key");
            Secret.ValidateName("A-b_9");
            foreach (string bad in new[] { "", "a b", "é", "a.b", new string('a', 65) })
            {
                SecretStoreException ex = Check.Throws<SecretStoreException>(delegate { Secret.ValidateName(bad); }, "nom invalide : " + bad);
                Check.Eq(SecretStoreErrorKind.InvalidName, ex.Kind, "kind InvalidName");
            }
            Secret.ValidateAllowedHosts(new[] { "api.anthropic.com" });
            Check.Eq(SecretStoreErrorKind.InvalidAllowedHosts, Check.Throws<SecretStoreException>(delegate { Secret.ValidateAllowedHosts(new string[0]); }, "liste vide").Kind, "vide → InvalidAllowedHosts");
            Check.Eq(SecretStoreErrorKind.InvalidAllowedHosts, Check.Throws<SecretStoreException>(delegate { Secret.ValidateAllowedHosts(new[] { "api.anthropic.com", "bad host" }); }, "hôte invalide").Kind, "hôte invalide → InvalidAllowedHosts");
        }

        private static void Models_SecretJson()
        {
            Secret s = new Secret("anthropic_api_key", new[] { "api.anthropic.com" }, T0, T0.AddSeconds(1000), 42, false);
            string json = Json.EmitCompact(s.ToJson());
            Check.Eq("{\"name\":\"anthropic_api_key\",\"allowed_hosts\":[\"api.anthropic.com\"],\"created_at\":\"2023-11-14T22:13:20Z\",\"last_used_at\":\"2023-11-14T22:30:00Z\",\"usage_count\":42,\"quarantined\":false}", json, "fil IRIS (snake_case, dates ISO)");
            Secret back = Secret.FromJson(Json.ParseObject(json));
            Check.Eq(s.Name, back.Name, "name"); Check.Eq(42L, back.UsageCount, "usage_count");
            Check.Eq(T0.AddSeconds(1000), back.LastUsedAt.Value, "last_used_at");
            Secret noUse = Secret.FromJson(Json.ParseObject("{\"name\":\"k\",\"allowed_hosts\":[\"h.example\"],\"created_at\":\"2023-11-14T22:13:20Z\",\"usage_count\":0}"));
            Check.True(noUse.LastUsedAt == null && !noUse.Quarantined, "last_used_at et quarantined optionnels (fixture IRIS)");
            Check.True(!Json.EmitCompact(noUse.ToJson()).Contains("last_used_at"), "last_used_at omis quand null");
            Secret updated = s.WithAllowedHosts(new[] { "b.example" }).WithUsage(T0.AddDays(1), 43).WithQuarantined(true);
            Check.True(updated.Name == s.Name && updated.CreatedAt == s.CreatedAt && updated.AllowedHosts[0] == "b.example" && updated.UsageCount == 43 && updated.Quarantined, "With… conserve l'identité");
        }

        private static void Models_MITMRule()
        {
            MITMRule r = new MITMRule("api.openai.com", new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), RuleOrigin.Default);
            Check.Eq("{\"host\":\"api.openai.com\",\"created_at\":\"1970-01-01T00:00:00Z\",\"origin\":\"default\"}", Json.EmitCompact(r.ToJson()), "origin sur le fil = default (fixture IRIS testMITMRuleEncodesOriginField)");
            MITMRule back = MITMRule.FromJson(Json.ParseObject("{\"host\":\"api.example.com\",\"created_at\":\"2023-11-14T22:13:20Z\"}"));
            Check.Eq(RuleOrigin.User, back.Origin, "origin absent → user (fixture testHostEntryDecodesWithoutOriginKeyAsUser)");
            Check.Eq(RuleOrigin.User, MITMRule.FromJson(Json.ParseObject("{\"host\":\"h.example\",\"created_at\":\"2023-11-14T22:13:20Z\",\"origin\":\"user\"}")).Origin, "origin user");
            Check.Throws<JsonException>(delegate { MITMRule.FromJson(Json.ParseObject("{\"host\":\"h.example\",\"created_at\":\"2023-11-14T22:13:20Z\",\"origin\":\"toml\"}")); }, "origin inconnu refusé");
        }

        private static void Models_EventWithAlert()
        {
            Alert alert = new Alert(AlertSeverity.High, ExfilRule.HostMismatch, "anthropic_api_key", AlertLocation.Body, "[REDACTED:abcd1234]");
            Event e = new Event(new Guid("11111111-2222-3333-4444-555555555555"), T0, EventKind.ExfilBlocked, "api.github.com", "POST", "/repos/foo/bar/issues", 201, 423, new string[0], alert, null, EventFlags.None);
            string json = Json.EmitCompact(e.ToJson());
            Check.Eq("{\"id\":\"11111111-2222-3333-4444-555555555555\",\"timestamp\":\"2023-11-14T22:13:20Z\",\"kind\":\"exfilBlocked\",\"host\":\"api.github.com\",\"method\":\"POST\",\"path\":\"/repos/foo/bar/issues\",\"status_code\":201,\"duration_ms\":423,\"substituted_secrets\":[],\"alert\":{\"severity\":\"high\",\"rule\":\"hostMismatch\",\"secret_name\":\"anthropic_api_key\",\"detected_at\":\"body\",\"snippet\":\"[REDACTED:abcd1234]\"}}", json, "fil IRIS (fixture testEventRoundTripWithAlert)");
            Event back = Event.FromJson(Json.ParseObject(json));
            Check.True(back.Id == e.Id && back.Kind == EventKind.ExfilBlocked && back.StatusCode == 201 && back.DurationMs == 423, "scalaires relus");
            Check.True(back.Alert != null && back.Alert.Rule == ExfilRule.HostMismatch && back.Alert.DetectedAt == AlertLocation.Body && back.SystemAlert == null, "alert relue");
            Check.Eq(EventFlags.None, back.Flags, "pas de flags");
        }

        private static void Models_EventSystemAlertAndFlags()
        {
            Event sys = new Event(new Guid("22222222-3333-4444-5555-666666666666"), T0, EventKind.SystemAlert, "config", "-", "-", null, null, new string[0], null, new SystemAlert(AlertSeverity.High, "config.json corrupted — defaults re-seeded"), EventFlags.None);
            string json = Json.EmitCompact(sys.ToJson());
            Check.True(json.Contains("\"kind\":\"systemAlert\"") && json.Contains("\"system_alert\":{\"severity\":\"high\",\"message\":\"config.json corrupted — defaults re-seeded\"}") && !json.Contains("status_code") && !json.Contains("\"alert\""), "system_alert émis, optionnels nuls omis");
            Event back = Event.FromJson(Json.ParseObject(json));
            Check.True(back.SystemAlert != null && back.SystemAlert.Severity == AlertSeverity.High && back.Alert == null, "system_alert relu");

            Event flagged = new Event(Guid.NewGuid(), T0, EventKind.NoMatch, "h.example", "GET", "/", 200, 5, new string[0], null, null, EventFlags.BodyTooLarge | EventFlags.Paused);
            string fjson = Json.EmitCompact(flagged.ToJson());
            Check.True(fjson.Contains("\"flags\":[\"bodyTooLarge\",\"paused\"]"), "flags émis en tableau de chaînes");
            Check.Eq(EventFlags.BodyTooLarge | EventFlags.Paused, Event.FromJson(Json.ParseObject(fjson)).Flags, "flags relus");

            Event old = Event.FromJson(Json.ParseObject("{\"id\":\"33333333-4444-5555-6666-777777777777\",\"timestamp\":\"2023-11-14T22:13:20Z\",\"kind\":\"substituted\",\"host\":\"api.anthropic.com\",\"method\":\"POST\",\"path\":\"/v1/messages\",\"substituted_secrets\":[]}"));
            Check.True(old.Alert == null && old.SystemAlert == null && old.StatusCode == null && old.Flags == EventFlags.None, "fixture IRIS sans system_alert ni flags");
        }

        private static void Models_EnumWire()
        {
            string[] kinds = { "substituted", "passThrough", "noMatch", "exfilBlocked", "error", "systemAlert", "pluginBlocked", "pluginResponded" };
            foreach (string k in kinds) Check.Eq(k, EventWire.KindToWire(EventWire.ParseKind(k)), "kind " + k);
            Check.Throws<JsonException>(delegate { EventWire.ParseKind("Substituted"); }, "kind sensible à la casse");
            foreach (string r in new[] { "hostMismatch", "nonCanonicalLocation", "multipleSecrets", "suspiciousContentType", "volumeAnomaly" })
                Check.Eq(r, AlertWire.RuleToWire(AlertWire.ParseRule(r)), "rule " + r);
            foreach (string l in new[] { "header", "queryString", "urlPath", "body" })
                Check.Eq(l, AlertWire.LocationToWire(AlertWire.ParseLocation(l)), "location " + l);
            Check.True(AlertSeverity.Low < AlertSeverity.Medium && AlertSeverity.Medium < AlertSeverity.High, "sévérités ordonnées");
            Check.Eq("[REDACTED:abcd1234]", new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, "k", AlertLocation.Header, "[REDACTED:abcd1234]").Snippet, "snippet conservé");
            Check.Eq(256, new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, "k", AlertLocation.Header, new string('x', 300)).Snippet.Length, "snippet tronqué à 256");
        }
    }
}
