using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- ExfilRuleEngine --------------------------------------------------

        private static DateTime exfilNow;

        private static ExfilRuleEngine Evaluator(int maxPerMinute, params string[] nameHostPairs)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            for (int i = 0; i + 1 < nameHostPairs.Length; i += 2)
                Wait(store.AddAsync(nameHostPairs[i], Bytes("v"), nameHostPairs[i + 1].Split('|'), T0));
            exfilNow = T0;
            return new ExfilRuleEngine(store, delegate { return maxPerMinute; }, delegate { return exfilNow; });
        }

        private static RequestContext Ctx(string host, string method, string path, string contentType)
        {
            return new RequestContext(host, method, path, contentType);
        }

        private static RequestContext CtxAnthropic() { return Ctx("api.anthropic.com", "POST", "/v1/messages", "application/json"); }

        private static ExfilDecision Eval(ExfilRuleEngine ev, RequestContext ctx, params PlaceholderHit[] hits)
        {
            return Wait(ev.EvaluateAsync(hits, ctx));
        }

        private static void Exfil_R1_HostMismatch()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com");
            PlaceholderHit hit = new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}");
            ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", "/v1/messages", "application/json"), hit);
            Check.True(d.Blocked, "hôte hors allowed_hosts → bloqué");
            Check.Eq(ExfilRule.HostMismatch, d.Alert.Rule, "R1");
            Check.Eq(AlertSeverity.High, d.Alert.Severity, "high");
            Check.Eq("foo", d.Alert.SecretName, "nom");
            Check.Eq(AlertLocation.Header, d.Alert.DetectedAt, "emplacement");
            Check.Eq("{{kc:foo}}", d.Alert.Snippet, "snippet du hit");
            Check.Eq(1, d.AllHits.Count, "tous les hits rendus");
            d = Eval(ev, CtxAnthropic(), hit);
            Check.True(!d.Blocked && d.Resolvable.Count == 1 && d.Resolvable[0].Name == "foo", "hôte autorisé → résoluble");
            d = Eval(ev, Ctx("api.anthropic.com:443", "POST", "/v1/messages", null), hit);
            Check.True(!d.Blocked, "port retiré avant comparaison");
            d = Eval(ev, Ctx("API.Anthropic.com", "POST", "/v1/messages", null), hit);
            Check.True(!d.Blocked, "comparaison insensible à la casse");
            d = Eval(Evaluator(60), CtxAnthropic(), new PlaceholderHit("ghost", HitLocation.Header("authorization"), "{{kc:ghost}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "secret inconnu : ni bloqué ni résoluble");
            d = Eval(ev, CtxAnthropic());
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "aucun hit → allow vide");
        }

        private static void Exfil_R2_NonCanonicalLocation()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com");
            ExfilDecision d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Header("x-custom"), "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.Severity == AlertSeverity.High, "en-tête non canonique");
            foreach (string header in new[] { "authorization", "x-api-key", "api-key", "x-auth-token", "X-API-Key", "AUTHORIZATION" })
            {
                d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Header(header), "{{kc:foo}}"));
                Check.True(!d.Blocked, header + " est canonique (insensible à la casse)");
            }
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.UrlPath, "/{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.DetectedAt == AlertLocation.UrlPath, "chemin");
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.QueryString, "?x={{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.DetectedAt == AlertLocation.QueryString, "query");
            d = Eval(ev, Ctx("api.anthropic.com", "GET", "/v1/messages", "application/json"), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation, "corps sur GET");
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation, "corps JSON sur POST vers l'hôte autorisé : bloqué (A2)");
        }

        private static void Exfil_R3_MultipleSecrets()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com", "bar", "api.anthropic.com");
            ExfilDecision d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("bar", HitLocation.Header("x-api-key"), "{{kc:bar}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.MultipleSecrets && d.Alert.Severity == AlertSeverity.Medium, "deux secrets connus distincts");
            Check.Eq("bar", d.Alert.SecretName, "nom déclencheur = premier par ordre alphabétique");
            Check.Eq("foo,bar", Names(d.AllHits), "tous les hits dans l'ordre");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("foo", HitLocation.Header("x-api-key"), "{{kc:foo}}"));
            Check.True(!d.Blocked, "même nom deux fois : pas R3");
            ev = Evaluator(60, "foo", "api.anthropic.com");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("ghost", HitLocation.Header("x-api-key"), "{{kc:ghost}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "foo", "un connu + un inconnu : pas R3, seul le connu est résoluble");
        }

        private static void Exfil_R4_BehindR2()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.github.com");
            foreach (string[] c in new[] {
                new[] { "/repos/x/y/issues", "text/plain" }, new[] { "/comments/123", "application/x-www-form-urlencoded" },
                new[] { "/repos/x/y/blob/main", "multipart/form-data" }, new[] { "/issues", "text/plain; charset=utf-8" },
                new[] { "/issues", null }, new[] { "/v1/complete", "text/plain" }, new[] { "/issues", "application/json" } })
            {
                ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", c[0], c[1]), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
                Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.DetectedAt == AlertLocation.Body, "corps connu → R2 préempte R4 : " + c[0] + " " + c[1]);
            }
            ExfilDecision allow = Eval(ev, Ctx("api.github.com", "POST", "/issues", "text/plain"), new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"));
            Check.True(!allow.Blocked, "sans hit dans le corps, R4 ne tire pas");
            allow = Eval(ev, Ctx("api.github.com", "POST", "/issues", "text/plain"), new PlaceholderHit("ghost", HitLocation.Body, "{{kc:ghost}}"));
            Check.True(!allow.Blocked, "nom inconnu dans un corps suspect : rien (R2 et R4 clés sur les connus)");
        }

        private static void Exfil_R5_VolumeAnomaly()
        {
            ExfilRuleEngine ev = Evaluator(3, "foo", "api.anthropic.com");
            PlaceholderHit hit = new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}");
            for (int i = 0; i < 3; i++)
            {
                Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "substitution " + (i + 1) + " autorisée");
                ev.RecordSubstitution(new[] { "foo" });
            }
            ExfilDecision d = Eval(ev, CtxAnthropic(), hit);
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.VolumeAnomaly && d.Alert.Severity == AlertSeverity.Low && d.Alert.SecretName == "foo", "4e dans la minute → R5");
            exfilNow = T0.AddSeconds(61);
            Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "fenêtre glissée : de nouveau autorisé");
            ev = Evaluator(2, "foo", "api.anthropic.com");
            for (int i = 0; i < 5; i++) Eval(ev, Ctx("api.evil.com", "POST", "/", null), hit);
            Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "les blocages R1 n'incrémentent pas R5");
        }

        private static void Exfil_CompositionAndQuarantine()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com", "bar", "api.anthropic.com");
            ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", "/v1/messages", "application/json"),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("bar", HitLocation.Header("x-api-key"), "{{kc:bar}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.HostMismatch && d.Alert.Severity == AlertSeverity.High && d.AllHits.Count == 2, "R1 gagne sur R3 (ordre = sévérité décroissante)");
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync("active", Bytes("v"), new[] { "api.anthropic.com" }, T0));
            Wait(store.AddAsync("quar", Bytes("v"), new[] { "api.anthropic.com" }, T0));
            Wait(store.SetQuarantinedAsync("quar", true));
            ev = new ExfilRuleEngine(store, delegate { return 60; }, delegate { return T0; });
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "en quarantaine sur hôte autorisé : non résoluble");
            d = Eval(ev, Ctx("api.github.com", "POST", "/", null), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "en quarantaine sur hôte interdit : inerte, pas de R1");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("active", HitLocation.Header("authorization"), "{{kc:active}}"),
                new PlaceholderHit("quar", HitLocation.Header("x-api-key"), "{{kc:quar}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "active", "quarantaine ne compte pas pour R3");
            Wait(store.SetQuarantinedAsync("quar", false));
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "quar", "levée de quarantaine : de nouveau résoluble");
        }
    }
}
