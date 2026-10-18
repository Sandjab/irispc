using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Placeholders --------------------------------------------------

        private static HttpHeaders H(params string[] pairs)
        {
            HttpHeaders h = new HttpHeaders();
            for (int i = 0; i + 1 < pairs.Length; i += 2) h.Add(pairs[i], pairs[i + 1]);
            return h;
        }

        private static string Names(IList<PlaceholderHit> hits)
        {
            List<string> names = new List<string>();
            foreach (PlaceholderHit h in hits) names.Add(h.Name);
            return string.Join(",", names);
        }

        private static void Scanner_Locations()
        {
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}"), "/v1/messages", null);
            Check.Eq(1, hits.Count, "un hit");
            Check.Eq("foo", hits[0].Name, "nom");
            Check.True(hits[0].Location.Equals(HitLocation.Header("authorization")), "en-tête, nom en minuscules");
            Check.Eq(AlertLocation.Header, hits[0].Location.ToAlertLocation(), "→ AlertLocation.Header");
            hits = PlaceholderScanner.Scan(H("X-{{kc:foo}}", "bar"), "/", null);
            Check.True(hits.Count == 1 && hits[0].Location.HeaderName.Contains("{{kc:foo}}"), "placeholder dans un nom d'en-tête");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/foo/{{kc:bar}}/baz", null);
            Check.True(hits.Count == 1 && hits[0].Location.Kind == HitLocationKind.UrlPath, "chemin");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/foo?key={{kc:bar}}", null);
            Check.True(hits.Count == 1 && hits[0].Location.Equals(HitLocation.QueryString), "query");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", "{\"key\":\"{{kc:bar}}\"}");
            Check.True(hits.Count == 1 && hits[0].Location.Equals(HitLocation.Body), "corps");
            hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}"), "/foo?x={{kc:foo}}", null);
            Check.Eq("foo,foo", Names(hits), "même secret à deux endroits = deux hits");
            hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}", "X-Other", "{{kc:bar}}"), "/", null);
            Check.Eq("foo,bar", Names(hits), "deux secrets distincts, ordre des en-têtes");
            hits = PlaceholderScanner.Scan(H("X-API-KEY", "{{kc:foo}}"), "/", null);
            Check.Eq("x-api-key", hits[0].Location.HeaderName, "nom d'en-tête en minuscules dans la localisation");
            Check.Eq("header(x-api-key)", hits[0].Location.Describe(), "Describe");
            string path, query;
            PlaceholderScanner.SplitUri("/a/b?c=1&d=2", out path, out query);
            Check.True(path == "/a/b" && query == "c=1&d=2", "SplitUri");
            PlaceholderScanner.SplitUri("/a", out path, out query);
            Check.True(path == "/a" && query == null, "SplitUri sans query");
            Check.Eq("a,b,c", string.Join(",", PlaceholderScanner.FindPlaceholderNames("{{kc:a}}-{{kc:b}}-{{kc:a}}-{{kc:c}}")), "FindPlaceholderNames : distincts, ordonnés");
            Check.Eq("ok", string.Join(",", PlaceholderScanner.FindPlaceholderNames("{{kc:}}-{{kc:has space}}-{kc:foo}}-{{kc:ok}}")), "malformés ignorés");
        }

        private static void Scanner_InvalidNamesAndSnippets()
        {
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:}}"), "/", null).Count, "nom vide ignoré");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:" + new string('a', 65) + "}}"), "/", null).Count, "nom de 65 caractères ignoré");
            Check.Eq(1, PlaceholderScanner.Scan(H("X", "{{kc:" + new string('a', 64) + "}}"), "/", null).Count, "nom de 64 caractères accepté");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{KC:foo}}"), "/", null).Count, "préfixe sensible à la casse");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:\u0430\u0501\u200Bname}}"), "/", null).Count, "lettres non ASCII refusées");
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}} suffix"), "/", null);
            Check.True(hits[0].Snippet.Contains("{{kc:foo}}") && hits[0].Snippet.Length <= 256, "snippet contient le placeholder littéral, ≤ 256");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", "\u0001\u0007prefix {{kc:foo}} suffix\u007F");
            Check.True(!hits[0].Snippet.Contains("\u0001") && !hits[0].Snippet.Contains("\u0007") && !hits[0].Snippet.Contains("\u007F") && hits[0].Snippet.Contains("?") && hits[0].Snippet.Contains("{{kc:foo}}"), "caractères de contrôle remplacés par ?");
            string longBody = new string('x', 500) + "{{kc:foo}}" + new string('y', 500);
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", longBody);
            Check.True(hits[0].Snippet.Length <= 256 && hits[0].Snippet.StartsWith("xxxx") && hits[0].Snippet.Contains("{{kc:foo}}"), "80 caractères de contexte de chaque côté");
            hits = PlaceholderScanner.Scan(H("X", "{{kc:{{kc:foo}}}}"), "/", null);
            Check.Eq("foo", Names(hits), "imbriqué : seul le motif interne valide");
            hits = PlaceholderScanner.Scan(H("X", "{{ {{kc {{kc: kc:x}} }}}} {{"), "/", null);
            Check.Eq(0, hits.Count, "accolades déséquilibrées : rien");
        }

        private static void Counter_SlidingMinute()
        {
            SlidingMinuteCounter c = new SlidingMinuteCounter();
            DateTime t0 = new DateTime(2026, 10, 17, 12, 0, 0, DateTimeKind.Utc);
            Check.Eq(0, c.Count(t0), "vide");
            c.Record(t0);
            Check.Eq(1, c.Count(t0), "un enregistrement");
            Check.Eq(1, c.Count(t0.AddSeconds(59)), "gardé à 59 s");
            Check.Eq(1, c.Count(t0.AddSeconds(60)), "gardé à 60 s (fenêtre inclusive)");
            Check.Eq(0, c.Count(t0.AddMilliseconds(60001)), "retiré juste après");
            c = new SlidingMinuteCounter();
            c.Record(t0); c.Record(t0.AddSeconds(30)); c.Record(t0.AddSeconds(60));
            Check.Eq(3, c.Count(t0.AddSeconds(60)), "trois dans la fenêtre");
            Check.Eq(2, c.Count(t0.AddSeconds(61)), "t0 expiré");
            Check.Eq(1, c.Count(t0.AddSeconds(91)), "t0+30 expiré");
            Check.Eq(0, c.Count(t0.AddSeconds(121)), "tout expiré");
        }

        private static InMemorySecretStore StoreWith(params string[] nameValuePairs)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            for (int i = 0; i + 1 < nameValuePairs.Length; i += 2)
                Wait(store.AddAsync(nameValuePairs[i], Bytes(nameValuePairs[i + 1]), new[] { "example.com" }, T0));
            return store;
        }

        private static PlaceholderHit Hit(string name, HitLocation location) { return new PlaceholderHit(name, location, ""); }

        private static void Engine_SubstitutesOnlyAuthorized()
        {
            PlaceholderEngine engine = new PlaceholderEngine(StoreWith("foo", "VALUE_FOO", "bar", "VALUE_BAR"));
            ResolvedPayload p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:foo}}", "X-Other", "{{kc:bar}}"), "/v1/messages", null,
                new[] { Hit("foo", HitLocation.Header("authorization")) }));
            Check.Eq("foo", string.Join(",", p.Substituted), "seul foo est substitué");
            Check.Eq("Bearer VALUE_FOO", p.Headers.First("Authorization"), "valeur substituée");
            Check.Eq("{{kc:bar}}", p.Headers.First("X-Other"), "bar non autorisé reste littéral");
            Check.True(p.Body == null, "corps absent inchangé");
            p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:foo}}"), "/v1", null, new PlaceholderHit[0]));
            Check.True(p.Substituted.Count == 0 && p.Headers.First("Authorization") == "Bearer {{kc:foo}}", "sans hit autorisé : verbatim");
            p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:k}}", "X-Echo", "{{kc:k}}"), "/x?t={{kc:k}}", Bytes("{\"t\":\"{{kc:k}}\"}"),
                new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.True(p.Substituted.Count == 0 && p.Unresolved.Count == 1 && p.Unresolved[0] == "k", "nom inconnu → Unresolved, rien substitué");
        }

        private static void Engine_AllOccurrencesBodyUriAndCache()
        {
            InMemorySecretStore inner = StoreWith("k", "V");
            SecretCache cached = new SecretCache(inner);
            PlaceholderEngine engine = new PlaceholderEngine(cached);
            ResolvedPayload p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:k}}", "X-Echo", "{{kc:k}}"), "/x?t={{kc:k}}", Bytes("{\"t\":\"{{kc:k}}\"}"),
                new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.Eq("k", string.Join(",", p.Substituted), "signalé une fois malgré quatre occurrences");
            Check.Eq("Bearer V", p.Headers.First("Authorization"), "en-tête 1");
            Check.Eq("V", p.Headers.First("X-Echo"), "en-tête 2");
            Check.Eq("/x?t=V", p.Uri, "URI");
            Check.Eq("{\"t\":\"V\"}", Encoding.UTF8.GetString(p.Body), "corps");
            Wait(inner.RotateAsync("k", Bytes("V2")));
            p = Wait(engine.SubstituteAsync(H("Authorization", "{{kc:k}}"), "/", null, new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.Eq("V", p.Headers.First("Authorization"), "le cache sert la valeur résolue dans le TTL (rotation faite sous le cache)");
            byte[] body = new byte[] { 0x00, 0xff, 0x01 };
            p = Wait(engine.SubstituteAsync(H("x-api-key", "{{kc:k}}"), "/", body, new[] { Hit("k", HitLocation.Header("x-api-key")) }));
            Check.Eq(Convert.ToBase64String(body), Convert.ToBase64String(p.Body), "corps non UTF-8 jamais réécrit");
            Check.Eq("V", p.Headers.First("x-api-key"), "mais l'en-tête est substitué");
            InMemorySecretStore bin = new InMemorySecretStore();
            Wait(bin.AddAsync("binkey", new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }, new[] { "api.x" }, T0));
            p = Wait(new PlaceholderEngine(bin).SubstituteAsync(H("Authorization", "Bearer {{kc:binkey}}"), "/", null, new[] { Hit("binkey", HitLocation.Header("authorization")) }));
            Check.True(p.Substituted.Count == 0 && p.Unresolved.Count == 1 && p.Unresolved[0] == "binkey" && p.Headers.First("Authorization") == "Bearer {{kc:binkey}}", "valeur non UTF-8 → Unresolved, placeholder intact");
            p = Wait(engine.SubstituteAsync(H("Authorization", "é {{kc:k}} ✓"), "/", Bytes("héllo {{kc:k}}"), new[] { Hit("k", HitLocation.Body) }));
            Check.True(p.Headers.First("Authorization") == "é V ✓" && Encoding.UTF8.GetString(p.Body) == "héllo V", "texte non ASCII autour conservé");
        }
    }
}
