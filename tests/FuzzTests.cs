using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>Une requête synthétique pour le pipeline scan → règles → substitution.</summary>
    public sealed class FuzzInput
    {
        public HttpHeaders Headers;
        public string Uri;
        public byte[] Body;
        public string Label;

        public FuzzInput(HttpHeaders headers, string uri, byte[] body, string label)
        {
            Headers = headers; Uri = uri; Body = body; Label = label;
        }
    }

    /// <summary>SplitMix64 : même graine → même corpus, aucun test instable.</summary>
    public sealed class SeededGenerator
    {
        private ulong state;
        public SeededGenerator(ulong seed) { state = seed; }

        public ulong Next()
        {
            state += 0x9E3779B97F4A7C15UL;
            ulong z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }

        public int NextInt(int maxExclusive) { return (int)(Next() % (ulong)maxExclusive); }
    }

    /// <summary>Corpus adverse repris de ../Iris/Tests/IrisKitTests/Fuzzing/AdversarialInputGenerator.swift.</summary>
    public static class AdversarialInputGenerator
    {
        public const ulong Seed = 0xD1CE5EED17152026UL;
        public const string KnownSecretName = "leaky";
        public const string Sentinel = "SENTINEL_VALUE_DO_NOT_LEAK_7Q3Z";
        private const string CanonicalHeader = "x-api-key";
        private const string KnownPlaceholder = "{{kc:" + KnownSecretName + "}}";

        private static HttpHeaders Hdr(params string[] pairs)
        {
            HttpHeaders h = new HttpHeaders();
            for (int i = 0; i + 1 < pairs.Length; i += 2) h.Add(pairs[i], pairs[i + 1]);
            return h;
        }

        private static string Repeat(string s, int n) { StringBuilder sb = new StringBuilder(); for (int i = 0; i < n; i++) sb.Append(s); return sb.ToString(); }

        public static IList<FuzzInput> NamedCorpus()
        {
            return new List<FuzzInput> {
                new FuzzInput(Hdr(CanonicalHeader, "Bearer {{kc:" + new string('a', 65) + "}}"), "/v1/messages", null, "name-too-long"),
                new FuzzInput(Hdr(CanonicalHeader, "Bearer {{kc:" + new string('a', 64) + "}}"), "/v1/messages", null, "name-at-limit"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:}}"), "/v1/messages", null, "name-empty"),
                new FuzzInput(Hdr(CanonicalHeader, Repeat(KnownPlaceholder, 5000)), "/v1/messages", null, "thousands-occurrences"),
                new FuzzInput(Hdr(CanonicalHeader, "{{ {{kc {{kc: kc:x}} }}}} {{"), "/v1/messages", null, "unbalanced-braces"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:{{kc:" + KnownSecretName + "}}}}"), "/v1/messages", null, "nested-placeholder"),
                new FuzzInput(Hdr(CanonicalHeader, KnownPlaceholder), "/v1/messages", new byte[] { 0xFF, 0xFE, 0x00, 0x80, 0xC0, 0x01 }, "non-utf8-body"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:\u0000\u0001\u007F}}"), "/v1/\u0000messages", null, "control-chars"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:\u0430\u0501\u200Bname}}"), "/v1/messages", null, "unicode-name"),
                new FuzzInput(Hdr("X-API-KEY", KnownPlaceholder, "AUTHORIZATION", KnownPlaceholder), "/v1/messages", null, "mixed-case-headers"),
            };
        }

        private static readonly string[] Fragments = {
            KnownPlaceholder, "{{kc:}}", "{{kc:" + new string('z', 70) + "}}", "{{kc", "kc:}}", "}}{{",
            "{{kc:{{kc:" + KnownSecretName + "}}}}", "{{kc:\u0000}}", "{{kc:\u200B\u0430}}", "{{KC:" + KnownSecretName + "}}",
            "{{kc:a-b_c}}", "  {{kc:" + KnownSecretName + "}}  ",
        };

        public static IList<FuzzInput> Generate(int count)
        {
            SeededGenerator gen = new SeededGenerator(Seed);
            List<FuzzInput> list = new List<FuzzInput>(count);
            for (int i = 0; i < count; i++)
            {
                string payload = Repeat(Fragments[gen.NextInt(Fragments.Length)], 1 + gen.NextInt(4));
                switch (gen.NextInt(5))
                {
                    case 0: list.Add(new FuzzInput(Hdr(CanonicalHeader, payload), "/v1/messages", null, "gen-" + i + "-canonical-header")); break;
                    case 1: list.Add(new FuzzInput(Hdr("x-custom-" + (i % 7), payload), "/v1/messages", null, "gen-" + i + "-random-header")); break;
                    case 2: list.Add(new FuzzInput(Hdr(), "/v1/" + payload + "/messages", null, "gen-" + i + "-url-path")); break;
                    case 3: list.Add(new FuzzInput(Hdr(), "/v1/messages?token=" + payload, null, "gen-" + i + "-query")); break;
                    default: list.Add(new FuzzInput(Hdr("content-type", "application/json"), "/v1/messages", Encoding.UTF8.GetBytes(payload), "gen-" + i + "-body")); break;
                }
            }
            return list;
        }
    }

    public static partial class TestMain
    {
        // ---- Fuzzing (I1 robustesse, I2 aucune valeur dans les events, I3 aucune substitution hors scope) ----

        private const int FuzzIterations = 2000;
        private static readonly UTF8Encoding FuzzUtf8 = new UTF8Encoding(false, true);

        private sealed class PipelineResult { public ExfilDecision Decision; public ResolvedPayload Payload; }

        private static InMemorySecretStore FuzzStore(params string[] allowedHosts)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync(AdversarialInputGenerator.KnownSecretName, Bytes(AdversarialInputGenerator.Sentinel), allowedHosts, T0));
            return store;
        }

        private static string BodyText(byte[] body)
        {
            if (body == null) return null;
            try { return FuzzUtf8.GetString(body); } catch (DecoderFallbackException) { return null; }
        }

        private static IList<FuzzInput> AllFuzzInputs()
        {
            List<FuzzInput> all = new List<FuzzInput>(AdversarialInputGenerator.NamedCorpus());
            all.AddRange(AdversarialInputGenerator.Generate(FuzzIterations));
            return all;
        }

        /// <summary>Le vrai pipeline, comme MITMHandler : scan → EvaluateAsync → SubstituteAsync.</summary>
        private static PipelineResult RunPipeline(FuzzInput input, InMemorySecretStore store, string host)
        {
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(input.Headers, input.Uri, BodyText(input.Body));
            ExfilRuleEngine engine = new ExfilRuleEngine(store, delegate { return 100000; }, delegate { return T0; });
            string path, query;
            PlaceholderScanner.SplitUri(input.Uri, out path, out query);
            PipelineResult r = new PipelineResult();
            r.Decision = Wait(engine.EvaluateAsync(hits, new RequestContext(host, "POST", path, "application/json")));
            if (!r.Decision.Blocked)
                r.Payload = Wait(new PlaceholderEngine(store).SubstituteAsync(input.Headers, input.Uri, input.Body, r.Decision.Resolvable));
            return r;
        }

        private static void Fuzz_ScanBoundedAndPipelineNeverThrows()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            int n = 0;
            foreach (FuzzInput input in AllFuzzInputs())
            {
                string body = BodyText(input.Body);
                IList<PlaceholderHit> hits = PlaceholderScanner.Scan(input.Headers, input.Uri, body);
                int chars = input.Uri.Length + (body == null ? 0 : body.Length);
                foreach (HttpHeader h in input.Headers) chars += h.Name.Length + h.Value.Length;
                if (hits.Count > chars + 1) Check.True(false, "nombre de hits non borné pour " + input.Label);
                RunPipeline(input, store, "api.anthropic.com");
                n++;
            }
            Check.Eq(FuzzIterations + 10, n, "corpus complet parcouru sans exception");
        }

        private static void Fuzz_SentinelNeverInEncodedEvent()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            foreach (FuzzInput input in AllFuzzInputs())
            {
                PipelineResult r = RunPipeline(input, store, "api.anthropic.com");
                Event e;
                if (r.Decision.Blocked)
                    e = new Event(Guid.NewGuid(), T0, EventKind.ExfilBlocked, "api.anthropic.com", "POST", input.Uri, null, null, new string[0], r.Decision.Alert, null, EventFlags.None);
                else
                    e = new Event(Guid.NewGuid(), T0, r.Payload.Substituted.Count == 0 ? EventKind.NoMatch : EventKind.Substituted, "api.anthropic.com", "POST", input.Uri, null, null, r.Payload.Substituted, null, null, EventFlags.None);
                string json = Json.EmitCompact(e.ToJson());
                if (json.Contains(AdversarialInputGenerator.Sentinel)) Check.True(false, "la valeur sentinelle fuit dans l'event pour " + input.Label);
            }
            Check.True(true, "aucune fuite sur " + (FuzzIterations + 10) + " entrées");
        }

        private static void Fuzz_OutOfScopeNeverSubstituted()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            HttpHeaders none = new HttpHeaders();
            HttpHeaders canonical = new HttpHeaders(); canonical.Add("x-api-key", "{{kc:leaky}}");
            HttpHeaders evil = new HttpHeaders(); evil.Add("x-evil-header", "{{kc:leaky}}");
            PipelineResult r = RunPipeline(new FuzzInput(canonical, "/v1/messages", null, "r1-host-mismatch"), store, "evil.example.com");
            Check.True(r.Decision.Blocked && r.Payload == null, "R1 : hôte hors scope → bloqué, rien substitué");
            r = RunPipeline(new FuzzInput(evil, "/v1/messages", null, "r2-non-canonical-header"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : en-tête non canonique → bloqué");
            r = RunPipeline(new FuzzInput(none, "/v1/{{kc:leaky}}/messages", null, "r2-url-path"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : chemin → bloqué");
            r = RunPipeline(new FuzzInput(none, "/v1/messages?token={{kc:leaky}}", null, "r2-query-string"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : query → bloqué");
            r = RunPipeline(new FuzzInput(canonical, "/v1/messages", null, "in-scope-canonical"), store, "api.anthropic.com");
            Check.True(!r.Decision.Blocked && string.Join(",", r.Payload.Substituted) == AdversarialInputGenerator.KnownSecretName, "dans le scope et canonique → substitué");
            Check.Eq(AdversarialInputGenerator.Sentinel, r.Payload.Headers.First("x-api-key"), "la valeur réelle est dans l'en-tête réécrit (et nulle part ailleurs)");
        }
    }
}
