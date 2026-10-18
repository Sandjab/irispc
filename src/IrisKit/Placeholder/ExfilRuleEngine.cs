using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    public sealed class RequestContext
    {
        public string Host { get; private set; }
        public string Method { get; private set; }
        public string Path { get; private set; }
        public string ContentType { get; private set; }

        public RequestContext(string host, string method, string path, string contentType)
        {
            Host = host; Method = method; Path = path; ContentType = contentType;
        }
    }

    public sealed class ExfilDecision
    {
        public bool Blocked { get; private set; }
        public Alert Alert { get; private set; }
        public IList<PlaceholderHit> Resolvable { get; private set; }
        public IList<PlaceholderHit> AllHits { get; private set; }

        private ExfilDecision() { }

        public static ExfilDecision Allow(IList<PlaceholderHit> resolvable)
        {
            ExfilDecision d = new ExfilDecision();
            d.Blocked = false; d.Resolvable = resolvable; d.AllHits = resolvable;
            return d;
        }

        public static ExfilDecision Block(Alert alert, IList<PlaceholderHit> allHits)
        {
            ExfilDecision d = new ExfilDecision();
            d.Blocked = true; d.Alert = alert; d.Resolvable = new PlaceholderHit[0]; d.AllHits = allHits;
            return d;
        }
    }

    /// <summary>
    /// Règles d'exfiltration R1–R5 (SPECS §9), évaluées dans l'ordre = sévérité décroissante ; la première déclenchée fait l'alerte.
    /// Toutes clés sur les secrets connus ; les inconnus ne résolvent jamais ; les secrets en quarantaine sont inertes.
    /// Le journal de diagnostic (debug) ne porte que des noms et des emplacements, jamais une valeur ni un snippet.
    /// </summary>
    public sealed class ExfilRuleEngine
    {
        public static readonly string[] CanonicalAuthHeaders = { "authorization", "x-api-key", "api-key", "x-auth-token" };
        public static readonly string[] SuspiciousContentTypes = { "text/plain", "application/x-www-form-urlencoded", "multipart/form-data" };
        public static readonly string[] SuspiciousPathFragments = { "/comments", "/issues", "/notes", "/messages", "/blob" };

        private readonly ISecretStore secrets;
        private readonly Func<int> maxPerMinute;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private readonly Dictionary<string, SlidingMinuteCounter> counters = new Dictionary<string, SlidingMinuteCounter>(StringComparer.Ordinal);

        /// <summary>maxPerMinute est relu à chaque évaluation : le seuil peut être rechargé à chaud sans recréer le moteur.</summary>
        public ExfilRuleEngine(ISecretStore secrets, Func<int> maxPerMinute, Func<DateTime> clock)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
            this.maxPerMinute = maxPerMinute;
            this.clock = clock;
        }

        /// <summary>À appeler après une substitution effective (jamais sur blocage).</summary>
        public void RecordSubstitution(IEnumerable<string> names)
        {
            DateTime now = clock();
            lock (gate)
            {
                foreach (string name in names)
                {
                    SlidingMinuteCounter c;
                    if (!counters.TryGetValue(name, out c)) { c = new SlidingMinuteCounter(); counters[name] = c; }
                    c.Record(now);
                }
            }
        }

        private bool WouldExceedVolume(string name)
        {
            int limit = maxPerMinute();
            DateTime now = clock();
            lock (gate)
            {
                SlidingMinuteCounter c;
                int current = counters.TryGetValue(name, out c) ? c.Count(now) : 0;
                return current + 1 > limit;
            }
        }

        public async Task<ExfilDecision> EvaluateAsync(IList<PlaceholderHit> hits, RequestContext context)
        {
            if (hits == null || hits.Count == 0) return ExfilDecision.Allow(new PlaceholderHit[0]);
            string host = HostName.Normalize(context.Host);

            Dictionary<string, Secret> known = new Dictionary<string, Secret>(StringComparer.Ordinal);
            HashSet<string> looked = new HashSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in hits)
            {
                if (!looked.Add(hit.Name)) continue;
                try { known[hit.Name] = await secrets.SecretAsync(hit.Name).ConfigureAwait(false); }
                catch (SecretStoreException ex) { if (ex.Kind != SecretStoreErrorKind.UnknownSecret) throw; }
            }

            List<PlaceholderHit> effective = new List<PlaceholderHit>();
            List<PlaceholderHit> knownHits = new List<PlaceholderHit>();
            foreach (PlaceholderHit hit in hits)
            {
                Secret s;
                bool isKnown = known.TryGetValue(hit.Name, out s);
                if (isKnown && s.Quarantined) continue;
                effective.Add(hit);
                if (isKnown) knownHits.Add(hit);
            }

            if (Log.Minimum <= LogLevel.Debug)
            {
                StringBuilder inv = new StringBuilder();
                foreach (PlaceholderHit hit in effective)
                {
                    if (inv.Length > 0) inv.Append(", ");
                    inv.Append(hit.Name).Append('@').Append(hit.Location.Describe()).Append(known.ContainsKey(hit.Name) ? ":known" : ":unknown");
                }
                Log.Debug("exfil", "inventaire " + context.Method + " " + host + " " + context.Path + " : " + inv);
            }

            // R1 — hôte hors allowed_hosts (high)
            foreach (PlaceholderHit hit in knownHits)
            {
                bool allowed = false;
                foreach (string h in known[hit.Name].AllowedHosts) if (HostName.Normalize(h) == host) { allowed = true; break; }
                if (!allowed) return ExfilDecision.Block(new Alert(AlertSeverity.High, ExfilRule.HostMismatch, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);
            }
            // R2 — emplacement non canonique (high) : seuls les en-têtes d'auth canoniques sont admis
            foreach (PlaceholderHit hit in knownHits)
                if (IsNonCanonical(hit.Location))
                    return ExfilDecision.Block(new Alert(AlertSeverity.High, ExfilRule.NonCanonicalLocation, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);
            // R3 — plusieurs secrets connus distincts (medium)
            SortedSet<string> distinct = new SortedSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in knownHits) distinct.Add(hit.Name);
            if (distinct.Count >= 2)
            {
                string first = distinct.Min;
                PlaceholderHit trigger = knownHits[0];
                foreach (PlaceholderHit hit in knownHits) if (hit.Name == first) { trigger = hit; break; }
                return ExfilDecision.Block(new Alert(AlertSeverity.Medium, ExfilRule.MultipleSecrets, first, trigger.Location.ToAlertLocation(), trigger.Snippet), effective);
            }
            // R4 — type de contenu suspect (medium) ; inatteignable derrière R2, conservée pour la défense en profondeur
            PlaceholderHit suspicious = SuspiciousContentTypeFires(knownHits, context);
            if (suspicious != null)
                return ExfilDecision.Block(new Alert(AlertSeverity.Medium, ExfilRule.SuspiciousContentType, suspicious.Name, AlertLocation.Body, suspicious.Snippet), effective);
            // R5 — volume (low) : compté sur les substitutions effectives seulement
            foreach (PlaceholderHit hit in knownHits)
                if (WouldExceedVolume(hit.Name))
                    return ExfilDecision.Block(new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);

            return ExfilDecision.Allow(knownHits);
        }

        private static bool IsNonCanonical(HitLocation location)
        {
            if (location.Kind != HitLocationKind.Header) return true;
            foreach (string c in CanonicalAuthHeaders) if (c == location.HeaderName) return false;
            return true;
        }

        private static PlaceholderHit SuspiciousContentTypeFires(IList<PlaceholderHit> hits, RequestContext context)
        {
            PlaceholderHit bodyHit = null;
            foreach (PlaceholderHit hit in hits) if (hit.Location.Kind == HitLocationKind.Body) { bodyHit = hit; break; }
            if (bodyHit == null || context.ContentType == null) return null;
            string baseType = context.ContentType.Split(';')[0].Trim().ToLowerInvariant();
            if (Array.IndexOf(SuspiciousContentTypes, baseType) < 0) return null;
            string path = (context.Path ?? "").ToLowerInvariant();
            foreach (string fragment in SuspiciousPathFragments) if (path.Contains(fragment)) return bodyHit;
            return null;
        }
    }
}
