using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    public enum RequestOutcome { Bypassed, Substituted, NoMatch, Blocked }

    /// <summary>Requête prête à partir vers l'amont et ce qu'il faut en consigner. Ne contient jamais une valeur de secret hors Head/Body.</summary>
    public sealed class ProcessedRequest
    {
        public HttpRequestHead Head { get; private set; }
        public byte[] Body { get; private set; }
        public RequestOutcome Outcome { get; private set; }
        public IList<string> Substituted { get; private set; }
        public IList<string> Unresolved { get; private set; }
        public Alert Alert { get; private set; }
        public EventFlags Flags { get; private set; }

        public ProcessedRequest(HttpRequestHead head, byte[] body, RequestOutcome outcome, IList<string> substituted, IList<string> unresolved, Alert alert, EventFlags flags)
        {
            Head = head; Body = body; Outcome = outcome;
            Substituted = substituted ?? new string[0];
            Unresolved = unresolved ?? new string[0];
            Alert = alert; Flags = flags;
        }

        /// <summary>Spec socle §6.2 : en pause, noMatch + drapeau paused (IRIS émet passThrough).</summary>
        public EventKind EventKind
        {
            get
            {
                switch (Outcome)
                {
                    case RequestOutcome.Substituted: return EventKind.Substituted;
                    case RequestOutcome.Blocked: return EventKind.ExfilBlocked;
                    default: return EventKind.NoMatch;
                }
            }
        }
    }

    /// <summary>
    /// Étape pure du MITM (spec §6.2 étapes 2–4 et 7) : retire Accept-Encoding / Proxy-Connection / Expect, pose les drapeaux
    /// bodyTooLarge / nonUtf8 / compressedBody, scanne (en-têtes et URL toujours, corps seulement s'il est bufferisé, UTF-8 et
    /// non compressé), évalue R1–R5, substitue, compte R5, enregistre l'usage en tâche détachée, applique on_exfil_attempt.
    /// </summary>
    public sealed class RequestProcessor
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly ISecretStore secrets;
        private readonly Func<ExfilPolicy> policy;
        private readonly Action pause;
        private readonly Func<DateTime> clock;

        public ExfilRuleEngine Rules { get; private set; }
        public PlaceholderEngine Engine { get; private set; }
        /// <summary>Dernier enregistrement d'usage détaché (les tests l'attendent) ; jamais sur le chemin de la requête.</summary>
        public Task LastUsageRecording { get; private set; }

        public RequestProcessor(ISecretStore secrets, Func<int> maxPerMinute, Func<ExfilPolicy> policy, Action pause, Func<DateTime> clock)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
            this.policy = policy;
            this.pause = pause;
            this.clock = clock;
            Rules = new ExfilRuleEngine(secrets, maxPerMinute, clock);
            Engine = new PlaceholderEngine(secrets);
            LastUsageRecording = Task.FromResult(0);
        }

        public async Task<ProcessedRequest> ProcessAsync(HttpRequestHead head, byte[] body, bool bodyTooLarge, string host, bool paused)
        {
            HttpHeaders prepared = head.Headers.Clone();
            prepared.Remove("Accept-Encoding");   // SPECS §7.5 : on ne décompresse jamais les réponses
            prepared.Remove("Proxy-Connection");
            prepared.Remove("Expect");            // le 100 Continue a déjà été rendu au client
            HttpRequestHead preparedHead = new HttpRequestHead(head.Method, head.Target, "HTTP/1.1", prepared);
            string normalizedHost = HostName.Normalize(host);

            EventFlags flags = EventFlags.None;
            if (bodyTooLarge) flags |= EventFlags.BodyTooLarge;
            if (paused)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.Bypassed, null, null, null, flags | EventFlags.Paused);

            string bodyText = null;
            if (bodyTooLarge)
            {
                Log.Warn("proxy", "corps de plus de " + HttpParser.MaxBufferedBody / (1024 * 1024) + " MiB vers " + normalizedHost + " : relayé sans scan du corps");
            }
            else if (prepared.Contains("Content-Encoding"))
            {
                flags |= EventFlags.CompressedBody;
                if (body != null && body.Length > 0) Log.Warn("proxy", "corps compressé (" + prepared.First("Content-Encoding") + ") vers " + normalizedHost + " : pas de substitution dans le corps");
            }
            else if (body != null && body.Length > 0)
            {
                try { bodyText = StrictUtf8.GetString(body); }
                catch (DecoderFallbackException)
                {
                    flags |= EventFlags.NonUtf8;
                    Log.Debug("proxy", "corps non UTF-8 vers " + normalizedHost + " : non scanné");
                }
            }

            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(prepared, head.Target, bodyText);
            if (hits.Count == 0) return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, null, null, flags);

            string path, query;
            PlaceholderScanner.SplitUri(head.Target, out path, out query);
            string contentType = prepared.First("Content-Type");
            RequestContext context = new RequestContext(normalizedHost, head.Method, path, contentType == null ? null : contentType.ToLowerInvariant());
            ExfilDecision decision = await Rules.EvaluateAsync(hits, context).ConfigureAwait(false);
            if (decision.Blocked)
            {
                ApplyPolicy(decision.Alert, normalizedHost);
                return new ProcessedRequest(preparedHead, body, RequestOutcome.Blocked, null, null, decision.Alert, flags);
            }
            if (decision.Resolvable.Count == 0)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, DistinctNames(hits), null, flags);

            ResolvedPayload payload = await Engine.SubstituteAsync(prepared, head.Target, bodyText == null ? null : body, decision.Resolvable).ConfigureAwait(false);
            if (payload.Substituted.Count == 0)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, payload.Unresolved, null, flags);

            byte[] newBody = body;
            HttpHeaders newHeaders = payload.Headers;
            if (bodyText != null && payload.Body != null && !ReferenceEquals(payload.Body, body))
            {
                newBody = payload.Body;
                if (newHeaders.Contains("Content-Length")) newHeaders.Set("Content-Length", newBody.Length.ToString(CultureInfo.InvariantCulture));
            }
            Rules.RecordSubstitution(payload.Substituted);
            LastUsageRecording = RecordUsageAsync(payload.Substituted, clock());
            Log.Info("proxy", "substitution de " + string.Join(", ", payload.Substituted) + " pour " + head.Method + " " + normalizedHost + " " + path);
            return new ProcessedRequest(new HttpRequestHead(head.Method, payload.Uri, "HTTP/1.1", newHeaders), newBody, RequestOutcome.Substituted, payload.Substituted, payload.Unresolved, null, flags);
        }

        private void ApplyPolicy(Alert alert, string host)
        {
            Log.Warn("proxy", "tentative d'exfiltration bloquée : " + AlertWire.RuleToWire(alert.Rule) + " (" + AlertWire.SeverityToWire(alert.Severity) + ") secret " + alert.SecretName + " vers " + host + ", requête transmise intacte");
            switch (policy())
            {
                case ExfilPolicy.BlockAndNotify:
                    Log.Warn("proxy", "notification demandée (prise en charge par l'app, lot ultérieur)");
                    break;
                case ExfilPolicy.BlockNotifyPause:
                    Log.Warn("proxy", "politique block_notify_pause : mise en pause du daemon");
                    if (pause != null) pause();
                    break;
            }
        }

        /// <summary>Usage par secret, détaché et jamais fatal (nom seul dans le journal, jamais la valeur).</summary>
        private async Task RecordUsageAsync(IList<string> names, DateTime at)
        {
            foreach (string name in names)
            {
                try { await secrets.RecordUsageAsync(name, at).ConfigureAwait(false); }
                catch (SecretStoreException ex) { Log.Warn("proxy", "usage de " + name + " non enregistré : " + ex.Message); }
                catch (Exception ex) { Log.Warn("proxy", "usage de " + name + " non enregistré : " + ex.GetType().Name); }
            }
        }

        private static IList<string> DistinctNames(IList<PlaceholderHit> hits)
        {
            List<string> names = new List<string>();
            foreach (PlaceholderHit h in hits) if (!names.Contains(h.Name)) names.Add(h.Name);
            return names;
        }
    }
}
