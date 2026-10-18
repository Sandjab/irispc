using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Résultat d'une substitution : requête réécrite, noms substitués, noms non résolus (inconnus ou valeur non UTF-8).</summary>
    public sealed class ResolvedPayload
    {
        public HttpHeaders Headers { get; private set; }
        public string Uri { get; private set; }
        public byte[] Body { get; private set; }
        public IList<string> Substituted { get; private set; }
        public IList<string> Unresolved { get; private set; }

        public ResolvedPayload(HttpHeaders headers, string uri, byte[] body, IList<string> substituted, IList<string> unresolved)
        {
            Headers = headers; Uri = uri; Body = body; Substituted = substituted; Unresolved = unresolved;
        }
    }

    /// <summary>
    /// Substitution par nom des hits déjà autorisés par ExfilRuleEngine (R1/R2 passés pour chaque nom : toute occurrence
    /// du nom est donc légitime). Octet pour octet sur l'UTF-8 ; un corps non UTF-8 n'est jamais réécrit ; une valeur de
    /// secret non UTF-8 est signalée dans Unresolved (échec visible plutôt que silencieux).
    /// </summary>
    public sealed class PlaceholderEngine
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private readonly ISecretStore secrets;

        public PlaceholderEngine(ISecretStore secrets)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
        }

        private static readonly char[] ForbiddenChars = { '\r', '\n', '\0' };

        public async Task<ResolvedPayload> SubstituteAsync(HttpHeaders headers, string uri, byte[] body, IList<PlaceholderHit> resolvable)
        {
            if (resolvable == null || resolvable.Count == 0)
                return new ResolvedPayload(headers, uri, body, new List<string>(), new List<string>());

            SortedSet<string> names = new SortedSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in resolvable) names.Add(hit.Name);

            // Deux textes par valeur : Latin-1 (un octet = un char) pour les en-têtes et l'URI, modélisés ainsi par HttpParser,
            // afin que les octets UTF-8 partent tels quels sur le fil ; UTF-8 strict pour le corps. Une valeur non UTF-8, ou
            // contenant CR, LF ou NUL (injection d'en-tête, request splitting), n'est jamais substituée : Unresolved.
            Dictionary<string, string> wireValues = new Dictionary<string, string>(StringComparer.Ordinal);
            Dictionary<string, string> bodyValues = new Dictionary<string, string>(StringComparer.Ordinal);
            List<string> unresolved = new List<string>();
            foreach (string name in names)
            {
                byte[] raw;
                try { raw = await secrets.ValueAsync(name).ConfigureAwait(false); }
                catch (SecretStoreException ex)
                {
                    if (ex.Kind != SecretStoreErrorKind.UnknownSecret) throw;
                    unresolved.Add(name);
                    continue;
                }
                try
                {
                    string text = StrictUtf8.GetString(raw);
                    if (text.IndexOfAny(ForbiddenChars) >= 0)
                    {
                        Log.Warn("placeholder", "secret " + name + " contient un retour à la ligne ou un octet nul : non substitué");
                        unresolved.Add(name);
                    }
                    else
                    {
                        bodyValues[name] = text;
                        wireValues[name] = HttpParser.Latin1.GetString(raw);
                    }
                }
                catch (DecoderFallbackException) { unresolved.Add(name); }
                finally { Array.Clear(raw, 0, raw.Length); }
            }

            SortedSet<string> substituted = new SortedSet<string>(StringComparer.Ordinal);
            Func<string, Dictionary<string, string>, string> mutate = delegate(string input, Dictionary<string, string> values)
            {
                string result = input;
                foreach (KeyValuePair<string, string> kv in values)
                {
                    string needle = "{{kc:" + kv.Key + "}}";
                    if (result.IndexOf(needle, StringComparison.Ordinal) < 0) continue;
                    result = result.Replace(needle, kv.Value);
                    substituted.Add(kv.Key);
                }
                return result;
            };

            HttpHeaders newHeaders = new HttpHeaders();
            foreach (HttpHeader h in headers) newHeaders.Add(mutate(h.Name, wireValues), mutate(h.Value, wireValues));
            string newUri = mutate(uri, wireValues);
            byte[] newBody = body;
            if (body != null)
            {
                string text = null;
                try { text = StrictUtf8.GetString(body); }
                catch (DecoderFallbackException) { }
                if (text != null)
                {
                    string transformed = mutate(text, bodyValues);
                    if (!ReferenceEquals(transformed, text) && transformed != text) newBody = StrictUtf8.GetBytes(transformed);
                }
            }
            return new ResolvedPayload(newHeaders, newUri, newBody, new List<string>(substituted), unresolved);
        }
    }
}
