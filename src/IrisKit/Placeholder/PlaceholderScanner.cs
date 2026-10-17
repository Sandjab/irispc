using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace IrisKit
{
    /// <summary>Scan des placeholders `{{kc:NAME}}` (SPECS §7.1–7.2) dans les noms et valeurs d'en-têtes, le chemin, la query et le corps.</summary>
    public static class PlaceholderScanner
    {
        public const string PatternText = @"\{\{kc:([a-zA-Z0-9_-]{1,64})\}\}";
        public static readonly Regex Pattern = new Regex(PatternText, RegexOptions.CultureInvariant);
        /// <summary>Plafond du snippet ; avec 80 caractères de contexte et un nom ≤ 64 le pire cas fait ≈ 233, le plafond est une défense en profondeur.</summary>
        public const int SnippetMaxLength = 256;
        public const int SnippetContextChars = 80;

        /// <summary>body = null quand le corps est absent, trop grand ou non UTF-8 : le scanner ne décode jamais lui-même.</summary>
        public static IList<PlaceholderHit> Scan(HttpHeaders headers, string uri, string body)
        {
            List<PlaceholderHit> hits = new List<PlaceholderHit>();
            foreach (HttpHeader h in headers)
            {
                HitLocation location = HitLocation.Header(h.Name);
                hits.AddRange(ScanString(h.Name, location));
                hits.AddRange(ScanString(h.Value, location));
            }
            string path, query;
            SplitUri(uri ?? "", out path, out query);
            hits.AddRange(ScanString(path, HitLocation.UrlPath));
            if (query != null) hits.AddRange(ScanString(query, HitLocation.QueryString));
            if (body != null) hits.AddRange(ScanString(body, HitLocation.Body));
            return hits;
        }

        internal static IList<PlaceholderHit> ScanString(string text, HitLocation location)
        {
            List<PlaceholderHit> hits = new List<PlaceholderHit>();
            if (string.IsNullOrEmpty(text)) return hits;
            foreach (Match m in Pattern.Matches(text))
                hits.Add(new PlaceholderHit(m.Groups[1].Value, location, MakeSnippet(text, m.Index, m.Length)));
            return hits;
        }

        public static void SplitUri(string uri, out string path, out string query)
        {
            int q = uri.IndexOf('?');
            if (q < 0) { path = uri; query = null; return; }
            path = uri.Substring(0, q);
            query = uri.Substring(q + 1);
        }

        /// <summary>80 caractères de contexte de chaque côté, caractères de contrôle ASCII → '?', plafond 256 avec '…'.</summary>
        internal static string MakeSnippet(string text, int start, int length)
        {
            int from = Math.Max(0, start - SnippetContextChars);
            int to = Math.Min(text.Length, start + length + SnippetContextChars);
            StringBuilder sb = new StringBuilder(to - from);
            for (int i = from; i < to; i++)
            {
                char c = text[i];
                sb.Append(c < 0x20 || c == 0x7F ? '?' : c);
            }
            if (sb.Length > SnippetMaxLength) return sb.ToString(0, SnippetMaxLength - 1) + "\u2026";
            return sb.ToString();
        }

        /// <summary>Noms distincts dans l'ordre d'apparition (utilisé par le lot CLI / mcp wrap).</summary>
        public static IList<string> FindPlaceholderNames(string text)
        {
            List<string> order = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(text)) return order;
            foreach (Match m in Pattern.Matches(text))
            {
                string name = m.Groups[1].Value;
                if (seen.Add(name)) order.Add(name);
            }
            return order;
        }
    }
}
