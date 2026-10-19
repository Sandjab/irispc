using System;
using System.Globalization;
using System.Text.RegularExpressions;
using IrisKit;

namespace IrisCli
{
    /// <summary>`--since` / `--until` : `<entier><s|m|h|d>` soustrait de maintenant, ou date ISO-8601 ; rendu en UTC.</summary>
    public static class RelativeTime
    {
        private static readonly Regex Relative = new Regex("^([0-9]{1,9})([smhd])$", RegexOptions.CultureInvariant);

        public static DateTime Parse(string text, DateTime now)
        {
            Match m = Relative.Match(text ?? "");
            if (m.Success)
            {
                long n = long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                switch (m.Groups[2].Value)
                {
                    case "s": return now.ToUniversalTime().AddSeconds(-n);
                    case "m": return now.ToUniversalTime().AddMinutes(-n);
                    case "h": return now.ToUniversalTime().AddHours(-n);
                    default: return now.ToUniversalTime().AddDays(-n);
                }
            }
            try { return Json.ParseDate(text ?? "").ToUniversalTime(); }
            catch (JsonException) { throw new UsageException("date invalide : " + text + " (attendu : 30s, 5m, 1h, 2d ou ISO-8601)"); }
            catch (FormatException) { throw new UsageException("date invalide : " + text + " (attendu : 30s, 5m, 1h, 2d ou ISO-8601)"); }
        }
    }
}
