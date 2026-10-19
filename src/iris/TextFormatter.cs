using System;
using System.Collections.Generic;
using System.Text;

namespace IrisCli
{
    /// <summary>Rendu lisible (français) : durées, dates relatives, états, tableaux alignés.</summary>
    public static class TextFormatter
    {
        private static readonly long[] Sizes = { 86400, 3600, 60, 1 };
        private static readonly string[] Units = { "j", "h", "m", "s" };

        /// <summary>Les deux unités les plus significatives, sans unité nulle en queue : 12s, 5m30s, 1h, 1j1h.</summary>
        public static string Duration(long seconds)
        {
            if (seconds < 0) seconds = 0;
            for (int i = 0; i < Sizes.Length; i++)
            {
                long major = seconds / Sizes[i];
                if (major == 0 && i < Sizes.Length - 1) continue;
                string text = major + Units[i];
                if (i + 1 < Sizes.Length)
                {
                    long minor = (seconds % Sizes[i]) / Sizes[i + 1];
                    if (minor > 0) text += minor + Units[i + 1];
                }
                return text;
            }
            return "0s";
        }

        public static string Ago(DateTime then, DateTime now)
        {
            return "il y a " + Duration((long)Math.Floor((now.ToUniversalTime() - then.ToUniversalTime()).TotalSeconds));
        }

        public static string VaultState(string wire)
        {
            switch (wire)
            {
                case "absent": return "absent";
                case "locked": return "verrouillé";
                case "unlocked": return "déverrouillé";
                default: return wire ?? "?";
            }
        }

        public static string YesNo(bool value) { return value ? "oui" : "non"; }

        /// <summary>Colonnes séparées de deux espaces, dernière colonne non complétée.</summary>
        public static IList<string> Table(string[] headers, IList<string[]> rows)
        {
            int[] widths = new int[headers.Length];
            for (int i = 0; i < headers.Length; i++) widths[i] = headers[i].Length;
            foreach (string[] row in rows)
                for (int i = 0; i < row.Length; i++) widths[i] = Math.Max(widths[i], row[i].Length);
            List<string> lines = new List<string>();
            lines.Add(Row(headers, widths));
            foreach (string[] row in rows) lines.Add(Row(row, widths));
            return lines;
        }

        private static string Row(string[] cells, int[] widths)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < cells.Length; i++)
            {
                if (i < cells.Length - 1) sb.Append(cells[i].PadRight(widths[i] + 2));
                else sb.Append(cells[i]);
            }
            return sb.ToString();
        }
    }
}
