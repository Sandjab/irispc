using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;

namespace IrisKit
{
    /// <summary>
    /// Copies horodatées `prefix-<stamp>-<8hex>ext` et rotation par préfixe (config.json et iris.kdbx, spec §4.5 / §5.1).
    /// Les copies `prefix-corrupted-*` ne sont jamais rotées : elles peuvent être la seule copie récupérable.
    /// </summary>
    public static class Backups
    {
        public static string Stamp(DateTime utc)
        {
            return utc.ToUniversalTime().ToString("yyyyMMdd'T'HHmmssfff'Z'", CultureInfo.InvariantCulture);
        }

        public static string CopyWithStamp(string sourcePath, string backupsDir, string prefix, string extension, DateTime now)
        {
            Directory.CreateDirectory(backupsDir);
            string name = prefix + "-" + Stamp(now) + "-" + Guid.NewGuid().ToString("N").Substring(0, 8) + extension;
            string dest = Path.Combine(backupsDir, name);
            File.Copy(sourcePath, dest, false);
            return dest;
        }

        /// <summary>Supprime les plus anciennes (ordre lexicographique = chronologique) au-delà de maxCount. Rend le nombre supprimé.</summary>
        public static int Rotate(string backupsDir, string prefix, string extension, int maxCount)
        {
            if (!Directory.Exists(backupsDir)) return 0;
            List<string> names = new List<string>();
            foreach (string path in Directory.GetFiles(backupsDir, prefix + "-*" + extension))
            {
                string name = Path.GetFileName(path);
                if (name.StartsWith(prefix + "-corrupted-", StringComparison.Ordinal)) continue;
                names.Add(name);
            }
            names.Sort(StringComparer.Ordinal);
            int removed = 0;
            for (int i = 0; i < names.Count - maxCount; i++)
            {
                try { File.Delete(Path.Combine(backupsDir, names[i])); removed++; }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            return removed;
        }
    }
}
