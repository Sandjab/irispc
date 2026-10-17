using System;
using System.IO;
using System.Reflection;

namespace IrisKit
{
    public sealed class DataDirException : Exception
    {
        public DataDirException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>Dossier `data\` (spec §3) : à côté de l'exécutable, ou `--data` ; jamais de repli vers AppData.</summary>
    public static class DataDir
    {
        public static string Resolve(string overridePath)
        {
            if (!string.IsNullOrWhiteSpace(overridePath)) return Path.GetFullPath(overridePath);
            return Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "data");
        }

        /// <summary>Crée `data\`, `events\`, `backups\` et vérifie l'écriture par un fichier témoin. Échec = DataDirException avec chemin et cause.</summary>
        public static void Prepare(string dataDir)
        {
            try
            {
                Directory.CreateDirectory(dataDir);
                Directory.CreateDirectory(Path.Combine(dataDir, "events"));
                Directory.CreateDirectory(Path.Combine(dataDir, "backups"));
                string probe = Path.Combine(dataDir, ".write-test-" + Guid.NewGuid().ToString("N"));
                File.WriteAllText(probe, "ok");
                File.Delete(probe);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException || ex is NotSupportedException)
                    throw new DataDirException("dossier de données inutilisable : " + dataDir + " (" + ex.Message + ")", ex);
                throw;
            }
        }
    }
}
