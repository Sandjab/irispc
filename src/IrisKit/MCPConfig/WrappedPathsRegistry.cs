using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace IrisKit
{
    /// <summary>Manifeste présent mais illisible : jamais traité comme vide (un Add le réécrirait et perdrait les autres chemins).</summary>
    public sealed class WrappedPathsCorruptException : Exception
    {
        public WrappedPathsCorruptException(string path, string reason)
            : base("registre des fichiers enrobés illisible : " + path + " (" + reason + ") ; corrigez-le ou supprimez-le") { }
    }

    /// <summary>
    /// Chemins absolus des fichiers MCP patchés par `iris mcp wrap` (`data\wrapped-paths.json`, tableau JSON, sans doublon, ordre
    /// d'insertion) : l'app (phase 6) et la désinstallation (phase 7) les restaurent. Comparaison insensible à la casse (Windows).
    /// </summary>
    public sealed class WrappedPathsRegistry
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        public string ManifestPath { get; private set; }

        public WrappedPathsRegistry(string manifestPath) { ManifestPath = manifestPath; }

        public static WrappedPathsRegistry ForDataDir(string dataDir)
        {
            return new WrappedPathsRegistry(Path.Combine(dataDir, "wrapped-paths.json"));
        }

        public IList<string> List()
        {
            if (!File.Exists(ManifestPath)) return new List<string>();
            string text;
            try { text = File.ReadAllText(ManifestPath, Encoding.UTF8); }
            catch (IOException ex) { throw new WrappedPathsCorruptException(ManifestPath, ex.Message); }
            catch (UnauthorizedAccessException ex) { throw new WrappedPathsCorruptException(ManifestPath, ex.Message); }
            IList<object> items;
            try { items = Json.Parse(text) as IList<object>; }
            catch (JsonException ex) { throw new WrappedPathsCorruptException(ManifestPath, ex.Message); }
            if (items == null) throw new WrappedPathsCorruptException(ManifestPath, "tableau JSON attendu");
            List<string> paths = new List<string>();
            foreach (object item in items)
            {
                string s = item as string;
                if (s == null) throw new WrappedPathsCorruptException(ManifestPath, "chemins (chaînes) attendus");
                paths.Add(s);
            }
            return paths;
        }

        public void Add(string path)
        {
            IList<string> paths = List();
            foreach (string p in paths)
                if (string.Equals(p, path, StringComparison.OrdinalIgnoreCase)) return;
            paths.Add(path);
            Write(paths);
        }

        public void Remove(string path)
        {
            IList<string> paths = List();
            List<string> kept = new List<string>();
            foreach (string p in paths)
                if (!string.Equals(p, path, StringComparison.OrdinalIgnoreCase)) kept.Add(p);
            if (kept.Count != paths.Count) Write(kept);
        }

        private void Write(IList<string> paths)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ManifestPath));
            List<object> items = new List<object>();
            foreach (string p in paths) items.Add(p);
            string tmp = ManifestPath + ".tmp";
            File.WriteAllText(tmp, Json.Emit(items) + "\n", Utf8NoBom);
            if (File.Exists(ManifestPath)) File.Replace(tmp, ManifestPath, null);
            else File.Move(tmp, ManifestPath);
        }
    }
}
