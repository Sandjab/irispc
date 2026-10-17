using System;
using System.IO;
using System.Text;

namespace IrisKit
{
    /// <summary>Erreur d'E/S irrécupérable sur config.json : le daemon sort avec le code 1.</summary>
    public sealed class ConfigIOException : Exception
    {
        public ConfigIOException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// Source de vérité de config.json (spec §5.1). Seed si absent ; fichier illisible ou invalide au démarrage →
    /// copie `backups\config-corrupted-<stamp>.json`, reseed, RecoveredFromCorruption = true (démarrage dégradé).
    /// Save : validation → backup horodaté → écriture atomique (tmp + File.Replace) → rotation.
    /// </summary>
    public sealed class ConfigStore
    {
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);
        private readonly object gate = new object();

        public string Path { get; private set; }
        public string BackupsDir { get; private set; }
        public Config Current { get; private set; }
        public bool RecoveredFromCorruption { get; private set; }
        public string CorruptionDetail { get; private set; }

        private ConfigStore(string path, string backupsDir)
        {
            Path = path;
            BackupsDir = backupsDir;
            CorruptionDetail = "";
        }

        public static ConfigStore Open(string dataDir, DateTime now)
        {
            ConfigStore store = new ConfigStore(System.IO.Path.Combine(dataDir, "config.json"), System.IO.Path.Combine(dataDir, "backups"));
            if (!File.Exists(store.Path))
            {
                Log.Info("config", "config.json absent, création avec les valeurs par défaut : " + store.Path);
                store.Current = Config.Default(now);
                store.WriteAtomic(store.Current);
                return store;
            }
            string text;
            try
            {
                text = File.ReadAllText(store.Path, Encoding.UTF8);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                    throw new ConfigIOException("lecture de " + store.Path + " impossible : " + ex.Message, ex);
                throw;
            }
            try
            {
                Config loaded = Config.FromJson(Json.ParseObject(text));
                loaded.Validate();
                store.Current = loaded;
                return store;
            }
            catch (JsonException ex) { store.CorruptionDetail = ex.Message; }
            catch (ConfigException ex) { store.CorruptionDetail = ex.Message; }
            // Démarrage dégradé : copie de l'original, reseed, le daemon continue.
            Log.Error("config", "config.json corrompu (" + store.CorruptionDetail + ") : copie de sauvegarde puis valeurs par défaut");
            try
            {
                Directory.CreateDirectory(store.BackupsDir);
                File.Copy(store.Path, System.IO.Path.Combine(store.BackupsDir, "config-corrupted-" + Backups.Stamp(now) + ".json"), true);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                    throw new ConfigIOException("sauvegarde du config.json corrompu impossible : " + ex.Message, ex);
                throw;
            }
            store.Current = Config.Default(now);
            store.WriteAtomic(store.Current);
            store.RecoveredFromCorruption = true;
            return store;
        }

        /// <summary>Validation, backup du fichier courant, écriture atomique, rotation. Une erreur de validation ne change rien.</summary>
        public void Save(Config config, DateTime now)
        {
            config.Validate();
            lock (gate)
            {
                try
                {
                    if (File.Exists(Path))
                    {
                        Backups.CopyWithStamp(Path, BackupsDir, "config", ".json", now);
                        Backups.Rotate(BackupsDir, "config", ".json", config.Backups.MaxCount);
                    }
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                        throw new ConfigIOException("backup de config.json impossible : " + ex.Message, ex);
                    throw;
                }
                WriteAtomic(config);
                Current = config;
            }
        }

        private void WriteAtomic(Config config)
        {
            string tmp = Path + ".tmp";
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(Path));
                File.WriteAllText(tmp, Json.Emit(config.ToJson()) + "\n", Utf8NoBom);
                if (File.Exists(Path)) File.Replace(tmp, Path, null);
                else File.Move(tmp, Path);
            }
            catch (Exception ex)
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { }
                if (ex is IOException || ex is UnauthorizedAccessException)
                    throw new ConfigIOException("écriture de " + Path + " impossible : " + ex.Message, ex);
                throw;
            }
        }
    }
}
