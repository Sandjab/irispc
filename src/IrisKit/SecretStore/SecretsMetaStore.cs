using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Threading;

namespace IrisKit
{
    /// <summary>Métadonnées volatiles d'un secret (spec §4.2) : jamais dans le kdbx.</summary>
    public sealed class SecretMeta
    {
        public static readonly SecretMeta Empty = new SecretMeta(null, 0, false);

        public DateTime? LastUsedAt { get; private set; }
        public long UsageCount { get; private set; }
        public bool Quarantined { get; private set; }

        public SecretMeta(DateTime? lastUsedAt, long usageCount, bool quarantined)
        {
            LastUsedAt = lastUsedAt; UsageCount = usageCount; Quarantined = quarantined;
        }
    }

    /// <summary>
    /// `secrets-meta.json` : écrit au plus une fois par `debounce` (2 s) et à l'arrêt, atomiquement.
    /// Les noms absents de `existingNames()` sont purgés à l'écriture ; un fichier illisible fait repartir vide (avertissement).
    /// </summary>
    public sealed class SecretsMetaStore : IDisposable
    {
        public static readonly TimeSpan DefaultDebounce = TimeSpan.FromSeconds(2);
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        private readonly object gate = new object();
        private readonly string path;
        private readonly Func<ICollection<string>> existingNames;
        private readonly TimeSpan debounce;
        private readonly Func<DateTime> clock;
        private readonly Dictionary<string, SecretMeta> items = new Dictionary<string, SecretMeta>(StringComparer.Ordinal);
        private Timer timer;
        private bool dirty;
        private bool disposed;

        public bool Dirty { get { lock (gate) { return dirty; } } }

        public SecretsMetaStore(string path, Func<ICollection<string>> existingNames, TimeSpan debounce, Func<DateTime> clock)
        {
            this.path = path; this.existingNames = existingNames; this.debounce = debounce; this.clock = clock;
            Load();
        }

        private void Load()
        {
            if (!File.Exists(path)) return;
            try
            {
                JsonObject root = Json.ParseObject(File.ReadAllText(path, Encoding.UTF8));
                JsonObject secrets = root.OptionalObject("secrets");
                if (secrets == null) return;
                foreach (string name in secrets.Keys)
                {
                    JsonObject m = secrets.Object(name);
                    string last = m.OptionalString("last_used_at");
                    items[name] = new SecretMeta(last == null ? (DateTime?)null : Json.ParseDate(last), m.OptionalInt("usage_count") ?? 0, m.Bool("quarantined", false));
                }
            }
            catch (JsonException ex) { Warn(ex.Message); }
            catch (IOException ex) { Warn(ex.Message); }
            catch (UnauthorizedAccessException ex) { Warn(ex.Message); }
        }

        private void Warn(string detail)
        {
            items.Clear();
            Log.Warn("secrets", "secrets-meta.json illisible, métadonnées d'usage remises à zéro : " + detail);
        }

        public SecretMeta Get(string name)
        {
            lock (gate)
            {
                SecretMeta m;
                return items.TryGetValue(name, out m) ? m : SecretMeta.Empty;
            }
        }

        public SecretMeta RecordUsage(string name, DateTime at)
        {
            lock (gate)
            {
                SecretMeta m = Get(name);
                m = new SecretMeta(at, m.UsageCount + 1, m.Quarantined);
                items[name] = m;
                MarkDirty();
                return m;
            }
        }

        public SecretMeta SetQuarantined(string name, bool quarantined)
        {
            lock (gate)
            {
                SecretMeta m = Get(name);
                m = new SecretMeta(m.LastUsedAt, m.UsageCount, quarantined);
                items[name] = m;
                MarkDirty();
                return m;
            }
        }

        public void Remove(string name)
        {
            lock (gate)
            {
                if (items.Remove(name)) MarkDirty();
            }
        }

        private void MarkDirty()
        {
            dirty = true;
            if (timer == null && !disposed)
                timer = new Timer(delegate { Flush(); }, null, debounce, TimeSpan.FromMilliseconds(-1));
        }

        /// <summary>Écrit maintenant si nécessaire. Rend true si une écriture a eu lieu.</summary>
        public bool Flush()
        {
            lock (gate)
            {
                if (timer != null) { timer.Dispose(); timer = null; }
                if (!dirty) return false;
                HashSet<string> keep = new HashSet<string>(existingNames(), StringComparer.Ordinal);
                List<string> names = new List<string>(items.Keys);
                names.Sort(StringComparer.Ordinal);
                OrderedDictionary secrets = new OrderedDictionary();
                foreach (string name in names)
                {
                    if (!keep.Contains(name)) { items.Remove(name); continue; }
                    SecretMeta m = items[name];
                    OrderedDictionary o = new OrderedDictionary();
                    if (m.LastUsedAt.HasValue) o["last_used_at"] = m.LastUsedAt.Value;
                    o["usage_count"] = m.UsageCount;
                    o["quarantined"] = m.Quarantined;
                    secrets[name] = o;
                }
                OrderedDictionary root = new OrderedDictionary();
                root["version"] = 1L;
                root["secrets"] = secrets;
                string tmp = path + ".tmp";
                try
                {
                    File.WriteAllText(tmp, Json.Emit(root) + "\n", Utf8NoBom);
                    if (File.Exists(path)) File.Replace(tmp, path, null);
                    else File.Move(tmp, path);
                    dirty = false;
                }
                catch (IOException ex) { Log.Error("secrets", "écriture de secrets-meta.json impossible : " + ex.Message); }
                catch (UnauthorizedAccessException ex) { Log.Error("secrets", "écriture de secrets-meta.json impossible : " + ex.Message); }
                return true;
            }
        }

        public void Dispose()
        {
            lock (gate) { disposed = true; }
            Flush();
        }
    }
}
