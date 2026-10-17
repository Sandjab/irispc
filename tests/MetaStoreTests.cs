using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- SecretsMetaStore ------------------------------------------

        private static void MetaStore_DefaultsAndFlush()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, "secrets-meta.json");
                List<string> names = new List<string> { "a", "b" };
                using (SecretsMetaStore meta = new SecretsMetaStore(path, delegate { return names; }, TimeSpan.FromHours(1), delegate { return T0; }))
                {
                    SecretMeta none = meta.Get("a");
                    Check.True(none.UsageCount == 0 && none.LastUsedAt == null && !none.Quarantined, "défauts sans entrée");
                    Check.True(!meta.Dirty && !File.Exists(path), "rien à écrire au départ");
                    SecretMeta m = meta.RecordUsage("a", T0.AddSeconds(5));
                    m = meta.RecordUsage("a", T0.AddSeconds(6));
                    Check.True(m.UsageCount == 2 && m.LastUsedAt == T0.AddSeconds(6) && meta.Dirty, "usage en mémoire, dirty");
                    meta.SetQuarantined("b", true);
                    meta.RecordUsage("zombie", T0);
                    Check.True(meta.Flush(), "Flush écrit");
                    Check.True(!meta.Dirty && !meta.Flush(), "plus rien à écrire");
                    string text = File.ReadAllText(path);
                    Check.Eq("{\n  \"version\": 1,\n  \"secrets\": {\n    \"a\": {\n      \"last_used_at\": \"2023-11-14T22:13:26Z\",\n      \"usage_count\": 2,\n      \"quarantined\": false\n    },\n    \"b\": {\n      \"usage_count\": 0,\n      \"quarantined\": true\n    }\n  }\n}\n", text, "format spec §4.2 ; « zombie » (sans entrée dans le coffre) purgé");
                    Check.True(!File.Exists(path + ".tmp"), "écriture atomique sans résidu");
                }
                using (SecretsMetaStore again = new SecretsMetaStore(path, delegate { return names; }, TimeSpan.FromHours(1), delegate { return T0; }))
                {
                    Check.True(again.Get("a").UsageCount == 2 && again.Get("b").Quarantined, "relu depuis le disque");
                    again.Remove("b");
                    again.Flush();
                    Check.True(!File.ReadAllText(path).Contains("\"b\""), "Remove retire l'entrée");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void MetaStore_DebounceAndDispose()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, "secrets-meta.json");
                SecretsMetaStore meta = new SecretsMetaStore(path, delegate { return new[] { "a" }; }, TimeSpan.FromMilliseconds(100), delegate { return DateTime.UtcNow; });
                meta.RecordUsage("a", T0);
                Check.True(!File.Exists(path), "pas d'écriture immédiate");
                Thread.Sleep(400);
                Check.True(File.Exists(path) && !meta.Dirty, "écrit après le délai de débounce");
                meta.RecordUsage("a", T0.AddSeconds(1));
                meta.Dispose();
                Check.True(File.ReadAllText(path).Contains("\"usage_count\": 2"), "Dispose flushe le reste");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void MetaStore_CorruptFileStartsEmpty()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, "secrets-meta.json");
                File.WriteAllText(path, "{{{");
                StringWriter log = new StringWriter();
                Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Warn;
                using (SecretsMetaStore meta = new SecretsMetaStore(path, delegate { return new[] { "a" }; }, TimeSpan.FromHours(1), delegate { return T0; }))
                {
                    Check.Eq(0L, meta.Get("a").UsageCount, "repart vide");
                }
                Log.Reset();
                Check.True(log.ToString().Contains("secrets-meta.json"), "avertissement journalisé");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
