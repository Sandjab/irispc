using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- SecretStore (mémoire) -------------------------------------

        private static byte[] Bytes(string s) { return Encoding.UTF8.GetBytes(s); }

        private static T Wait<T>(Task<T> task) { return task.GetAwaiter().GetResult(); }
        private static void Wait(Task task) { task.GetAwaiter().GetResult(); }

        /// <summary>Contrat ISecretStore commun à toutes les implémentations (réutilisé pour KeePass en tâche 8).</summary>
        private static void SecretStoreContract(ISecretStore store)
        {
            Secret s = Wait(store.AddAsync("anthropic_api_key", Bytes("sk-ant-1"), new[] { "API.Anthropic.com:443" }, T0));
            Check.Eq("api.anthropic.com", s.AllowedHosts[0], "hôtes normalisés à l'ajout");
            Check.True(s.UsageCount == 0 && s.LastUsedAt == null && !s.Quarantined && s.CreatedAt == T0, "métadonnées initiales");
            Check.Eq("sk-ant-1", Encoding.UTF8.GetString(Wait(store.ValueAsync("anthropic_api_key"))), "valeur relue");
            Check.Eq(SecretStoreErrorKind.Duplicate, Check.Throws<SecretStoreException>(delegate { Wait(store.AddAsync("Anthropic_API_Key", Bytes("x"), new[] { "h.example" }, T0)); }, "doublon insensible à la casse").Kind, "Duplicate");
            Check.Eq(SecretStoreErrorKind.InvalidName, Check.Throws<SecretStoreException>(delegate { Wait(store.AddAsync("bad name", Bytes("x"), new[] { "h.example" }, T0)); }, "nom invalide").Kind, "InvalidName");
            Check.Eq(SecretStoreErrorKind.InvalidAllowedHosts, Check.Throws<SecretStoreException>(delegate { Wait(store.AddAsync("other", Bytes("x"), new string[0], T0)); }, "hôtes vides").Kind, "InvalidAllowedHosts");
            Check.Eq(SecretStoreErrorKind.UnknownSecret, Check.Throws<SecretStoreException>(delegate { Wait(store.ValueAsync("nope")); }, "inconnu").Kind, "UnknownSecret");
            Check.Eq(SecretStoreErrorKind.UnknownSecret, Check.Throws<SecretStoreException>(delegate { Wait(store.ValueAsync("ANTHROPIC_API_KEY")); }, "la recherche est exacte").Kind, "casse exacte en lecture");

            Wait(store.AddAsync("github_token", Bytes("ghp"), new[] { "api.github.com" }, T0.AddSeconds(1)));
            IList<Secret> list = Wait(store.ListAsync());
            Check.Eq("anthropic_api_key,github_token", string.Join(",", new List<Secret>(list).ConvertAll(delegate(Secret x) { return x.Name; })), "liste triée par nom");

            Secret upd = Wait(store.UpdateAsync("github_token", new[] { "api.github.com", "Uploads.GitHub.com" }));
            Check.Eq("api.github.com,uploads.github.com", string.Join(",", upd.AllowedHosts), "Update remplace et normalise les hôtes");
            Check.Throws<SecretStoreException>(delegate { Wait(store.UpdateAsync("github_token", new[] { "bad host" })); }, "Update valide");
            Secret rot = Wait(store.RotateAsync("github_token", Bytes("ghp2")));
            Check.Eq("ghp2", Encoding.UTF8.GetString(Wait(store.ValueAsync("github_token"))), "valeur tournée");
            Check.Eq(T0.AddSeconds(1), rot.CreatedAt, "Rotate conserve created_at");
            Secret used = Wait(store.RecordUsageAsync("github_token", T0.AddDays(1)));
            used = Wait(store.RecordUsageAsync("github_token", T0.AddDays(2)));
            Check.True(used.UsageCount == 2 && used.LastUsedAt == T0.AddDays(2), "RecordUsage incrémente et date");
            Check.True(Wait(store.SetQuarantinedAsync("github_token", true)).Quarantined, "quarantaine");
            Check.True(Wait(store.SecretAsync("github_token")).Quarantined, "quarantaine persistée");
            Wait(store.DeleteAsync("github_token"));
            Check.Throws<SecretStoreException>(delegate { Wait(store.SecretAsync("github_token")); }, "supprimé");
            Check.Throws<SecretStoreException>(delegate { Wait(store.DeleteAsync("github_token")); }, "suppression d'un inconnu");
            Check.Eq(1, Wait(store.ListAsync()).Count, "un secret restant");
        }

        private static void SecretStore_InMemoryContract()
        {
            SecretStoreContract(new InMemorySecretStore());
        }

        private static void SecretStore_InMemoryDefensiveCopies()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            byte[] value = Bytes("abc");
            Wait(store.AddAsync("k", value, new[] { "h.example" }, T0));
            value[0] = (byte)'z';
            byte[] read = Wait(store.ValueAsync("k"));
            Check.Eq("abc", Encoding.UTF8.GetString(read), "le tableau du client n'est pas partagé");
            read[0] = (byte)'z';
            Check.Eq("abc", Encoding.UTF8.GetString(Wait(store.ValueAsync("k"))), "le tableau rendu n'est pas partagé");
        }

        private static void SecretStore_Cache()
        {
            InMemorySecretStore inner = new InMemorySecretStore();
            DateTime now = T0;
            SecretCache cache = new SecretCache(inner, 2, TimeSpan.FromMinutes(5), delegate { return now; });
            Wait(cache.AddAsync("a", Bytes("1"), new[] { "h.example" }, T0));
            Wait(cache.AddAsync("b", Bytes("2"), new[] { "h.example" }, T0));
            Wait(cache.AddAsync("c", Bytes("3"), new[] { "h.example" }, T0));
            Wait(cache.ValueAsync("a"));
            Wait(inner.RotateAsync("a", Bytes("1bis")));
            Check.Eq("1", Encoding.UTF8.GetString(Wait(cache.ValueAsync("a"))), "servi depuis le cache (valeur de l'inner modifiée par derrière)");
            Wait(cache.ValueAsync("b"));
            Wait(cache.ValueAsync("c"));
            Check.Eq(2, cache.CachedCount, "LRU borné à 2");
            Check.Eq("1bis", Encoding.UTF8.GetString(Wait(cache.ValueAsync("a"))), "a évincé (le moins récemment utilisé), relu depuis l'inner");
            now = now.AddMinutes(6);
            Wait(inner.RotateAsync("a", Bytes("1ter")));
            Check.Eq("1ter", Encoding.UTF8.GetString(Wait(cache.ValueAsync("a"))), "TTL 5 min expiré");
            Wait(cache.RotateAsync("a", Bytes("1quater")));
            Check.Eq("1quater", Encoding.UTF8.GetString(Wait(cache.ValueAsync("a"))), "Rotate via le cache invalide");
            Wait(cache.ValueAsync("c"));
            Wait(cache.DeleteAsync("c"));
            Check.Throws<SecretStoreException>(delegate { Wait(cache.ValueAsync("c")); }, "Delete via le cache invalide");
            Check.Eq(2, Wait(cache.ListAsync()).Count, "les autres opérations passent à l'inner");
        }

        private static void EnvSecrets_Load()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Hashtable env = new Hashtable();
            env["IRIS_SECRET_anthropic_api_key"] = "sk-ant";
            env["IRIS_SECRET_anthropic_api_key_HOSTS"] = "api.anthropic.com, API.Anthropic.com:443";
            env["IRIS_SECRET_github"] = "ghp";
            env["IRIS_SECRET_github_HOSTS"] = "api.github.com";
            env["PATH"] = "C:\\Windows";
            Check.Eq(2, EnvSecrets.LoadInto(store, env, T0), "deux secrets chargés");
            Check.Eq("api.anthropic.com", string.Join(",", Wait(store.SecretAsync("anthropic_api_key")).AllowedHosts), "hôtes normalisés et dédoublonnés");
            Check.Eq("sk-ant", Encoding.UTF8.GetString(Wait(store.ValueAsync("anthropic_api_key"))), "valeur");
        }

        private static void EnvSecrets_MissingHosts_Ignored()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Warn;
            Hashtable env = new Hashtable();
            env["IRIS_SECRET_nohosts"] = "v";
            env["IRIS_SECRET_emptyhosts"] = "v";
            env["IRIS_SECRET_emptyhosts_HOSTS"] = " , ";
            env["IRIS_SECRET_bad name"] = "v";
            env["IRIS_SECRET_bad name_HOSTS"] = "h.example";
            env["IRIS_SECRET_badhost"] = "v";
            env["IRIS_SECRET_badhost_HOSTS"] = "not a host";
            env["IRIS_SECRET_empty"] = "";
            env["IRIS_SECRET_empty_HOSTS"] = "h.example";
            Check.Eq(0, EnvSecrets.LoadInto(store, env, T0), "aucun secret sans scoping valide");
            Check.Eq(0, Wait(store.ListAsync()).Count, "store vide");
            string text = log.ToString();
            Log.Reset();
            Check.True(text.Contains("nohosts") && text.Contains("emptyhosts") && text.Contains("bad name") && text.Contains("badhost") && text.Contains("empty"), "un avertissement par variable ignorée");
            Check.True(!text.Contains("\"v\"") && !text.Contains(" v ") , "aucune valeur dans le log");
        }
    }
}
