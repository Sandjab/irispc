# Phase 1 — IrisKit (coffre, config, CA, events) : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `irisd --foreground` crée ou ouvre le coffre KeePass, charge ou génère le CA, écrit `data\ca.pem`, charge `config.json`, ouvre le journal d'events, puis attend Ctrl+C ; toute la logique vit dans `IrisKit` et est testée sans réseau.

**Architecture:** `IrisKit` (namespace `IrisKit`) reçoit, dossier par dossier, les briques sans UI de la spec §5 : `Json` (parseur `JavaScriptSerializer` + émetteur maison ordonné), `Models`, `Logging`, `Config` + `ConfigStore` (écriture atomique, backups), `Events` (ring, bus, JSONL), `SecretStore` (`ISecretStore`, mémoire, cache LRU, `KeePassVault` bas niveau, `KeePassSecretStore`, `SecretsMetaStore`, `VaultSession`), `CA` (`CAManager` sur un `ICAKeyStore` KeePass ou mémoire). Le daemon (`Irisd`) n'orchestre que : `Entry.Run(args, stdout, stderr, console, cancel)` est testable avec une console scriptée. Tout est synchrone sous verrou côté coffre (I/O rares) et exposé en `Task` conformément à l'interface de la spec.

**Tech Stack:** C# 5, .NET Framework 4.8, `csc.exe` natif, `KeePassLib` (dans `KeePass.exe` 2.61.1), `System.Web.Extensions` (`JavaScriptSerializer`), `System.Security.Cryptography` (`ECDsaCng`, `CertificateRequest`, `X509SignatureGenerator`).

**Spec:** `docs/superpowers/specs/2026-10-17-socle-design.md` (§3 dossier portable, §4 coffre, §5 cœur, §7 daemon, §8 sécurité, §9 tests, §11 phase 1). Amont : `../Iris/SPECS.md` §5 (modèles), §6 (config.json), §11.1 (CA), `../Iris/Sources/IrisKit/{Models,Config,Events,SecretStore,CA}`, `../Iris/Tests/IrisKitTests/{ModelsTests.swift,Config/}` (fixtures). Contexte : `CLAUDE.md`. Vérifications préalables (spikes du 2026-10-17, code jetable) : KeePassLib via `-r:KeePass.exe` ; `ECDsaCng` éphémère exporte en `Pkcs8PrivateBlob` (165 octets), `CngKey.Import` le relit, `X509SignatureGenerator.CreateForECDsa` signe une feuille vérifiable par `X509Chain`, `CngKey.Delete` supprime bien le conteneur d'une clé persistée.

## Global Constraints

- **C# 5 strict** (csc `v4.0.30319`) : pas de `$""`, `?.`, `nameof`, `out var`, tuples, fonctions locales, membres expression-bodied, initialiseurs d'auto-propriétés, `catch … when`, initialiseurs d'index `[k] = v`. `async`/`await`, lambdas, `Task.FromResult` sont permis.
- Références : `System.dll, System.Core.dll, System.Web.Extensions.dll, System.Security.dll` et `vendor\KeePass-2.61.1\KeePass.exe`. Aucun NuGet.
- Flags csc : `-nologo -codepage:65001 -target:exe -optimize+` ; depuis Git Bash, chemins de sources en antislash entre apostrophes et `.bat` par chemin absolu (`cmd //c 'D:\Dev\irispc\test.bat'`).
- Un fichier par responsabilité, ~300 lignes max ; `// ----` pour sectionner. Textes utilisateur en français, identifiants et protocole en anglais, identiques à IRIS.
- Formats de fil **identiques à IRIS** : clés `snake_case` (`allowed_hosts`, `created_at`, `last_used_at`, `usage_count`, `status_code`, `duration_ms`, `substituted_secrets`, `secret_name`, `detected_at`, `system_alert`, `on_exfil_attempt`, `max_substitutions_per_minute`, `event_retention_days`, `event_ring_size`, `max_count`) ; valeurs d'enums `substituted|passThrough|noMatch|exfilBlocked|error|systemAlert|pluginBlocked|pluginResponded`, `hostMismatch|nonCanonicalLocation|multipleSecrets|suspiciousContentType|volumeAnomaly`, `low|medium|high`, `header|queryString|urlPath|body`, `default|user`, `block_only|block_and_notify|block_notify_pause`. Dates ISO 8601 UTC `yyyy-MM-ddTHH:mm:ssZ` en écriture, avec ou sans fraction en lecture.
- **Niveaux de log = valeurs IRIS** `trace|debug|info|warn|error` (config `broker.log_level` et `--log-level`). La spec socle §5.5 et §7 écrivent `debug|info|warning|error` : c'est une divergence involontaire avec le format `config.json` d'IRIS qui « ne change pas » ; la tâche 10 corrige la spec et `Arguments.LogLevels`.
- Seule divergence de fil assumée : `broker.admin_pipe` remplace `broker.admin_socket` (spec §2) ; et l'`Event` porte une clé optionnelle `flags` (tableau de `bodyTooLarge|nonUtf8|compressedBody|paused`), émise seulement quand non vide, que les décodeurs IRIS ignorent.
- Sécurité (spec §8, CLAUDE.md d'IRIS §6) : aucune valeur de secret ni mot de passe dans les logs, les events, les snippets, les arguments ou l'environnement (sauf `IRIS_SECRET_*` du mode `--in-memory-secrets`, marqué DEBUG). La clé privée du CA n'est sur disque que dans `iris.kdbx` (champ protégé). Un test vérifie que les dumps ring + journal + log ne contiennent jamais une valeur.
- Tests : `tests\Tests.cs` + fichiers `partial class TestMain` ; **aucun test n'ouvre une base utilisateur** : les bases KeePass de test sont créées dans `%TEMP%\irispc-tests\<guid>\` et supprimées.
- Codes de sortie de `irisd` (spec §7) : 0 normal, 1 données ou config, 2 coffre, 3 port (phase 2), 4 argument invalide.
- Git : branche `feat/phase-1-iriskit` (créée), commits conventionnels, PR avec checklist, merge en squash après confirmation explicite de l'utilisateur.
- Les cinq mineurs différés de la revue de phase 0 sont repris : `--data` fait d'espaces refusé (tâche 10), constantes de sortie nommées (tâche 10), `Entry.Run` testable (tâche 10), `ci.yml` sans double run + `permissions` (tâche 11), formulation CLAUDE.md « trois fichiers KeePass » (tâche 11).

## Review Focus

1. **Mot de passe maître erroné trois fois** : message clair, aucune trace du mot de passe, sortie code 2 (pas une exception brute). Test `Entry_WrongPasswordThreeTimes_Exit2` (tâche 10).
2. **`config.json` corrompu au démarrage** : copie `backups\config-corrupted-<h>.json`, reseed, event `systemAlert` sévérité `high`, démarrage continué. Test `ConfigStore_Corrupted_DegradedBoot` (tâche 4) et `Entry_CorruptedConfig_StillStarts` (tâche 10).
3. **Base ouverte dans KeePass.exe (`iris.kdbx.lock` présent)** : lecture permise, écriture refusée `VaultBusy` sans toucher la base ni créer de backup. Test `KeePass_LockFile_VaultBusy` (tâche 8).
4. **Valeur de secret dans un dump** : après add/value/usage, aucun `Event`, ligne JSONL ou ligne de log ne contient la valeur ; la redaction est `[REDACTED:<8 hex>]`. Test `Security_NoSecretValueInDumps` (tâche 10).
5. **`IRIS_SECRET_<NAME>` sans `_HOSTS`** : secret ignoré avec avertissement, jamais chargé sans scoping. Test `EnvSecrets_MissingHosts_Ignored` (tâche 6).

---

## Structure des fichiers de la phase 1

| Fichier | Responsabilité |
|---|---|
| `src\IrisKit\Json\JsonParser.cs` | `Json.Parse`, `JsonException`, dates ISO 8601 (`Json.FormatDate`, `Json.ParseDate`) |
| `src\IrisKit\Json\JsonObject.cs` | lecture typée d'un objet JSON (`String`, `Int`, `Bool`, `Object`, `Array`, `StringArray`, `Has`) |
| `src\IrisKit\Json\JsonWriter.cs` | `Json.Emit` (indent 2) et `Json.EmitCompact` (une ligne) sur `IDictionary`/`IEnumerable`/scalaires/`DateTime` |
| `src\IrisKit\Models\HostName.cs` | `HostName.IsValid`, `HostName.Normalize` (minuscules, sans port) |
| `src\IrisKit\Models\Secret.cs` | `Secret` (sans valeur), validation du nom et des hôtes, `ToJson`/`FromJson`, `With…` |
| `src\IrisKit\Models\MITMRule.cs` | `MITMRule`, `RuleOrigin` |
| `src\IrisKit\Models\Alert.cs` | `Alert`, `SystemAlert`, `AlertSeverity`, `ExfilRule`, `AlertLocation` |
| `src\IrisKit\Models\Event.cs` | `Event`, `EventKind`, `EventFlags` |
| `src\IrisKit\Logging\Log.cs` | `LogLevel`, `Log` (console horodatée, niveau minimum) |
| `src\IrisKit\Logging\Redaction.cs` | `Redaction.Redact` → `[REDACTED:xxxxxxxx]` |
| `src\IrisKit\Config\Config.cs` | `Config`, `BrokerConfig`, `SecurityConfig`, `BackupsConfig`, `ExfilPolicy`, `ConfigException`, défauts, validation, JSON |
| `src\IrisKit\Config\Backups.cs` | copie horodatée + rotation par préfixe (config et kdbx) |
| `src\IrisKit\Config\ConfigStore.cs` | seed, chargement, démarrage dégradé, `Save` atomique, `ConfigIOException` |
| `src\IrisKit\Events\EventRing.cs` | anneau borné, totaux par kind |
| `src\IrisKit\Events\EventsBus.cs` | abonnés synchrones in-process |
| `src\IrisKit\Events\JsonlEventStore.cs` | un fichier par jour UTC, purge |
| `src\IrisKit\Events\EventPipeline.cs` | `Emit` → ring + journal + bus |
| `src\IrisKit\SecretStore\ISecretStore.cs` | interface, `SecretStoreException`, `SecretStoreErrorKind` |
| `src\IrisKit\SecretStore\InMemorySecretStore.cs` | implémentation mémoire (tests, `--in-memory-secrets`) |
| `src\IrisKit\SecretStore\SecretCache.cs` | décorateur LRU 32 / TTL 5 min sur `ValueAsync` |
| `src\IrisKit\SecretStore\EnvSecrets.cs` | chargement `IRIS_SECRET_<NAME>` / `_HOSTS` |
| `src\IrisKit\SecretStore\SecretsMetaStore.cs` | `secrets-meta.json`, débounce 2 s, purge, écriture atomique |
| `src\IrisKit\SecretStore\KeePassVault.cs` | bas niveau kdbx : création, ouverture, groupes `secrets`/`ca`, `.lock`, backup, `Save` |
| `src\IrisKit\SecretStore\KeePassSecretStore.cs` | `ISecretStore` sur `KeePassVault` + `SecretsMetaStore` |
| `src\IrisKit\SecretStore\VaultSession.cs` | chemin du coffre, `Exists`, `Create(SecureString)`, `Unlock(SecureString)` |
| `src\IrisKit\CA\CACrypto.cs` | clé ECDSA P-256, PKCS#8, certificat racine auto-signé, série aléatoire, PEM |
| `src\IrisKit\CA\CAKeyStore.cs` | `CAMaterial`, `ICAKeyStore`, `InMemoryCAKeyStore`, `KeePassCAKeyStore` |
| `src\IrisKit\CA\CAManager.cs` | `EnsureCA`, `CACertificate`, export `ca.pem` |
| `src\IrisKit\DataDir.cs` | résolution de `data\`, création, test d'écriture, `DataDirException` |
| `src\irisd\ExitCodes.cs` | constantes 0/1/2/3/4 |
| `src\irisd\IConsoleInput.cs` | `IConsoleInput.ReadPassword(prompt) : SecureString` + `ConsoleInput` (saisie masquée) |
| `src\irisd\Daemon.cs` | séquence de démarrage de la spec §7, attente, arrêt propre |
| `src\irisd\Entry.cs` | `Entry.Run(args, stdout, stderr, console, cancel) : int` |
| `src\irisd\Program.cs` | `Main` : Ctrl+C → annulation, délègue à `Entry.Run` |
| `tests\TestSupport.cs` | `TestDir`, `Secure(string)`, `ScriptedConsoleInput`, `StringWriter` helpers |
| `tests\JsonTests.cs`, `ModelsTests.cs`, `LoggingTests.cs`, `ConfigTests.cs`, `EventsTests.cs`, `SecretStoreTests.cs`, `MetaStoreTests.cs`, `KeePassTests.cs`, `CATests.cs`, `DaemonTests.cs` | `partial class TestMain`, une méthode par test |

Chaque tâche ajoute ses sources à **`IRISKIT_SOURCES`** (ou `IRISD_SOURCES`, `TEST_SOURCES`) dans `test.bat` et `build.bat` ; la liste complète finale est dans la tâche 11.

---

### Task 1: JSON — parseur, lecture typée, émetteur ordonné

**Files:**
- Create: `src\IrisKit\Json\JsonParser.cs`
- Create: `src\IrisKit\Json\JsonObject.cs`
- Create: `src\IrisKit\Json\JsonWriter.cs`
- Create: `tests\JsonTests.cs`
- Modify: `tests\Tests.cs` (enregistrement), `test.bat`, `build.bat` (sources)

**Interfaces:**
- Consumes: `Iris.Tests.Check` (phase 0).
- Produces: `IrisKit.Json.Parse(string) : object` (objets → `IDictionary<string, object>`, tableaux → `IList<object>`, nombres → `long` ou `double`, `string`, `bool`, `null`) ; `Json.Emit(object) : string` (indent 2, LF) ; `Json.EmitCompact(object) : string` ; `Json.FormatDate(DateTime) : string` ; `Json.ParseDate(string) : DateTime` (Kind UTC) ; `Json.ParseObject(string) : JsonObject` ; `IrisKit.JsonException` ; `IrisKit.JsonObject` (`Has`, `String`, `OptionalString`, `Int`, `OptionalInt`, `Bool`, `Object`, `OptionalObject`, `Array`, `OptionalArray`, `StringArray`, `Raw`, `Keys`). Émission : `OrderedDictionary` (ordre d'insertion), toute `IDictionary` à clés `string`, `IEnumerable` non-string → tableau, `DateTime` → ISO UTC.

- [ ] **Step 1: Écrire `tests\JsonTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Json ------------------------------------------------------

        private static void Json_RoundTripOrdered()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["version"] = 1L;
            o["name"] = "irisé";
            o["enabled"] = true;
            o["nothing"] = null;
            o["ratio"] = 0.5;
            o["hosts"] = new List<object> { "a.example", "b.example" };
            OrderedDictionary inner = new OrderedDictionary();
            inner["max_count"] = 10L;
            o["backups"] = inner;
            string text = Json.Emit(o);
            Check.Eq("{\n  \"version\": 1,\n  \"name\": \"irisé\",\n  \"enabled\": true,\n  \"nothing\": null,\n  \"ratio\": 0.5,\n  \"hosts\": [\n    \"a.example\",\n    \"b.example\"\n  ],\n  \"backups\": {\n    \"max_count\": 10\n  }\n}", text, "indentation 2, ordre d'insertion, LF");
            JsonObject back = Json.ParseObject(text);
            Check.Eq(1L, back.Int("version"), "entier relu en long");
            Check.Eq("irisé", back.String("name"), "chaîne non ASCII intacte");
            Check.True(back.Bool("enabled", false), "booléen");
            Check.True(back.Has("nothing") && back.Raw("nothing") == null, "null conservé");
            Check.Eq(0.5, (double)back.Raw("ratio"), "double");
            Check.Eq("a.example,b.example", string.Join(",", back.StringArray("hosts")), "tableau de chaînes");
            Check.Eq(10L, back.Object("backups").Int("max_count"), "objet imbriqué");
            Check.Eq("version,name,enabled,nothing,ratio,hosts,backups", string.Join(",", back.Keys), "ordre des clés conservé en lecture");
        }

        private static void Json_CompactAndEscapes()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["s"] = "a\"b\\c\n\t\u0001é";
            o["empty"] = new OrderedDictionary();
            o["list"] = new object[0];
            Check.Eq("{\"s\":\"a\\\"b\\\\c\\n\\t\\u0001é\",\"empty\":{},\"list\":[]}", Json.EmitCompact(o), "échappements, objets et tableaux vides");
            Check.Eq("a\"b\\c\n\t\u0001é", Json.ParseObject(Json.EmitCompact(o)).String("s"), "aller-retour des échappements");
        }

        private static void Json_Dates()
        {
            DateTime d = new DateTime(2026, 10, 17, 7, 49, 47, DateTimeKind.Utc);
            Check.Eq("2026-10-17T07:49:47Z", Json.FormatDate(d), "format ISO UTC sans fraction");
            Check.Eq("2026-10-17T07:49:47Z", Json.FormatDate(d.ToLocalTime()), "une date locale est convertie en UTC");
            Check.Eq(d, Json.ParseDate("2026-10-17T07:49:47Z"), "lecture sans fraction");
            Check.Eq(d.AddMilliseconds(123), Json.ParseDate("2026-10-17T07:49:47.123Z"), "lecture avec fraction");
            Check.Eq(d, Json.ParseDate("2026-10-17T09:49:47+02:00"), "décalage horaire ramené en UTC");
            Check.Eq(DateTimeKind.Utc, Json.ParseDate("2026-10-17T07:49:47Z").Kind, "Kind UTC");
            Check.Throws<JsonException>(delegate { Json.ParseDate("hier"); }, "date invalide");
            OrderedDictionary o = new OrderedDictionary();
            o["at"] = d;
            Check.Eq("{\"at\":\"2026-10-17T07:49:47Z\"}", Json.EmitCompact(o), "DateTime émis en ISO");
        }

        private static void Json_Errors()
        {
            Check.Throws<JsonException>(delegate { Json.Parse("{"); }, "JSON tronqué");
            Check.Throws<JsonException>(delegate { Json.Parse(""); }, "vide");
            Check.Throws<JsonException>(delegate { Json.ParseObject("[1]"); }, "ParseObject sur un tableau");
            JsonObject o = Json.ParseObject("{\"n\":\"x\",\"i\":3,\"l\":[1]}");
            JsonException ex = Check.Throws<JsonException>(delegate { o.String("absent"); }, "champ requis absent");
            Check.True(ex.Message.Contains("absent"), "le message cite la clé");
            Check.Throws<JsonException>(delegate { o.Int("n"); }, "type inattendu");
            Check.Throws<JsonException>(delegate { o.StringArray("i"); }, "tableau attendu");
            Check.Eq(null, o.OptionalString("absent"), "optionnel absent → null");
            Check.Eq(7L, o.OptionalInt("absent") ?? 7L, "optionnel entier absent");
            Check.Throws<JsonException>(delegate { Json.Emit(new object()); }, "type non sérialisable");
            Check.Throws<JsonException>(delegate { Json.Emit(double.NaN); }, "NaN refusé");
        }

        private static void Json_Numbers()
        {
            object parsed = Json.Parse("{\"a\":1,\"b\":12345678901,\"c\":1.25,\"d\":-3,\"e\":1e3}");
            JsonObject o = new JsonObject((IDictionary<string, object>)parsed);
            Check.Eq(1L, o.Int("a"), "petit entier");
            Check.Eq(12345678901L, o.Int("b"), "grand entier");
            Check.Eq(1.25, (double)o.Raw("c"), "décimal → double");
            Check.Eq(-3L, o.Int("d"), "négatif");
            Check.Eq(1000.0, Convert.ToDouble(o.Raw("e")), "notation exponentielle (long ou double selon le parseur, valeur 1000)");
            Check.Eq("[1,12345678901,1.25,-3]", Json.EmitCompact(new object[] { 1, 12345678901L, 1.25, -3 }), "émission des nombres en invariant");
        }
    }
}
```

Dans `tests\Tests.cs`, `Main`, après les lignes `Arguments`, ajouter :

```csharp
            Check.Run("Json : aller-retour ordonné, indentation", Json_RoundTripOrdered);
            Check.Run("Json : compact et échappements", Json_CompactAndEscapes);
            Check.Run("Json : dates ISO 8601 UTC", Json_Dates);
            Check.Run("Json : erreurs de parse et d'accès", Json_Errors);
            Check.Run("Json : nombres", Json_Numbers);
```

Dans `test.bat`, remplacer la ligne `set TEST_SOURCES=` par :

```bat
set TEST_SOURCES="%TESTS%\Check.cs" "%TESTS%\Tests.cs" "%TESTS%\JsonTests.cs"
```

- [ ] **Step 2: Vérifier l'échec**

```bash
cmd //c 'D:\Dev\irispc\test.bat' 2>&1 | grep -E 'error CS' | head -3
```

Attendu : `CS0246 ... 'JsonObject'` / `'Json'`, compilation impossible.

- [ ] **Step 3: Écrire `src\IrisKit\Json\JsonParser.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Web.Script.Serialization;

namespace IrisKit
{
    /// <summary>JSON invalide, type inattendu ou champ manquant. Message en français.</summary>
    public sealed class JsonException : Exception
    {
        public JsonException(string message) : base(message) { }
        public JsonException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// Façade JSON (spec §5.2) : lecture via JavaScriptSerializer, écriture maison ordonnée (JsonWriter.cs),
    /// dates ISO 8601 UTC. Les modèles ont des ToJson()/FromJson() explicites, jamais de réflexion.
    /// </summary>
    public static partial class Json
    {
        private const string DateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

        /// <summary>Objets → IDictionary&lt;string, object&gt; (ordre d'insertion), tableaux → IList&lt;object&gt;, nombres → long ou double.</summary>
        public static object Parse(string text)
        {
            if (string.IsNullOrEmpty(text)) throw new JsonException("JSON vide");
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            serializer.RecursionLimit = 64;
            object raw;
            try
            {
                raw = serializer.DeserializeObject(text);
            }
            catch (ArgumentException ex)
            {
                throw new JsonException("JSON invalide : " + ex.Message, ex);
            }
            catch (InvalidOperationException ex)
            {
                throw new JsonException("JSON invalide : " + ex.Message, ex);
            }
            return Normalize(raw);
        }

        public static JsonObject ParseObject(string text)
        {
            IDictionary<string, object> dict = Parse(text) as IDictionary<string, object>;
            if (dict == null) throw new JsonException("objet JSON attendu à la racine");
            return new JsonObject(dict);
        }

        /// <summary>Ramène les types de JavaScriptSerializer à long / double / string / bool / null / dict / liste.</summary>
        private static object Normalize(object value)
        {
            if (value == null || value is string || value is bool) return value;
            if (value is int) return (long)(int)value;
            if (value is long) return value;
            if (value is decimal)
            {
                decimal d = (decimal)value;
                if (d == decimal.Truncate(d) && d >= long.MinValue && d <= long.MaxValue) return (long)d;
                return (double)d;
            }
            if (value is double || value is float) return Convert.ToDouble(value, CultureInfo.InvariantCulture);
            IDictionary<string, object> dict = value as IDictionary<string, object>;
            if (dict != null)
            {
                Dictionary<string, object> result = new Dictionary<string, object>();
                foreach (KeyValuePair<string, object> kv in dict) result[kv.Key] = Normalize(kv.Value);
                return result;
            }
            object[] array = value as object[];
            if (array != null)
            {
                List<object> list = new List<object>(array.Length);
                foreach (object item in array) list.Add(Normalize(item));
                return list;
            }
            throw new JsonException("valeur JSON inattendue : " + value.GetType().Name);
        }

        // ---- Dates -----------------------------------------------------

        public static string FormatDate(DateTime value)
        {
            return value.ToUniversalTime().ToString(DateFormat, CultureInfo.InvariantCulture);
        }

        /// <summary>ISO 8601 avec ou sans fraction, Z ou décalage ; résultat en Kind UTC.</summary>
        public static DateTime ParseDate(string text)
        {
            DateTime parsed;
            if (text == null || !DateTime.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed)
                || text.IndexOf('T') < 0)
                throw new JsonException("date ISO 8601 attendue, reçu : " + (text ?? "null"));
            return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\Json\JsonObject.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Lecture typée d'un objet JSON parsé. Les champs requis absents ou d'un autre type lèvent JsonException.</summary>
    public sealed class JsonObject
    {
        private readonly IDictionary<string, object> raw;

        public JsonObject(IDictionary<string, object> raw)
        {
            if (raw == null) throw new ArgumentNullException("raw");
            this.raw = raw;
        }

        public IEnumerable<string> Keys { get { return raw.Keys; } }

        public bool Has(string key) { return raw.ContainsKey(key); }

        public object Raw(string key)
        {
            object value;
            return raw.TryGetValue(key, out value) ? value : null;
        }

        public string String(string key) { return Require<string>(key, "chaîne"); }

        public string OptionalString(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            string s = value as string;
            if (s == null) throw new JsonException("champ " + key + " : chaîne attendue");
            return s;
        }

        public long Int(string key)
        {
            object value = Require<object>(key, "entier");
            if (value is long) return (long)value;
            throw new JsonException("champ " + key + " : entier attendu");
        }

        public long? OptionalInt(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            if (value is long) return (long)value;
            throw new JsonException("champ " + key + " : entier attendu");
        }

        public bool Bool(string key, bool defaultValue)
        {
            object value = Raw(key);
            if (value == null) return defaultValue;
            if (value is bool) return (bool)value;
            throw new JsonException("champ " + key + " : booléen attendu");
        }

        public JsonObject Object(string key)
        {
            return new JsonObject(Require<IDictionary<string, object>>(key, "objet"));
        }

        public JsonObject OptionalObject(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            IDictionary<string, object> dict = value as IDictionary<string, object>;
            if (dict == null) throw new JsonException("champ " + key + " : objet attendu");
            return new JsonObject(dict);
        }

        public IList<object> Array(string key) { return Require<IList<object>>(key, "tableau"); }

        public IList<object> OptionalArray(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            IList<object> list = value as IList<object>;
            if (list == null) throw new JsonException("champ " + key + " : tableau attendu");
            return list;
        }

        public IList<string> StringArray(string key)
        {
            IList<object> items = Array(key);
            List<string> result = new List<string>(items.Count);
            foreach (object item in items)
            {
                string s = item as string;
                if (s == null) throw new JsonException("champ " + key + " : tableau de chaînes attendu");
                result.Add(s);
            }
            return result;
        }

        private T Require<T>(string key, string expected) where T : class
        {
            object value;
            if (!raw.TryGetValue(key, out value) || value == null)
                throw new JsonException("champ manquant : " + key);
            T typed = value as T;
            if (typed == null) throw new JsonException("champ " + key + " : " + expected + " attendu");
            return typed;
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Json\JsonWriter.cs`**

```csharp
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace IrisKit
{
    public static partial class Json
    {
        /// <summary>Émission indentée (2 espaces, LF), ordre d'insertion des dictionnaires respecté.</summary>
        public static string Emit(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0, true);
            return sb.ToString();
        }

        /// <summary>Émission sur une ligne (JSONL).</summary>
        public static string EmitCompact(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0, false);
            return sb.ToString();
        }

        private static void Write(StringBuilder sb, object value, int depth, bool pretty)
        {
            if (value == null) { sb.Append("null"); return; }
            string s = value as string;
            if (s != null) { WriteString(sb, s); return; }
            if (value is bool) { sb.Append((bool)value ? "true" : "false"); return; }
            if (value is DateTime) { WriteString(sb, FormatDate((DateTime)value)); return; }
            if (value is int || value is long || value is short || value is byte || value is uint || value is ulong)
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }
            if (value is double || value is float || value is decimal)
            {
                double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) throw new JsonException("nombre non représentable en JSON");
                sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            if (value is Enum) throw new JsonException("énumération non sérialisable directement : " + value.GetType().Name);
            IDictionary dict = value as IDictionary;
            if (dict != null) { WriteObject(sb, dict, depth, pretty); return; }
            IEnumerable list = value as IEnumerable;
            if (list != null) { WriteArray(sb, list, depth, pretty); return; }
            throw new JsonException("type non sérialisable : " + value.GetType().Name);
        }

        private static void WriteObject(StringBuilder sb, IDictionary dict, int depth, bool pretty)
        {
            if (dict.Count == 0) { sb.Append("{}"); return; }
            sb.Append('{');
            bool first = true;
            foreach (DictionaryEntry entry in dict)
            {
                string key = entry.Key as string;
                if (key == null) throw new JsonException("clé JSON non textuelle");
                if (!first) sb.Append(',');
                first = false;
                NewLine(sb, depth + 1, pretty);
                WriteString(sb, key);
                sb.Append(pretty ? ": " : ":");
                Write(sb, entry.Value, depth + 1, pretty);
            }
            NewLine(sb, depth, pretty);
            sb.Append('}');
        }

        private static void WriteArray(StringBuilder sb, IEnumerable list, int depth, bool pretty)
        {
            sb.Append('[');
            bool first = true;
            foreach (object item in list)
            {
                if (!first) sb.Append(',');
                first = false;
                NewLine(sb, depth + 1, pretty);
                Write(sb, item, depth + 1, pretty);
            }
            if (!first) NewLine(sb, depth, pretty);
            sb.Append(']');
        }

        private static void NewLine(StringBuilder sb, int depth, bool pretty)
        {
            if (!pretty) return;
            sb.Append('\n');
            sb.Append(' ', depth * 2);
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
```

- [ ] **Step 6: Ajouter les sources aux scripts**

Dans `test.bat` **et** `build.bat`, remplacer la ligne `set IRISKIT_SOURCES=...` par :

```bat
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs" "%SRC%\IrisKit\Json\JsonParser.cs" "%SRC%\IrisKit\Json\JsonObject.cs" "%SRC%\IrisKit\Json\JsonWriter.cs"
```

- [ ] **Step 7: Vérifier le vert**

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
```

Attendu : `16 test(s) réussi(s), 0 échec(s)`, `[SUCCES]`. Si `Json_RoundTripOrdered` échoue sur l'ordre des clés en lecture : `JavaScriptSerializer` rend un `Dictionary<string, object>` dont l'énumération suit l'insertion tant qu'il n'y a pas de suppression ; le `Normalize` recopie dans le même ordre. Si l'ordre diffère malgré tout, remplacer `Dictionary<string, object>` par une classe `OrderedMap : IDictionary<string, object>` adossée à une `List<KeyValuePair>` (même contrat, ordre garanti) et consigner la décision.

- [ ] **Step 8: Commit**

```bash
git add src/IrisKit/Json tests/JsonTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): façade Json (parse, lecture typée, émission ordonnée, dates ISO)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Modèles — `HostName`, `Secret`, `MITMRule`, `Alert`, `Event`

**Files:**
- Create: `src\IrisKit\Models\HostName.cs`, `Secret.cs`, `MITMRule.cs`, `Alert.cs`, `Event.cs`
- Create: `src\IrisKit\SecretStore\ISecretStore.cs` (l'exception de validation vit avec l'interface)
- Create: `tests\ModelsTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Json`, `JsonObject` (tâche 1).
- Produces: `HostName.IsValid(string) : bool`, `HostName.Normalize(string) : string` ; `Secret` (`Name`, `AllowedHosts : IList<string>`, `CreatedAt`, `LastUsedAt : DateTime?`, `UsageCount : long`, `Quarantined : bool`, ctor complet, `WithAllowedHosts`, `WithUsage(DateTime lastUsedAt, long usageCount)`, `WithQuarantined(bool)`, `ToJson() : OrderedDictionary`, `static FromJson(JsonObject)`, `static ValidateName(string)`, `static ValidateAllowedHosts(IList<string>)`, `NameRegex`) ; `MITMRule` (`Host`, `CreatedAt`, `Origin : RuleOrigin`), `RuleOrigin { Default, User }` + `RuleOriginWire.ToWire/Parse` ; `Alert`, `SystemAlert`, `AlertSeverity { Low, Medium, High }`, `ExfilRule`, `AlertLocation`, `AlertWire` (ToWire/Parse pour chaque enum) ; `Event` (`Id : Guid`, `Timestamp`, `Kind : EventKind`, `Host`, `Method`, `Path`, `StatusCode : int?`, `DurationMs : long?`, `SubstitutedSecrets : IList<string>`, `Alert`, `SystemAlert`, `Flags : EventFlags`), `EventKind` (8 valeurs), `EventFlags` [Flags] (`None, BodyTooLarge, NonUtf8, CompressedBody, Paused`), `EventWire.KindToWire/ParseKind` ; `SecretStoreException` (`Kind : SecretStoreErrorKind`, `Name`), `SecretStoreErrorKind { InvalidName, InvalidAllowedHosts, UnknownSecret, Duplicate, VaultLocked, VaultBusy, DataCorruption }`, `ISecretStore` (signatures exactes de la spec §4.4).

- [ ] **Step 1: Écrire `tests\ModelsTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Modèles ---------------------------------------------------

        private static readonly DateTime T0 = new DateTime(2023, 11, 14, 22, 13, 20, DateTimeKind.Utc); // 1_700_000_000

        private static void Models_HostName()
        {
            foreach (string ok in new[] { "api.anthropic.com", "localhost", "a-b.c1", "x".PadRight(63, 'x') + ".com" })
                Check.True(HostName.IsValid(ok), "hôte valide : " + ok);
            foreach (string bad in new[] { "", "-a.com", "a-.com", "a..b", "a b.com", "_not_a_host_", "é.com", "a:8443", "x".PadRight(64, 'x') + ".com", new string('a', 254) })
                Check.True(!HostName.IsValid(bad), "hôte invalide : " + bad);
            Check.Eq("api.anthropic.com", HostName.Normalize("API.Anthropic.COM:443"), "minuscules, port retiré");
            Check.Eq("api.anthropic.com", HostName.Normalize("  api.anthropic.com "), "espaces retirés");
        }

        private static void Models_SecretValidation()
        {
            Secret.ValidateName("anthropic_api_key");
            Secret.ValidateName("A-b_9");
            foreach (string bad in new[] { "", "a b", "é", "a.b", new string('a', 65) })
            {
                SecretStoreException ex = Check.Throws<SecretStoreException>(delegate { Secret.ValidateName(bad); }, "nom invalide : " + bad);
                Check.Eq(SecretStoreErrorKind.InvalidName, ex.Kind, "kind InvalidName");
            }
            Secret.ValidateAllowedHosts(new[] { "api.anthropic.com" });
            Check.Eq(SecretStoreErrorKind.InvalidAllowedHosts, Check.Throws<SecretStoreException>(delegate { Secret.ValidateAllowedHosts(new string[0]); }, "liste vide").Kind, "vide → InvalidAllowedHosts");
            Check.Eq(SecretStoreErrorKind.InvalidAllowedHosts, Check.Throws<SecretStoreException>(delegate { Secret.ValidateAllowedHosts(new[] { "api.anthropic.com", "bad host" }); }, "hôte invalide").Kind, "hôte invalide → InvalidAllowedHosts");
        }

        private static void Models_SecretJson()
        {
            Secret s = new Secret("anthropic_api_key", new[] { "api.anthropic.com" }, T0, T0.AddSeconds(1000), 42, false);
            string json = Json.EmitCompact(s.ToJson());
            Check.Eq("{\"name\":\"anthropic_api_key\",\"allowed_hosts\":[\"api.anthropic.com\"],\"created_at\":\"2023-11-14T22:13:20Z\",\"last_used_at\":\"2023-11-14T22:30:00Z\",\"usage_count\":42,\"quarantined\":false}", json, "fil IRIS (snake_case, dates ISO)");
            Secret back = Secret.FromJson(Json.ParseObject(json));
            Check.Eq(s.Name, back.Name, "name"); Check.Eq(42L, back.UsageCount, "usage_count");
            Check.Eq(T0.AddSeconds(1000), back.LastUsedAt.Value, "last_used_at");
            Secret noUse = Secret.FromJson(Json.ParseObject("{\"name\":\"k\",\"allowed_hosts\":[\"h.example\"],\"created_at\":\"2023-11-14T22:13:20Z\",\"usage_count\":0}"));
            Check.True(noUse.LastUsedAt == null && !noUse.Quarantined, "last_used_at et quarantined optionnels (fixture IRIS)");
            Check.True(!Json.EmitCompact(noUse.ToJson()).Contains("last_used_at"), "last_used_at omis quand null");
            Secret updated = s.WithAllowedHosts(new[] { "b.example" }).WithUsage(T0.AddDays(1), 43).WithQuarantined(true);
            Check.True(updated.Name == s.Name && updated.CreatedAt == s.CreatedAt && updated.AllowedHosts[0] == "b.example" && updated.UsageCount == 43 && updated.Quarantined, "With… conserve l'identité");
        }

        private static void Models_MITMRule()
        {
            MITMRule r = new MITMRule("api.openai.com", new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc), RuleOrigin.Default);
            Check.Eq("{\"host\":\"api.openai.com\",\"created_at\":\"1970-01-01T00:00:00Z\",\"origin\":\"default\"}", Json.EmitCompact(r.ToJson()), "origin sur le fil = default (fixture IRIS testMITMRuleEncodesOriginField)");
            MITMRule back = MITMRule.FromJson(Json.ParseObject("{\"host\":\"api.example.com\",\"created_at\":\"2023-11-14T22:13:20Z\"}"));
            Check.Eq(RuleOrigin.User, back.Origin, "origin absent → user (fixture testHostEntryDecodesWithoutOriginKeyAsUser)");
            Check.Eq(RuleOrigin.User, MITMRule.FromJson(Json.ParseObject("{\"host\":\"h.example\",\"created_at\":\"2023-11-14T22:13:20Z\",\"origin\":\"user\"}")).Origin, "origin user");
            Check.Throws<JsonException>(delegate { MITMRule.FromJson(Json.ParseObject("{\"host\":\"h.example\",\"created_at\":\"2023-11-14T22:13:20Z\",\"origin\":\"toml\"}")); }, "origin inconnu refusé");
        }

        private static void Models_EventWithAlert()
        {
            Alert alert = new Alert(AlertSeverity.High, ExfilRule.HostMismatch, "anthropic_api_key", AlertLocation.Body, "[REDACTED:abcd1234]");
            Event e = new Event(new Guid("11111111-2222-3333-4444-555555555555"), T0, EventKind.ExfilBlocked, "api.github.com", "POST", "/repos/foo/bar/issues", 201, 423, new string[0], alert, null, EventFlags.None);
            string json = Json.EmitCompact(e.ToJson());
            Check.Eq("{\"id\":\"11111111-2222-3333-4444-555555555555\",\"timestamp\":\"2023-11-14T22:13:20Z\",\"kind\":\"exfilBlocked\",\"host\":\"api.github.com\",\"method\":\"POST\",\"path\":\"/repos/foo/bar/issues\",\"status_code\":201,\"duration_ms\":423,\"substituted_secrets\":[],\"alert\":{\"severity\":\"high\",\"rule\":\"hostMismatch\",\"secret_name\":\"anthropic_api_key\",\"detected_at\":\"body\",\"snippet\":\"[REDACTED:abcd1234]\"}}", json, "fil IRIS (fixture testEventRoundTripWithAlert)");
            Event back = Event.FromJson(Json.ParseObject(json));
            Check.True(back.Id == e.Id && back.Kind == EventKind.ExfilBlocked && back.StatusCode == 201 && back.DurationMs == 423, "scalaires relus");
            Check.True(back.Alert != null && back.Alert.Rule == ExfilRule.HostMismatch && back.Alert.DetectedAt == AlertLocation.Body && back.SystemAlert == null, "alert relue");
            Check.Eq(EventFlags.None, back.Flags, "pas de flags");
        }

        private static void Models_EventSystemAlertAndFlags()
        {
            Event sys = new Event(new Guid("22222222-3333-4444-5555-666666666666"), T0, EventKind.SystemAlert, "config", "-", "-", null, null, new string[0], null, new SystemAlert(AlertSeverity.High, "config.json corrupted — defaults re-seeded"), EventFlags.None);
            string json = Json.EmitCompact(sys.ToJson());
            Check.True(json.Contains("\"kind\":\"systemAlert\"") && json.Contains("\"system_alert\":{\"severity\":\"high\",\"message\":\"config.json corrupted — defaults re-seeded\"}") && !json.Contains("status_code") && !json.Contains("\"alert\""), "system_alert émis, optionnels nuls omis");
            Event back = Event.FromJson(Json.ParseObject(json));
            Check.True(back.SystemAlert != null && back.SystemAlert.Severity == AlertSeverity.High && back.Alert == null, "system_alert relu");

            Event flagged = new Event(Guid.NewGuid(), T0, EventKind.NoMatch, "h.example", "GET", "/", 200, 5, new string[0], null, null, EventFlags.BodyTooLarge | EventFlags.Paused);
            string fjson = Json.EmitCompact(flagged.ToJson());
            Check.True(fjson.Contains("\"flags\":[\"bodyTooLarge\",\"paused\"]"), "flags émis en tableau de chaînes");
            Check.Eq(EventFlags.BodyTooLarge | EventFlags.Paused, Event.FromJson(Json.ParseObject(fjson)).Flags, "flags relus");

            Event old = Event.FromJson(Json.ParseObject("{\"id\":\"33333333-4444-5555-6666-777777777777\",\"timestamp\":\"2023-11-14T22:13:20Z\",\"kind\":\"substituted\",\"host\":\"api.anthropic.com\",\"method\":\"POST\",\"path\":\"/v1/messages\",\"substituted_secrets\":[]}"));
            Check.True(old.Alert == null && old.SystemAlert == null && old.StatusCode == null && old.Flags == EventFlags.None, "fixture IRIS sans system_alert ni flags");
        }

        private static void Models_EnumWire()
        {
            string[] kinds = { "substituted", "passThrough", "noMatch", "exfilBlocked", "error", "systemAlert", "pluginBlocked", "pluginResponded" };
            foreach (string k in kinds) Check.Eq(k, EventWire.KindToWire(EventWire.ParseKind(k)), "kind " + k);
            Check.Throws<JsonException>(delegate { EventWire.ParseKind("Substituted"); }, "kind sensible à la casse");
            foreach (string r in new[] { "hostMismatch", "nonCanonicalLocation", "multipleSecrets", "suspiciousContentType", "volumeAnomaly" })
                Check.Eq(r, AlertWire.RuleToWire(AlertWire.ParseRule(r)), "rule " + r);
            foreach (string l in new[] { "header", "queryString", "urlPath", "body" })
                Check.Eq(l, AlertWire.LocationToWire(AlertWire.ParseLocation(l)), "location " + l);
            Check.True(AlertSeverity.Low < AlertSeverity.Medium && AlertSeverity.Medium < AlertSeverity.High, "sévérités ordonnées");
            Check.Eq("[REDACTED:abcd1234]", new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, "k", AlertLocation.Header, "[REDACTED:abcd1234]").Snippet, "snippet conservé");
            Check.Eq(256, new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, "k", AlertLocation.Header, new string('x', 300)).Snippet.Length, "snippet tronqué à 256");
        }
    }
}
```

Enregistrement dans `Main` :

```csharp
            Check.Run("Modèles : validation des hôtes", Models_HostName);
            Check.Run("Modèles : validation des secrets", Models_SecretValidation);
            Check.Run("Modèles : Secret ↔ JSON", Models_SecretJson);
            Check.Run("Modèles : MITMRule ↔ JSON", Models_MITMRule);
            Check.Run("Modèles : Event avec Alert (fixture IRIS)", Models_EventWithAlert);
            Check.Run("Modèles : Event systemAlert, flags, compat", Models_EventSystemAlertAndFlags);
            Check.Run("Modèles : valeurs de fil des énumérations", Models_EnumWire);
```

`TEST_SOURCES` de `test.bat` : ajouter `"%TESTS%\ModelsTests.cs"`.

- [ ] **Step 2: Vérifier l'échec**

```bash
cmd //c 'D:\Dev\irispc\test.bat' 2>&1 | grep -E 'error CS' | head -3
```

Attendu : `CS0246` sur `HostName` / `Secret` / `Event`.

- [ ] **Step 3: Écrire `src\IrisKit\Models\HostName.cs`**

```csharp
using System;

namespace IrisKit
{
    /// <summary>Nom d'hôte DNS tel qu'IRIS le valide (Secret.isValidHost) et le compare (minuscules, sans port, exact).</summary>
    public static class HostName
    {
        public static bool IsValid(string host)
        {
            if (string.IsNullOrEmpty(host) || host.Length > 253) return false;
            string[] labels = host.Split('.');
            foreach (string label in labels)
            {
                if (label.Length < 1 || label.Length > 63) return false;
                if (label[0] == '-' || label[label.Length - 1] == '-') return false;
                foreach (char c in label)
                {
                    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
                    if (!ok) return false;
                }
            }
            return true;
        }

        /// <summary>Minuscules, espaces retirés, port retiré (`host:443` → `host`).</summary>
        public static string Normalize(string host)
        {
            if (host == null) return "";
            string h = host.Trim().ToLowerInvariant();
            int colon = h.IndexOf(':');
            return colon >= 0 ? h.Substring(0, colon) : h;
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\SecretStore\ISecretStore.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    public enum SecretStoreErrorKind
    {
        InvalidName,
        InvalidAllowedHosts,
        UnknownSecret,
        Duplicate,
        VaultLocked,
        VaultBusy,
        DataCorruption
    }

    /// <summary>Erreur typée du coffre (spec §4.4). Message en français ; ne contient jamais une valeur.</summary>
    public sealed class SecretStoreException : Exception
    {
        public SecretStoreErrorKind Kind { get; private set; }
        public string Name { get; private set; }

        public SecretStoreException(SecretStoreErrorKind kind, string name, string message) : base(message)
        {
            Kind = kind;
            Name = name;
        }

        public SecretStoreException(SecretStoreErrorKind kind, string name, string message, Exception inner) : base(message, inner)
        {
            Kind = kind;
            Name = name;
        }
    }

    /// <summary>Accès aux secrets (spec §4.4). La valeur n'est jamais loguée ni mise dans un Event.</summary>
    public interface ISecretStore
    {
        Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt);
        Task<Secret> UpdateAsync(string name, IList<string> allowedHosts);
        Task<Secret> RotateAsync(string name, byte[] newValue);
        Task DeleteAsync(string name);
        Task<byte[]> ValueAsync(string name);
        Task<Secret> SecretAsync(string name);
        Task<IList<Secret>> ListAsync();
        Task<Secret> RecordUsageAsync(string name, DateTime at);
        Task<Secret> SetQuarantinedAsync(string name, bool quarantined);
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Models\Secret.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text.RegularExpressions;

namespace IrisKit
{
    /// <summary>Métadonnées d'un secret (SPECS §5.1). La valeur n'en fait jamais partie.</summary>
    public sealed class Secret
    {
        public static readonly Regex NameRegex = new Regex("^[a-zA-Z0-9_-]{1,64}$", RegexOptions.CultureInvariant);

        public string Name { get; private set; }
        public IList<string> AllowedHosts { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public DateTime? LastUsedAt { get; private set; }
        public long UsageCount { get; private set; }
        public bool Quarantined { get; private set; }

        public Secret(string name, IList<string> allowedHosts, DateTime createdAt, DateTime? lastUsedAt, long usageCount, bool quarantined)
        {
            Name = name;
            AllowedHosts = new List<string>(allowedHosts).AsReadOnly();
            CreatedAt = createdAt;
            LastUsedAt = lastUsedAt;
            UsageCount = usageCount;
            Quarantined = quarantined;
        }

        public Secret WithAllowedHosts(IList<string> allowedHosts) { return new Secret(Name, allowedHosts, CreatedAt, LastUsedAt, UsageCount, Quarantined); }
        public Secret WithUsage(DateTime lastUsedAt, long usageCount) { return new Secret(Name, AllowedHosts, CreatedAt, lastUsedAt, usageCount, Quarantined); }
        public Secret WithQuarantined(bool quarantined) { return new Secret(Name, AllowedHosts, CreatedAt, LastUsedAt, UsageCount, quarantined); }

        // ---- Validation --------------------------------------------------

        public static void ValidateName(string name)
        {
            if (name == null || !NameRegex.IsMatch(name))
                throw new SecretStoreException(SecretStoreErrorKind.InvalidName, name, "nom de secret invalide : " + (name ?? "null") + " (attendu : ^[a-zA-Z0-9_-]{1,64}$)");
        }

        public static void ValidateAllowedHosts(IList<string> hosts)
        {
            if (hosts == null || hosts.Count == 0)
                throw new SecretStoreException(SecretStoreErrorKind.InvalidAllowedHosts, null, "allowed_hosts ne peut pas être vide");
            foreach (string host in hosts)
                if (!HostName.IsValid(host))
                    throw new SecretStoreException(SecretStoreErrorKind.InvalidAllowedHosts, null, "hôte invalide dans allowed_hosts : " + host);
        }

        // ---- JSON --------------------------------------------------------

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["name"] = Name;
            o["allowed_hosts"] = new List<string>(AllowedHosts);
            o["created_at"] = CreatedAt;
            if (LastUsedAt.HasValue) o["last_used_at"] = LastUsedAt.Value;
            o["usage_count"] = UsageCount;
            o["quarantined"] = Quarantined;
            return o;
        }

        public static Secret FromJson(JsonObject o)
        {
            string lastUsed = o.OptionalString("last_used_at");
            return new Secret(
                o.String("name"),
                o.StringArray("allowed_hosts"),
                Json.ParseDate(o.String("created_at")),
                lastUsed == null ? (DateTime?)null : Json.ParseDate(lastUsed),
                o.Int("usage_count"),
                o.Bool("quarantined", false));
        }
    }
}
```

- [ ] **Step 6: Écrire `src\IrisKit\Models\MITMRule.cs`**

```csharp
using System;
using System.Collections.Specialized;

namespace IrisKit
{
    /// <summary>Origine d'une règle MITM : `default` (semée, protégée) ou `user` (ajoutée par rule.add).</summary>
    public enum RuleOrigin { Default, User }

    public static class RuleOriginWire
    {
        public static string ToWire(RuleOrigin origin) { return origin == RuleOrigin.Default ? "default" : "user"; }

        public static RuleOrigin Parse(string wire)
        {
            if (wire == "default") return RuleOrigin.Default;
            if (wire == "user") return RuleOrigin.User;
            throw new JsonException("origin inconnue : " + wire);
        }
    }

    /// <summary>Hôte whitelisté pour le MITM (SPECS §5.2) ; sert aussi d'entrée `hosts[]` de config.json.</summary>
    public sealed class MITMRule
    {
        public string Host { get; private set; }
        public DateTime CreatedAt { get; private set; }
        public RuleOrigin Origin { get; private set; }

        public MITMRule(string host, DateTime createdAt, RuleOrigin origin)
        {
            Host = host;
            CreatedAt = createdAt;
            Origin = origin;
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["host"] = Host;
            o["created_at"] = CreatedAt;
            o["origin"] = RuleOriginWire.ToWire(Origin);
            return o;
        }

        /// <summary>Tolérant comme IRIS : `origin` absent vaut `user`.</summary>
        public static MITMRule FromJson(JsonObject o)
        {
            string origin = o.OptionalString("origin");
            return new MITMRule(o.String("host"), Json.ParseDate(o.String("created_at")),
                origin == null ? RuleOrigin.User : RuleOriginWire.Parse(origin));
        }
    }
}
```

- [ ] **Step 7: Écrire `src\IrisKit\Models\Alert.cs`**

```csharp
using System;
using System.Collections.Specialized;

namespace IrisKit
{
    public enum AlertSeverity { Low = 0, Medium = 1, High = 2 }
    public enum ExfilRule { HostMismatch, NonCanonicalLocation, MultipleSecrets, SuspiciousContentType, VolumeAnomaly }
    public enum AlertLocation { Header, QueryString, UrlPath, Body }

    /// <summary>Valeurs de fil des énumérations d'alerte, identiques à IRIS (sensibles à la casse).</summary>
    public static class AlertWire
    {
        private static readonly string[] Severities = { "low", "medium", "high" };
        private static readonly string[] Rules = { "hostMismatch", "nonCanonicalLocation", "multipleSecrets", "suspiciousContentType", "volumeAnomaly" };
        private static readonly string[] Locations = { "header", "queryString", "urlPath", "body" };

        public static string SeverityToWire(AlertSeverity s) { return Severities[(int)s]; }
        public static string RuleToWire(ExfilRule r) { return Rules[(int)r]; }
        public static string LocationToWire(AlertLocation l) { return Locations[(int)l]; }
        public static AlertSeverity ParseSeverity(string w) { return (AlertSeverity)IndexOf(Severities, w, "severity"); }
        public static ExfilRule ParseRule(string w) { return (ExfilRule)IndexOf(Rules, w, "rule"); }
        public static AlertLocation ParseLocation(string w) { return (AlertLocation)IndexOf(Locations, w, "detected_at"); }

        internal static int IndexOf(string[] values, string wire, string field)
        {
            int i = Array.IndexOf(values, wire);
            if (i < 0) throw new JsonException(field + " inconnu : " + wire);
            return i;
        }
    }

    /// <summary>Alerte d'exfiltration (SPECS §5.4). Le snippet est pris avant substitution et tronqué à 256 caractères.</summary>
    public sealed class Alert
    {
        public const int SnippetMax = 256;

        public AlertSeverity Severity { get; private set; }
        public ExfilRule Rule { get; private set; }
        public string SecretName { get; private set; }
        public AlertLocation DetectedAt { get; private set; }
        public string Snippet { get; private set; }

        public Alert(AlertSeverity severity, ExfilRule rule, string secretName, AlertLocation detectedAt, string snippet)
        {
            Severity = severity;
            Rule = rule;
            SecretName = secretName;
            DetectedAt = detectedAt;
            Snippet = snippet == null ? "" : (snippet.Length > SnippetMax ? snippet.Substring(0, SnippetMax) : snippet);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["severity"] = AlertWire.SeverityToWire(Severity);
            o["rule"] = AlertWire.RuleToWire(Rule);
            o["secret_name"] = SecretName;
            o["detected_at"] = AlertWire.LocationToWire(DetectedAt);
            o["snippet"] = Snippet;
            return o;
        }

        public static Alert FromJson(JsonObject o)
        {
            return new Alert(AlertWire.ParseSeverity(o.String("severity")), AlertWire.ParseRule(o.String("rule")),
                o.String("secret_name"), AlertWire.ParseLocation(o.String("detected_at")), o.String("snippet"));
        }
    }

    /// <summary>Alerte du daemon sans lien avec une requête (démarrage dégradé) ; même canal que les events.</summary>
    public sealed class SystemAlert
    {
        public AlertSeverity Severity { get; private set; }
        public string Message { get; private set; }

        public SystemAlert(AlertSeverity severity, string message)
        {
            Severity = severity;
            Message = message;
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["severity"] = AlertWire.SeverityToWire(Severity);
            o["message"] = Message;
            return o;
        }

        public static SystemAlert FromJson(JsonObject o)
        {
            return new SystemAlert(AlertWire.ParseSeverity(o.String("severity")), o.String("message"));
        }
    }
}
```

- [ ] **Step 8: Écrire `src\IrisKit\Models\Event.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace IrisKit
{
    public enum EventKind { Substituted, PassThrough, NoMatch, ExfilBlocked, Error, SystemAlert, PluginBlocked, PluginResponded }

    [Flags]
    public enum EventFlags { None = 0, BodyTooLarge = 1, NonUtf8 = 2, CompressedBody = 4, Paused = 8 }

    public static class EventWire
    {
        private static readonly string[] Kinds = { "substituted", "passThrough", "noMatch", "exfilBlocked", "error", "systemAlert", "pluginBlocked", "pluginResponded" };
        private static readonly string[] FlagNames = { "bodyTooLarge", "nonUtf8", "compressedBody", "paused" };

        public static string KindToWire(EventKind k) { return Kinds[(int)k]; }
        public static EventKind ParseKind(string w) { return (EventKind)AlertWire.IndexOf(Kinds, w, "kind"); }

        public static List<string> FlagsToWire(EventFlags flags)
        {
            List<string> result = new List<string>();
            for (int i = 0; i < FlagNames.Length; i++)
                if ((flags & (EventFlags)(1 << i)) != 0) result.Add(FlagNames[i]);
            return result;
        }

        public static EventFlags ParseFlags(IList<string> names)
        {
            EventFlags flags = EventFlags.None;
            if (names == null) return flags;
            foreach (string name in names) flags |= (EventFlags)(1 << AlertWire.IndexOf(FlagNames, name, "flags"));
            return flags;
        }
    }

    /// <summary>Event du journal (SPECS §5.3) + drapeaux irispc (spec socle §5.3). Ne porte que des noms de secrets.</summary>
    public sealed class Event
    {
        public Guid Id { get; private set; }
        public DateTime Timestamp { get; private set; }
        public EventKind Kind { get; private set; }
        public string Host { get; private set; }
        public string Method { get; private set; }
        public string Path { get; private set; }
        public int? StatusCode { get; private set; }
        public long? DurationMs { get; private set; }
        public IList<string> SubstitutedSecrets { get; private set; }
        public Alert Alert { get; private set; }
        public SystemAlert SystemAlert { get; private set; }
        public EventFlags Flags { get; private set; }

        public Event(Guid id, DateTime timestamp, EventKind kind, string host, string method, string path, int? statusCode, long? durationMs,
            IList<string> substitutedSecrets, Alert alert, SystemAlert systemAlert, EventFlags flags)
        {
            Id = id;
            Timestamp = timestamp;
            Kind = kind;
            Host = host;
            Method = method;
            Path = path;
            StatusCode = statusCode;
            DurationMs = durationMs;
            SubstitutedSecrets = new List<string>(substitutedSecrets ?? new string[0]).AsReadOnly();
            Alert = alert;
            SystemAlert = systemAlert;
            Flags = flags;
        }

        /// <summary>Event système (démarrage dégradé…) : host = catégorie, method et path = "-".</summary>
        public static Event System(DateTime at, AlertSeverity severity, string category, string message)
        {
            return new Event(Guid.NewGuid(), at, EventKind.SystemAlert, category, "-", "-", null, null, new string[0], null, new SystemAlert(severity, message), EventFlags.None);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["id"] = Id.ToString("D");
            o["timestamp"] = Timestamp;
            o["kind"] = EventWire.KindToWire(Kind);
            o["host"] = Host;
            o["method"] = Method;
            o["path"] = Path;
            if (StatusCode.HasValue) o["status_code"] = (long)StatusCode.Value;
            if (DurationMs.HasValue) o["duration_ms"] = DurationMs.Value;
            o["substituted_secrets"] = new List<string>(SubstitutedSecrets);
            if (Alert != null) o["alert"] = Alert.ToJson();
            if (SystemAlert != null) o["system_alert"] = SystemAlert.ToJson();
            if (Flags != EventFlags.None) o["flags"] = EventWire.FlagsToWire(Flags);
            return o;
        }

        public static Event FromJson(JsonObject o)
        {
            long? status = o.OptionalInt("status_code");
            JsonObject alert = o.OptionalObject("alert");
            JsonObject system = o.OptionalObject("system_alert");
            IList<object> flagsRaw = o.OptionalArray("flags");
            List<string> flagNames = null;
            if (flagsRaw != null)
            {
                flagNames = new List<string>();
                foreach (object f in flagsRaw) flagNames.Add(f as string);
            }
            return new Event(
                new Guid(o.String("id")),
                Json.ParseDate(o.String("timestamp")),
                EventWire.ParseKind(o.String("kind")),
                o.String("host"), o.String("method"), o.String("path"),
                status.HasValue ? (int?)(int)status.Value : null,
                o.OptionalInt("duration_ms"),
                o.StringArray("substituted_secrets"),
                alert == null ? null : Alert.FromJson(alert),
                system == null ? null : SystemAlert.FromJson(system),
                EventWire.ParseFlags(flagNames));
        }
    }
}
```

- [ ] **Step 9: Ajouter les sources et vérifier le vert**

`IRISKIT_SOURCES` (les deux `.bat`) : ajouter `"%SRC%\IrisKit\Models\HostName.cs" "%SRC%\IrisKit\Models\Secret.cs" "%SRC%\IrisKit\Models\MITMRule.cs" "%SRC%\IrisKit\Models\Alert.cs" "%SRC%\IrisKit\Models\Event.cs" "%SRC%\IrisKit\SecretStore\ISecretStore.cs"`.

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
```

Attendu : `23 test(s) réussi(s), 0 échec(s)`.

- [ ] **Step 10: Commit**

```bash
git add src/IrisKit/Models src/IrisKit/SecretStore/ISecretStore.cs tests/ModelsTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): modèles Secret, MITMRule, Alert, Event au format de fil IRIS

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: Journal applicatif — `Log` et `Redaction`

**Files:**
- Create: `src\IrisKit\Logging\Log.cs`, `src\IrisKit\Logging\Redaction.cs`
- Create: `tests\LoggingTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Json.FormatDate`.
- Produces: `LogLevel { Trace, Debug, Info, Warn, Error }`, `LogLevelWire.ToWire/TryParse(string, out LogLevel)/Names`, `Log` statique (`Minimum : LogLevel`, `Writer : TextWriter`, `Clock : Func<DateTime>`, `Trace/Debug/Info/Warn/Error(string category, string message)`, `Reset()`), `Redaction.Redact(byte[]) : string` et `Redact(string)` → `[REDACTED:` + 8 hex du SHA-256 + `]`.

- [ ] **Step 1: Écrire `tests\LoggingTests.cs` (RED)**

```csharp
using System;
using System.IO;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Logging ---------------------------------------------------

        private static void Logging_LevelsAndFormat()
        {
            StringWriter w = new StringWriter();
            Log.Reset();
            Log.Writer = w;
            Log.Clock = delegate { return new DateTime(2026, 10, 17, 7, 49, 47, DateTimeKind.Utc); };
            Log.Minimum = LogLevel.Info;
            Log.Debug("vault", "caché");
            Log.Info("vault", "coffre ouvert");
            Log.Warn("ca", "attention");
            Log.Error("config", "échec");
            string[] lines = w.ToString().Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            Check.Eq(3, lines.Length, "debug filtré sous info");
            Check.Eq("2026-10-17T07:49:47Z INFO  [vault] coffre ouvert", lines[0], "format horodaté, niveau aligné, catégorie");
            Check.Eq("2026-10-17T07:49:47Z WARN  [ca] attention", lines[1], "warn");
            Check.Eq("2026-10-17T07:49:47Z ERROR [config] échec", lines[2], "error");
            Log.Minimum = LogLevel.Trace;
            Log.Trace("x", "t");
            Check.True(w.ToString().Contains("TRACE [x] t"), "trace visible au niveau trace");
            Log.Reset();
        }

        private static void Logging_LevelWire()
        {
            Check.Eq("trace,debug,info,warn,error", string.Join(",", LogLevelWire.Names), "valeurs IRIS");
            LogLevel level;
            Check.True(LogLevelWire.TryParse("warn", out level) && level == LogLevel.Warn, "warn");
            Check.True(!LogLevelWire.TryParse("warning", out level), "warning refusé (valeur IRIS = warn)");
            Check.True(!LogLevelWire.TryParse("INFO", out level), "sensible à la casse");
            Check.Eq("error", LogLevelWire.ToWire(LogLevel.Error), "ToWire");
        }

        private static void Logging_Redaction()
        {
            string r = Redaction.Redact("sk-ant-secret-123");
            Check.True(r.StartsWith("[REDACTED:") && r.EndsWith("]") && r.Length == "[REDACTED:".Length + 8 + 1, "format [REDACTED:8hex]");
            Check.Eq(r, Redaction.Redact(Encoding.UTF8.GetBytes("sk-ant-secret-123")), "même empreinte pour string et bytes UTF-8");
            Check.True(r != Redaction.Redact("sk-ant-secret-124"), "empreintes distinctes");
            Check.True(!r.Contains("sk-ant"), "la valeur n'apparaît pas");
            Check.Eq("[REDACTED:e3b0c442]", Redaction.Redact(new byte[0]), "SHA-256 de vide = e3b0c442…");
        }
    }
}
```

`Main` : `Check.Run("Logging : niveaux et format", Logging_LevelsAndFormat); Check.Run("Logging : valeurs de fil des niveaux", Logging_LevelWire); Check.Run("Logging : redaction", Logging_Redaction);` — `TEST_SOURCES` : ajouter `"%TESTS%\LoggingTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `cmd //c 'D:\Dev\irispc\test.bat' 2>&1 | grep -E 'error CS' | head -2` → `CS0246 'Log'`.

- [ ] **Step 3: Écrire `src\IrisKit\Logging\Log.cs`**

```csharp
using System;
using System.IO;

namespace IrisKit
{
    /// <summary>Niveaux de log, valeurs de fil IRIS : trace, debug, info, warn, error.</summary>
    public enum LogLevel { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4 }

    public static class LogLevelWire
    {
        public static readonly string[] Names = { "trace", "debug", "info", "warn", "error" };

        public static string ToWire(LogLevel level) { return Names[(int)level]; }

        public static bool TryParse(string wire, out LogLevel level)
        {
            int i = Array.IndexOf(Names, wire);
            level = i < 0 ? LogLevel.Info : (LogLevel)i;
            return i >= 0;
        }
    }

    /// <summary>
    /// Journal console horodaté (spec §5.5). Jamais de valeur de secret : passer par Redaction.Redact.
    /// Statique et verrouillé : un seul flux de sortie par processus.
    /// </summary>
    public static class Log
    {
        private static readonly object Gate = new object();
        private static readonly string[] Labels = { "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR" };

        public static LogLevel Minimum = LogLevel.Info;
        public static TextWriter Writer = Console.Out;
        public static Func<DateTime> Clock = delegate { return DateTime.UtcNow; };

        public static void Reset()
        {
            Minimum = LogLevel.Info;
            Writer = Console.Out;
            Clock = delegate { return DateTime.UtcNow; };
        }

        public static void Trace(string category, string message) { Write(LogLevel.Trace, category, message); }
        public static void Debug(string category, string message) { Write(LogLevel.Debug, category, message); }
        public static void Info(string category, string message) { Write(LogLevel.Info, category, message); }
        public static void Warn(string category, string message) { Write(LogLevel.Warn, category, message); }
        public static void Error(string category, string message) { Write(LogLevel.Error, category, message); }

        private static void Write(LogLevel level, string category, string message)
        {
            if (level < Minimum) return;
            string line = Json.FormatDate(Clock()) + " " + Labels[(int)level] + " [" + category + "] " + message;
            lock (Gate)
            {
                Writer.WriteLine(line);
                Writer.Flush();
            }
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\Logging\Redaction.cs`**

```csharp
using System.Security.Cryptography;
using System.Text;

namespace IrisKit
{
    /// <summary>Redaction d'IRIS (SPECS §19.1) : `[REDACTED:` + 8 premiers hex du SHA-256 + `]`.</summary>
    public static class Redaction
    {
        public static string Redact(string value)
        {
            return Redact(Encoding.UTF8.GetBytes(value ?? ""));
        }

        public static string Redact(byte[] value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(value ?? new byte[0]);
                StringBuilder sb = new StringBuilder("[REDACTED:");
                for (int i = 0; i < 4; i++) sb.Append(digest[i].ToString("x2"));
                sb.Append(']');
                return sb.ToString();
            }
        }
    }
}
```

- [ ] **Step 5: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Logging\Log.cs" "%SRC%\IrisKit\Logging\Redaction.cs"`. Puis `cmd //c 'D:\Dev\irispc\test.bat' | tail -2` → `26 test(s) réussi(s)`.

- [ ] **Step 6: Commit**

```bash
git add src/IrisKit/Logging tests/LoggingTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): journal console à niveaux et redaction SHA-256

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 4: Configuration — `Config`, `Backups`, `ConfigStore`

**Files:**
- Create: `src\IrisKit\Config\Config.cs`, `src\IrisKit\Config\Backups.cs`, `src\IrisKit\Config\ConfigStore.cs`
- Create: `tests\TestSupport.cs`, `tests\ConfigTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Json`, `JsonObject`, `MITMRule`, `HostName`, `LogLevel`, `LogLevelWire`, `Log`.
- Produces: `ExfilPolicy { BlockOnly, BlockAndNotify, BlockNotifyPause }`, `ExfilPolicyWire.ToWire/Parse`, `ConfigException(field, value)` (`Field`, `Value`), `BrokerConfig(listen, eventsListen, adminPipe, logLevel, eventRetentionDays, eventRingSize)`, `SecurityConfig(onExfilAttempt, maxSubstitutionsPerMinute)`, `BackupsConfig(maxCount)`, `Config(version, broker, security, backups, hosts : IList<MITMRule>, plugins : object)` avec `static Default(DateTime seededAt)`, `Validate()`, `ToJson()`, `static FromJson(JsonObject)`, `WithHosts(IList<MITMRule>)`, `AllowedHosts : ISet<string>` ; `Backups.Stamp(DateTime)`, `Backups.CopyWithStamp(source, dir, prefix, ext, now) : string`, `Backups.Rotate(dir, prefix, ext, maxCount) : int` ; `ConfigIOException` ; `ConfigStore.Open(dataDir, now)`, `Current`, `Path`, `BackupsDir`, `RecoveredFromCorruption`, `CorruptionDetail`, `Save(Config, DateTime now)` ; `TestSupport` : `TestDir.Create() : string`, `TestDir.Delete(string)`, `Secure(string) : SecureString`.

- [ ] **Step 1: Écrire `tests\TestSupport.cs`**

```csharp
using System;
using System.IO;
using System.Security;

namespace Iris.Tests
{
    /// <summary>Dossiers temporaires isolés : jamais une base ou une config utilisateur.</summary>
    public static class TestDir
    {
        public static string Create()
        {
            string dir = Path.Combine(Path.GetTempPath(), "irispc-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        public static void Delete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    public static partial class TestMain
    {
        public static SecureString Secure(string text)
        {
            SecureString s = new SecureString();
            foreach (char c in text) s.AppendChar(c);
            s.MakeReadOnly();
            return s;
        }
    }
}
```

- [ ] **Step 2: Écrire `tests\ConfigTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Config ----------------------------------------------------

        private static void Config_DefaultAndWire()
        {
            Config c = Config.Default(T0);
            c.Validate();
            string json = Json.Emit(c.ToJson());
            Check.True(json.Contains("\"listen\": \"127.0.0.1:8888\"") && json.Contains("\"events_listen\": \"127.0.0.1:8899\"") && json.Contains("\"admin_pipe\": \"iris-admin\"") && json.Contains("\"log_level\": \"info\"") && json.Contains("\"event_retention_days\": 7") && json.Contains("\"event_ring_size\": 10000"), "broker par défaut");
            Check.True(json.Contains("\"on_exfil_attempt\": \"block_and_notify\"") && json.Contains("\"max_substitutions_per_minute\": 60") && json.Contains("\"max_count\": 10"), "security et backups par défaut");
            Check.True(json.Contains("\"host\": \"api.anthropic.com\"") && json.Contains("\"origin\": \"default\"") && json.Contains("\"created_at\": \"2023-11-14T22:13:20Z\""), "hôte semé");
            Check.True(json.Contains("\"plugins\": []") && !json.Contains("admin_socket"), "plugins vide, admin_pipe remplace admin_socket");
            Check.Eq("version,broker,security,backups,hosts,plugins", string.Join(",", Json.ParseObject(json).Keys), "ordre des sections comme IRIS");
            Config back = Config.FromJson(Json.ParseObject(json));
            Check.True(back.Version == 1 && back.Broker.Listen == "127.0.0.1:8888" && back.Security.OnExfilAttempt == ExfilPolicy.BlockAndNotify && back.Backups.MaxCount == 10 && back.Hosts.Count == 1 && back.Hosts[0].Origin == RuleOrigin.Default, "relecture (fixture testDefaultRoundTripsThroughJSON)");
            Check.True(back.AllowedHosts.Contains("api.anthropic.com"), "AllowedHosts");
        }

        private static void Config_PluginsPreservedRaw()
        {
            string json = "{\"version\":1,\"broker\":{\"listen\":\"127.0.0.1:8888\",\"events_listen\":\"127.0.0.1:8899\",\"admin_pipe\":\"iris-admin\",\"log_level\":\"debug\",\"event_retention_days\":3,\"event_ring_size\":50},\"security\":{\"on_exfil_attempt\":\"block_only\",\"max_substitutions_per_minute\":5},\"backups\":{\"max_count\":2},\"hosts\":[],\"plugins\":[{\"id\":\"x\",\"enabled\":true,\"extra\":{\"k\":[1,2]}}]}";
            Config c = Config.FromJson(Json.ParseObject(json));
            Check.True(c.Broker.LogLevel == LogLevel.Debug && c.Broker.EventRetentionDays == 3 && c.Security.OnExfilAttempt == ExfilPolicy.BlockOnly && c.Hosts.Count == 0, "valeurs lues");
            Check.Eq(json, Json.EmitCompact(c.ToJson()), "plugins réécrit tel quel, jamais interprété");
            Config noPlugins = Config.FromJson(Json.ParseObject(json.Replace(",\"plugins\":[{\"id\":\"x\",\"enabled\":true,\"extra\":{\"k\":[1,2]}}]", "")));
            Check.True(Json.EmitCompact(noPlugins.ToJson()).EndsWith("\"plugins\":[]}"), "plugins absent → [] (compat IRIS)");
        }

        private static void Config_Validation()
        {
            Config d = Config.Default(T0);
            Action<string, Config> rejects = delegate(string field, Config bad)
            {
                ConfigException ex = Check.Throws<ConfigException>(delegate { bad.Validate(); }, "rejet " + field);
                Check.Eq(field, ex.Field, "champ en cause : " + field);
            };
            rejects("broker.listen", new Config(1, new BrokerConfig("127.0.0.1", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.listen", new Config(1, new BrokerConfig("127.0.0.1:0", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.listen", new Config(1, new BrokerConfig("localhost:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.events_listen", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:70000", "iris-admin", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.admin_pipe", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "", LogLevel.Info, 7, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.event_retention_days", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 0, 10000), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("broker.event_ring_size", new Config(1, new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 0), d.Security, d.Backups, d.Hosts, d.Plugins));
            rejects("security.max_substitutions_per_minute", new Config(1, d.Broker, new SecurityConfig(ExfilPolicy.BlockOnly, 0), d.Backups, d.Hosts, d.Plugins));
            rejects("backups.max_count", new Config(1, d.Broker, d.Security, new BackupsConfig(0), d.Hosts, d.Plugins));
            rejects("hosts.host", new Config(1, d.Broker, d.Security, d.Backups, new[] { new MITMRule("_not_a_host_", T0, RuleOrigin.User) }, d.Plugins));
            Check.Throws<JsonException>(delegate { Config.FromJson(Json.ParseObject(Json.Emit(d.ToJson()).Replace("\"info\"", "\"warning\""))); }, "log_level inconnu refusé au parse");
            Check.Throws<JsonException>(delegate { Config.FromJson(Json.ParseObject(Json.Emit(d.ToJson()).Replace("block_and_notify", "notify"))); }, "politique inconnue refusée au parse");
            Check.Eq("block_notify_pause", ExfilPolicyWire.ToWire(ExfilPolicyWire.Parse("block_notify_pause")), "politique pause");
        }

        private static void Backups_CopyAndRotate()
        {
            string dir = TestDir.Create();
            try
            {
                string src = Path.Combine(dir, "config.json");
                File.WriteAllText(src, "{}");
                string bdir = Path.Combine(dir, "backups");
                Check.Eq("20261017T074947123Z", Backups.Stamp(new DateTime(2026, 10, 17, 7, 49, 47, 123, DateTimeKind.Utc)), "horodatage triable");
                string first = Backups.CopyWithStamp(src, bdir, "config", ".json", T0);
                Check.True(File.Exists(first) && Path.GetFileName(first).StartsWith("config-20231114T221320000Z-") && first.EndsWith(".json"), "copie horodatée");
                Backups.CopyWithStamp(src, bdir, "config", ".json", T0.AddSeconds(1));
                Backups.CopyWithStamp(src, bdir, "config", ".json", T0.AddSeconds(2));
                File.WriteAllText(Path.Combine(bdir, "config-corrupted-20231114T221320000Z.json"), "x");
                File.WriteAllText(Path.Combine(bdir, "iris-20231114T221320000Z-abcdef01.kdbx"), "x");
                Check.Eq(1, Backups.Rotate(bdir, "config", ".json", 2), "une suppression");
                Check.True(!File.Exists(first), "la plus ancienne est supprimée");
                Check.Eq(2, Directory.GetFiles(bdir, "config-2*.json").Length, "deux conservées");
                Check.True(File.Exists(Path.Combine(bdir, "config-corrupted-20231114T221320000Z.json")), "config-corrupted-* jamais rotée");
                Check.True(File.Exists(Path.Combine(bdir, "iris-20231114T221320000Z-abcdef01.kdbx")), "autre préfixe intact");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_SeedAndLoad()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                Check.True(File.Exists(Path.Combine(dir, "config.json")) && !store.RecoveredFromCorruption, "semé, pas de corruption");
                Check.Eq(T0, store.Current.Hosts[0].CreatedAt, "created_at du hôte semé = maintenant");
                Check.True(!File.Exists(Path.Combine(dir, "config.json.tmp")), "pas de fichier temporaire résiduel");
                ConfigStore again = ConfigStore.Open(dir, T0.AddDays(1));
                Check.Eq(T0, again.Current.Hosts[0].CreatedAt, "relu depuis le disque, pas resemé");
                Check.Eq(Json.Emit(store.Current.ToJson()) + "\n", File.ReadAllText(Path.Combine(dir, "config.json")), "fichier = Emit + LF final");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_SaveBackupsRotation()
        {
            string dir = TestDir.Create();
            try
            {
                ConfigStore store = ConfigStore.Open(dir, T0);
                Config c = store.Current;
                Config two = new Config(1, c.Broker, c.Security, new BackupsConfig(2), c.Hosts, c.Plugins);
                store.Save(two, T0.AddSeconds(1));
                store.Save(two.WithHosts(new List<MITMRule>(two.Hosts) { new MITMRule("api.github.com", T0, RuleOrigin.User) }), T0.AddSeconds(2));
                store.Save(two, T0.AddSeconds(3));
                string bdir = Path.Combine(dir, "backups");
                Check.Eq(2, Directory.GetFiles(bdir, "config-2*.json").Length, "rotation à max_count = 2");
                Check.Eq(2, Config.FromJson(Json.ParseObject(File.ReadAllText(Path.Combine(dir, "config.json")))).Backups.MaxCount, "dernier état écrit");
                Check.Throws<ConfigException>(delegate { store.Save(new Config(1, c.Broker, c.Security, new BackupsConfig(0), c.Hosts, c.Plugins), T0); }, "Save valide avant d'écrire");
                Check.Eq(2, store.Current.Backups.MaxCount, "état inchangé après rejet");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_Corrupted_DegradedBoot()
        {
            string dir = TestDir.Create();
            try
            {
                File.WriteAllText(Path.Combine(dir, "config.json"), "{ pas du json");
                ConfigStore store = ConfigStore.Open(dir, T0);
                Check.True(store.RecoveredFromCorruption && store.CorruptionDetail.Length > 0, "corruption détectée");
                string[] saved = Directory.GetFiles(Path.Combine(dir, "backups"), "config-corrupted-*.json");
                Check.Eq(1, saved.Length, "copie de l'original");
                Check.Eq("{ pas du json", File.ReadAllText(saved[0]), "contenu d'origine conservé");
                Check.Eq("127.0.0.1:8888", store.Current.Broker.Listen, "défauts resemés");
                File.WriteAllText(Path.Combine(dir, "config.json"), Json.Emit(Config.Default(T0).ToJson()).Replace("8888", "0"));
                ConfigStore invalid = ConfigStore.Open(dir, T0);
                Check.True(invalid.RecoveredFromCorruption && invalid.CorruptionDetail.Contains("broker.listen"), "valeur invalide = dégradé aussi");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void ConfigStore_IOError()
        {
            string dir = TestDir.Create();
            try
            {
                Directory.CreateDirectory(Path.Combine(dir, "config.json"));
                Check.Throws<ConfigIOException>(delegate { ConfigStore.Open(dir, T0); }, "config.json illisible (répertoire) → erreur d'E/S, pas de reseed");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
```

`Main` :

```csharp
            Check.Run("Config : défauts et format de fil", Config_DefaultAndWire);
            Check.Run("Config : plugins conservé tel quel", Config_PluginsPreservedRaw);
            Check.Run("Config : validation de chaque champ", Config_Validation);
            Check.Run("Backups : copie horodatée et rotation", Backups_CopyAndRotate);
            Check.Run("ConfigStore : seed et relecture", ConfigStore_SeedAndLoad);
            Check.Run("ConfigStore : Save, backups, rotation", ConfigStore_SaveBackupsRotation);
            Check.Run("ConfigStore : démarrage dégradé sur corruption", ConfigStore_Corrupted_DegradedBoot);
            Check.Run("ConfigStore : erreur d'E/S irrécupérable", ConfigStore_IOError);
```

`TEST_SOURCES` : ajouter `"%TESTS%\TestSupport.cs" "%TESTS%\ConfigTests.cs"`.

- [ ] **Step 3: Vérifier l'échec** — `CS0246 'Config'`.

- [ ] **Step 4: Écrire `src\IrisKit\Config\Config.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Net;

namespace IrisKit
{
    public enum ExfilPolicy { BlockOnly, BlockAndNotify, BlockNotifyPause }

    public static class ExfilPolicyWire
    {
        public static readonly string[] Names = { "block_only", "block_and_notify", "block_notify_pause" };
        public static string ToWire(ExfilPolicy p) { return Names[(int)p]; }
        public static ExfilPolicy Parse(string w) { return (ExfilPolicy)AlertWire.IndexOf(Names, w, "on_exfil_attempt"); }
    }

    /// <summary>Valeur invalide dans config.json : champ en notation pointée (`broker.listen`) et valeur fautive.</summary>
    public sealed class ConfigException : Exception
    {
        public string Field { get; private set; }
        public string Value { get; private set; }

        public ConfigException(string field, string value)
            : base("valeur invalide pour " + field + " : " + value)
        {
            Field = field;
            Value = value;
        }
    }

    public sealed class BrokerConfig
    {
        public string Listen { get; private set; }
        public string EventsListen { get; private set; }
        public string AdminPipe { get; private set; }
        public LogLevel LogLevel { get; private set; }
        public int EventRetentionDays { get; private set; }
        public int EventRingSize { get; private set; }

        public BrokerConfig(string listen, string eventsListen, string adminPipe, LogLevel logLevel, int eventRetentionDays, int eventRingSize)
        {
            Listen = listen; EventsListen = eventsListen; AdminPipe = adminPipe;
            LogLevel = logLevel; EventRetentionDays = eventRetentionDays; EventRingSize = eventRingSize;
        }

        public void Validate()
        {
            ValidateListen(Listen, "broker.listen");
            ValidateListen(EventsListen, "broker.events_listen");
            if (string.IsNullOrEmpty(AdminPipe)) throw new ConfigException("broker.admin_pipe", AdminPipe ?? "null");
            if (EventRetentionDays <= 0) throw new ConfigException("broker.event_retention_days", EventRetentionDays.ToString(CultureInfo.InvariantCulture));
            if (EventRingSize <= 0) throw new ConfigException("broker.event_ring_size", EventRingSize.ToString(CultureInfo.InvariantCulture));
        }

        /// <summary>`ip:port`, IP littérale, port 1–65535.</summary>
        public static void ValidateListen(string address, string field)
        {
            string[] parts = (address ?? "").Split(':');
            int port;
            IPAddress ip;
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out ip)
                || !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535)
                throw new ConfigException(field, address ?? "null");
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["listen"] = Listen; o["events_listen"] = EventsListen; o["admin_pipe"] = AdminPipe;
            o["log_level"] = LogLevelWire.ToWire(LogLevel);
            o["event_retention_days"] = (long)EventRetentionDays; o["event_ring_size"] = (long)EventRingSize;
            return o;
        }

        public static BrokerConfig FromJson(JsonObject o)
        {
            LogLevel level;
            string wire = o.String("log_level");
            if (!LogLevelWire.TryParse(wire, out level)) throw new JsonException("log_level inconnu : " + wire + " (attendu : " + string.Join(", ", LogLevelWire.Names) + ")");
            return new BrokerConfig(o.String("listen"), o.String("events_listen"), o.String("admin_pipe"), level,
                (int)o.Int("event_retention_days"), (int)o.Int("event_ring_size"));
        }
    }

    public sealed class SecurityConfig
    {
        public ExfilPolicy OnExfilAttempt { get; private set; }
        public int MaxSubstitutionsPerMinute { get; private set; }

        public SecurityConfig(ExfilPolicy onExfilAttempt, int maxSubstitutionsPerMinute)
        {
            OnExfilAttempt = onExfilAttempt; MaxSubstitutionsPerMinute = maxSubstitutionsPerMinute;
        }

        public void Validate()
        {
            if (MaxSubstitutionsPerMinute <= 0) throw new ConfigException("security.max_substitutions_per_minute", MaxSubstitutionsPerMinute.ToString(CultureInfo.InvariantCulture));
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["on_exfil_attempt"] = ExfilPolicyWire.ToWire(OnExfilAttempt);
            o["max_substitutions_per_minute"] = (long)MaxSubstitutionsPerMinute;
            return o;
        }

        public static SecurityConfig FromJson(JsonObject o)
        {
            return new SecurityConfig(ExfilPolicyWire.Parse(o.String("on_exfil_attempt")), (int)o.Int("max_substitutions_per_minute"));
        }
    }

    public sealed class BackupsConfig
    {
        public int MaxCount { get; private set; }
        public BackupsConfig(int maxCount) { MaxCount = maxCount; }

        public void Validate()
        {
            if (MaxCount < 1) throw new ConfigException("backups.max_count", MaxCount.ToString(CultureInfo.InvariantCulture));
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["max_count"] = (long)MaxCount;
            return o;
        }

        public static BackupsConfig FromJson(JsonObject o) { return new BackupsConfig((int)o.Int("max_count")); }
    }

    /// <summary>config.json (SPECS §6, spec socle §5.1). Le daemon est le seul écrivain. `Plugins` est lu et réécrit tel quel.</summary>
    public sealed class Config
    {
        public int Version { get; private set; }
        public BrokerConfig Broker { get; private set; }
        public SecurityConfig Security { get; private set; }
        public BackupsConfig Backups { get; private set; }
        public IList<MITMRule> Hosts { get; private set; }
        public object Plugins { get; private set; }

        public Config(int version, BrokerConfig broker, SecurityConfig security, BackupsConfig backups, IList<MITMRule> hosts, object plugins)
        {
            Version = version; Broker = broker; Security = security; Backups = backups;
            Hosts = new List<MITMRule>(hosts).AsReadOnly();
            Plugins = plugins ?? new List<object>();
        }

        public static Config Default(DateTime seededAt)
        {
            return new Config(1,
                new BrokerConfig("127.0.0.1:8888", "127.0.0.1:8899", "iris-admin", LogLevel.Info, 7, 10000),
                new SecurityConfig(ExfilPolicy.BlockAndNotify, 60),
                new BackupsConfig(10),
                new[] { new MITMRule("api.anthropic.com", seededAt, RuleOrigin.Default) },
                new List<object>());
        }

        public Config WithHosts(IList<MITMRule> hosts) { return new Config(Version, Broker, Security, Backups, hosts, Plugins); }

        public ISet<string> AllowedHosts
        {
            get
            {
                HashSet<string> set = new HashSet<string>(StringComparer.Ordinal);
                foreach (MITMRule r in Hosts) set.Add(r.Host);
                return set;
            }
        }

        public void Validate()
        {
            Broker.Validate();
            Security.Validate();
            Backups.Validate();
            foreach (MITMRule r in Hosts)
                if (!HostName.IsValid(r.Host)) throw new ConfigException("hosts.host", r.Host);
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["version"] = (long)Version;
            o["broker"] = Broker.ToJson();
            o["security"] = Security.ToJson();
            o["backups"] = Backups.ToJson();
            List<object> hosts = new List<object>();
            foreach (MITMRule r in Hosts) hosts.Add(r.ToJson());
            o["hosts"] = hosts;
            o["plugins"] = Plugins;
            return o;
        }

        public static Config FromJson(JsonObject o)
        {
            List<MITMRule> hosts = new List<MITMRule>();
            foreach (object h in o.Array("hosts"))
            {
                IDictionary<string, object> dict = h as IDictionary<string, object>;
                if (dict == null) throw new JsonException("hosts : objets attendus");
                hosts.Add(MITMRule.FromJson(new JsonObject(dict)));
            }
            object plugins = o.Has("plugins") ? o.Raw("plugins") : new List<object>();
            return new Config((int)o.Int("version"), BrokerConfig.FromJson(o.Object("broker")), SecurityConfig.FromJson(o.Object("security")),
                BackupsConfig.FromJson(o.Object("backups")), hosts, plugins);
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Config\Backups.cs`**

```csharp
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
```

- [ ] **Step 6: Écrire `src\IrisKit\Config\ConfigStore.cs`**

```csharp
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
```

- [ ] **Step 7: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Config\Config.cs" "%SRC%\IrisKit\Config\Backups.cs" "%SRC%\IrisKit\Config\ConfigStore.cs"`. `cmd //c 'D:\Dev\irispc\test.bat' | tail -2` → `34 test(s) réussi(s)`. Si `ConfigStore_IOError` rend `UnauthorizedAccessException` plutôt qu'`IOException` lors de la lecture d'un répertoire, le `catch` les couvre toutes deux ; vérifier que le test reçoit bien `ConfigIOException`.

- [ ] **Step 8: Commit**

```bash
git add src/IrisKit/Config tests/TestSupport.cs tests/ConfigTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): config.json (modèle, validation, seed, démarrage dégradé, backups rotatifs)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: Events — `EventRing`, `EventsBus`, `JsonlEventStore`, `EventPipeline`

**Files:**
- Create: `src\IrisKit\Events\EventRing.cs`, `EventsBus.cs`, `JsonlEventStore.cs`, `EventPipeline.cs`
- Create: `tests\EventsTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Event`, `EventKind`, `Json`, `Log`.
- Produces: `EventRing(int capacity)` (`Append`, `All : IList<Event>`, `Recent(int)`, `Since(DateTime)`, `Count(EventKind) : long`, `Capacity`, `Clear() : int`) ; `EventsBus` (`Subscribe(Action<Event>) : IDisposable`, `Publish(Event)`, `SubscriberCount`) ; `JsonlEventStore(string eventsDir, int retentionDays, Func<DateTime> clock) : IDisposable` (`Append(Event)`, `Purge() : int`, `Read(DateTime day) : IList<Event>`, `static FileNameFor(DateTime)`, `static TryParseFileDate(string, out DateTime)`, `Dispose`) ; `EventPipeline(EventRing, JsonlEventStore, EventsBus)` (`Emit(Event)`, `Ring`, `Bus`, `Store`).

- [ ] **Step 1: Écrire `tests\EventsTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Events ----------------------------------------------------

        private static Event Ev(EventKind kind, DateTime at, string host)
        {
            return new Event(Guid.NewGuid(), at, kind, host, "GET", "/", 200, 1, new string[0], null, null, EventFlags.None);
        }

        private static void Events_Ring()
        {
            Check.Throws<ArgumentOutOfRangeException>(delegate { new EventRing(0); }, "capacité nulle refusée");
            EventRing ring = new EventRing(3);
            for (int i = 0; i < 5; i++) ring.Append(Ev(i % 2 == 0 ? EventKind.NoMatch : EventKind.Substituted, T0.AddSeconds(i), "h" + i));
            Check.Eq(3, ring.All.Count, "borné à la capacité");
            Check.Eq("h2,h3,h4", string.Join(",", new List<Event>(ring.All).ConvertAll(delegate(Event e) { return e.Host; })), "les plus anciens évincés");
            Check.Eq(2, ring.Recent(2).Count, "Recent(2)");
            Check.Eq("h4", ring.Recent(1)[0].Host, "Recent rend les derniers en ordre");
            Check.Eq(0, ring.Recent(0).Count, "Recent(0) vide");
            Check.Eq(0, ring.Recent(-1).Count, "Recent(-1) vide");
            Check.Eq(2, ring.Since(T0.AddSeconds(3)).Count, "Since inclusif");
            Check.Eq(3L, ring.Count(EventKind.NoMatch), "totaux par kind sur la vie du ring (évincés compris)");
            Check.Eq(2L, ring.Count(EventKind.Substituted), "totaux");
            Check.Eq(3, ring.Clear(), "Clear rend le nombre retiré");
            Check.Eq(3L, ring.Count(EventKind.NoMatch), "Clear ne remet pas les totaux à zéro");
        }

        private static void Events_Bus()
        {
            EventsBus bus = new EventsBus();
            List<string> seen = new List<string>();
            IDisposable a = bus.Subscribe(delegate(Event e) { seen.Add("a:" + e.Host); });
            IDisposable b = bus.Subscribe(delegate(Event e) { throw new InvalidOperationException("abonné défaillant"); });
            IDisposable c = bus.Subscribe(delegate(Event e) { seen.Add("c:" + e.Host); });
            Check.Eq(3, bus.SubscriberCount, "trois abonnés");
            bus.Publish(Ev(EventKind.NoMatch, T0, "x"));
            Check.Eq("a:x,c:x", string.Join(",", seen), "un abonné en échec n'empêche pas les autres");
            a.Dispose(); b.Dispose();
            bus.Publish(Ev(EventKind.NoMatch, T0, "y"));
            Check.Eq("a:x,c:x,c:y", string.Join(",", seen), "désabonnement");
            Check.Eq(1, bus.SubscriberCount, "un abonné restant");
            c.Dispose(); c.Dispose();
            Check.Eq(0, bus.SubscriberCount, "Dispose idempotent");
        }

        private static void Events_JsonlStore()
        {
            string dir = TestDir.Create();
            try
            {
                DateTime now = new DateTime(2026, 10, 17, 23, 59, 0, DateTimeKind.Utc);
                Check.Eq("events-2026-10-17.jsonl", JsonlEventStore.FileNameFor(now), "nom de fichier par jour UTC");
                DateTime parsed;
                Check.True(JsonlEventStore.TryParseFileDate("events-2026-10-17.jsonl", out parsed) && parsed == now.Date, "date relue depuis le nom");
                Check.True(!JsonlEventStore.TryParseFileDate("notes.txt", out parsed), "autre fichier ignoré");
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return now; }))
                {
                    Event e1 = Ev(EventKind.Substituted, now, "api.anthropic.com");
                    store.Append(e1);
                    store.Append(Ev(EventKind.NoMatch, now.AddSeconds(30), "h2"));
                    store.Append(Ev(EventKind.PassThrough, now.AddMinutes(2), "h3")); // lendemain UTC
                    string[] lines = File.ReadAllLines(Path.Combine(dir, "events-2026-10-17.jsonl"));
                    Check.Eq(2, lines.Length, "deux lignes le 17 (flush à chaque écriture)");
                    Check.Eq(Json.EmitCompact(e1.ToJson()), lines[0], "une ligne = EmitCompact de l'event");
                    Check.True(File.Exists(Path.Combine(dir, "events-2026-10-18.jsonl")), "changement de jour → nouveau fichier");
                    IList<Event> back = store.Read(now);
                    Check.True(back.Count == 2 && back[0].Id == e1.Id && back[1].Host == "h2", "relecture d'un jour");
                }
                File.WriteAllText(Path.Combine(dir, "events-2026-10-09.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "events-2026-10-10.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "events-2026-10-11.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "garde-moi.txt"), "");
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return now; }))
                {
                    Check.Eq(2, store.Purge(), "fichiers plus vieux que 7 jours supprimés (09 et 10)");
                    Check.True(!File.Exists(Path.Combine(dir, "events-2026-10-09.jsonl")) && File.Exists(Path.Combine(dir, "events-2026-10-11.jsonl")) && File.Exists(Path.Combine(dir, "garde-moi.txt")), "limite inclusive à retention_days, autres fichiers intacts");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Events_Pipeline()
        {
            string dir = TestDir.Create();
            try
            {
                EventRing ring = new EventRing(10);
                EventsBus bus = new EventsBus();
                int published = 0;
                bus.Subscribe(delegate(Event e) { published++; });
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return T0; }))
                {
                    EventPipeline p = new EventPipeline(ring, store, bus);
                    p.Emit(Ev(EventKind.Error, T0, "h"));
                    Check.True(ring.All.Count == 1 && published == 1 && File.Exists(Path.Combine(dir, "events-2023-11-14.jsonl")), "ring, bus et journal alimentés");
                }
                EventPipeline noStore = new EventPipeline(ring, null, bus);
                noStore.Emit(Ev(EventKind.Error, T0, "h"));
                Check.Eq(2, ring.All.Count, "journal optionnel");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
```

`Main` : `Check.Run("Events : ring borné et totaux", Events_Ring); Check.Run("Events : bus d'abonnés", Events_Bus); Check.Run("Events : journal JSONL par jour, purge", Events_JsonlStore); Check.Run("Events : pipeline", Events_Pipeline);` — `TEST_SOURCES` : ajouter `"%TESTS%\EventsTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'EventRing'`.

- [ ] **Step 3: Écrire `src\IrisKit\Events\EventRing.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Anneau borné d'events (SPECS §19.3) + totaux cumulés par kind (jamais remis à zéro). Thread-safe.</summary>
    public sealed class EventRing
    {
        private readonly object gate = new object();
        private readonly Queue<Event> entries;
        private readonly long[] totals = new long[8];

        public int Capacity { get; private set; }

        public EventRing(int capacity)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException("capacity", "la capacité du ring doit être positive");
            Capacity = capacity;
            entries = new Queue<Event>(capacity);
        }

        public void Append(Event e)
        {
            lock (gate)
            {
                if (entries.Count >= Capacity) entries.Dequeue();
                entries.Enqueue(e);
                totals[(int)e.Kind]++;
            }
        }

        public IList<Event> All
        {
            get { lock (gate) { return new List<Event>(entries); } }
        }

        public IList<Event> Recent(int n)
        {
            lock (gate)
            {
                List<Event> all = new List<Event>(entries);
                if (n <= 0) return new List<Event>();
                if (n >= all.Count) return all;
                return all.GetRange(all.Count - n, n);
            }
        }

        public IList<Event> Since(DateTime at)
        {
            lock (gate)
            {
                List<Event> result = new List<Event>();
                foreach (Event e in entries) if (e.Timestamp >= at) result.Add(e);
                return result;
            }
        }

        public long Count(EventKind kind)
        {
            lock (gate) { return totals[(int)kind]; }
        }

        public int Clear()
        {
            lock (gate)
            {
                int n = entries.Count;
                entries.Clear();
                return n;
            }
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\Events\EventsBus.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Abonnés synchrones in-process (spec §5.5). Un abonné qui lève n'empêche pas les autres ; l'erreur est journalisée.</summary>
    public sealed class EventsBus
    {
        private readonly object gate = new object();
        private readonly Dictionary<int, Action<Event>> subscribers = new Dictionary<int, Action<Event>>();
        private int nextId;

        private sealed class Subscription : IDisposable
        {
            private EventsBus bus;
            private readonly int id;
            public Subscription(EventsBus bus, int id) { this.bus = bus; this.id = id; }
            public void Dispose()
            {
                EventsBus b = bus;
                bus = null;
                if (b != null) b.Unsubscribe(id);
            }
        }

        public IDisposable Subscribe(Action<Event> handler)
        {
            if (handler == null) throw new ArgumentNullException("handler");
            lock (gate)
            {
                int id = ++nextId;
                subscribers[id] = handler;
                return new Subscription(this, id);
            }
        }

        private void Unsubscribe(int id)
        {
            lock (gate) { subscribers.Remove(id); }
        }

        public int SubscriberCount
        {
            get { lock (gate) { return subscribers.Count; } }
        }

        public void Publish(Event e)
        {
            List<Action<Event>> snapshot;
            lock (gate) { snapshot = new List<Action<Event>>(subscribers.Values); }
            foreach (Action<Event> handler in snapshot)
            {
                try { handler(e); }
                catch (Exception ex) { Log.Warn("events", "abonné en échec : " + ex.GetType().Name + " : " + ex.Message); }
            }
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Events\JsonlEventStore.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Journal persistant : un fichier `events-AAAA-MM-JJ.jsonl` par jour UTC (jour du timestamp de l'event),
    /// une ligne par event, flush à chaque écriture. Purge des fichiers plus vieux que retentionDays
    /// au démarrage (appel explicite) et à chaque changement de jour.
    /// </summary>
    public sealed class JsonlEventStore : IDisposable
    {
        private const string Prefix = "events-";
        private const string Extension = ".jsonl";
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        private readonly object gate = new object();
        private readonly string dir;
        private readonly int retentionDays;
        private readonly Func<DateTime> clock;
        private StreamWriter writer;
        private DateTime openDay;

        public string Directory { get { return dir; } }

        public JsonlEventStore(string eventsDir, int retentionDays, Func<DateTime> clock)
        {
            if (retentionDays <= 0) throw new ArgumentOutOfRangeException("retentionDays");
            dir = eventsDir;
            this.retentionDays = retentionDays;
            this.clock = clock;
            System.IO.Directory.CreateDirectory(dir);
        }

        public static string FileNameFor(DateTime utc)
        {
            return Prefix + utc.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + Extension;
        }

        public static bool TryParseFileDate(string fileName, out DateTime day)
        {
            day = DateTime.MinValue;
            if (fileName == null || !fileName.StartsWith(Prefix, StringComparison.Ordinal) || !fileName.EndsWith(Extension, StringComparison.Ordinal)) return false;
            string middle = fileName.Substring(Prefix.Length, fileName.Length - Prefix.Length - Extension.Length);
            if (!DateTime.TryParseExact(middle, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out day)) return false;
            day = DateTime.SpecifyKind(day.Date, DateTimeKind.Utc);
            return true;
        }

        public void Append(Event e)
        {
            lock (gate)
            {
                DateTime day = e.Timestamp.ToUniversalTime().Date;
                if (writer == null || day != openDay)
                {
                    CloseWriter();
                    writer = new StreamWriter(Path.Combine(dir, FileNameFor(day)), true, Utf8NoBom);
                    writer.AutoFlush = true;
                    writer.NewLine = "\n";
                    bool dayChanged = openDay != DateTime.MinValue;
                    openDay = day;
                    if (dayChanged) Purge();
                }
                writer.WriteLine(Json.EmitCompact(e.ToJson()));
            }
        }

        /// <summary>Conserve les retentionDays derniers jours (aujourd'hui compris) : supprime les fichiers dont le jour ≤ aujourd'hui − retentionDays. Rend le nombre supprimé.</summary>
        public int Purge()
        {
            DateTime limit = clock().ToUniversalTime().Date.AddDays(-retentionDays);
            int removed = 0;
            foreach (string path in System.IO.Directory.GetFiles(dir, Prefix + "*" + Extension))
            {
                DateTime day;
                if (!TryParseFileDate(Path.GetFileName(path), out day) || day > limit) continue;
                try { File.Delete(path); removed++; }
                catch (IOException ex) { Log.Warn("events", "purge impossible : " + path + " : " + ex.Message); }
                catch (UnauthorizedAccessException ex) { Log.Warn("events", "purge impossible : " + path + " : " + ex.Message); }
            }
            if (removed > 0) Log.Info("events", removed + " fichier(s) d'events purgé(s), rétention " + retentionDays + " jour(s)");
            return removed;
        }

        public IList<Event> Read(DateTime day)
        {
            string path = Path.Combine(dir, FileNameFor(day));
            List<Event> result = new List<Event>();
            if (!File.Exists(path)) return result;
            lock (gate)
            {
                foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
                {
                    if (line.Trim().Length == 0) continue;
                    try { result.Add(Event.FromJson(Json.ParseObject(line))); }
                    catch (JsonException ex) { Log.Warn("events", "ligne illisible dans " + path + " : " + ex.Message); }
                }
            }
            return result;
        }

        private void CloseWriter()
        {
            if (writer == null) return;
            writer.Flush();
            writer.Dispose();
            writer = null;
        }

        public void Dispose()
        {
            lock (gate) { CloseWriter(); }
        }
    }
}
```

- [ ] **Step 6: Écrire `src\IrisKit\Events\EventPipeline.cs`**

```csharp
using System;
using System.IO;

namespace IrisKit
{
    /// <summary>Point d'émission unique : ring (mémoire) → journal JSONL (optionnel) → bus (abonnés).</summary>
    public sealed class EventPipeline
    {
        public EventRing Ring { get; private set; }
        public JsonlEventStore Store { get; private set; }
        public EventsBus Bus { get; private set; }

        public EventPipeline(EventRing ring, JsonlEventStore store, EventsBus bus)
        {
            if (ring == null) throw new ArgumentNullException("ring");
            if (bus == null) throw new ArgumentNullException("bus");
            Ring = ring;
            Store = store;
            Bus = bus;
        }

        public void Emit(Event e)
        {
            Ring.Append(e);
            if (Store != null)
            {
                try { Store.Append(e); }
                catch (IOException ex) { Log.Error("events", "journal inaccessible : " + ex.Message); }
                catch (UnauthorizedAccessException ex) { Log.Error("events", "journal inaccessible : " + ex.Message); }
            }
            Bus.Publish(e);
        }
    }
}
```

- [ ] **Step 7: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Events\EventRing.cs" "%SRC%\IrisKit\Events\EventsBus.cs" "%SRC%\IrisKit\Events\JsonlEventStore.cs" "%SRC%\IrisKit\Events\EventPipeline.cs"`. → `38 test(s) réussi(s)`.

- [ ] **Step 8: Commit**

```bash
git add src/IrisKit/Events tests/EventsTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): ring d'events, bus d'abonnés, journal JSONL journalier avec purge

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Secrets en mémoire — `InMemorySecretStore`, `SecretCache`, `EnvSecrets`

**Files:**
- Create: `src\IrisKit\SecretStore\InMemorySecretStore.cs`, `SecretCache.cs`, `EnvSecrets.cs`
- Create: `tests\SecretStoreTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `ISecretStore`, `Secret`, `HostName`, `Log`.
- Produces: `InMemorySecretStore : ISecretStore` (unicité insensible à la casse, hôtes normalisés, copies défensives des valeurs) ; `SecretCache : ISecretStore` (`SecretCache(ISecretStore inner, int capacity, TimeSpan ttl, Func<DateTime> clock)`, `CachedCount`, `Invalidate(name)`, `Clear()`) ; `EnvSecrets.LoadInto(InMemorySecretStore store, IDictionary env, DateTime now) : int` (avertissements via `Log.Warn("secrets", …)`), `EnvSecrets.Prefix = "IRIS_SECRET_"`, `EnvSecrets.HostsSuffix = "_HOSTS"`.

- [ ] **Step 1: Écrire `tests\SecretStoreTests.cs` (RED)**

```csharp
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
```

`Main` : `Check.Run("SecretStore : contrat (mémoire)", SecretStore_InMemoryContract); Check.Run("SecretStore : copies défensives", SecretStore_InMemoryDefensiveCopies); Check.Run("SecretStore : cache LRU 32 / TTL", SecretStore_Cache); Check.Run("EnvSecrets : chargement IRIS_SECRET_*", EnvSecrets_Load); Check.Run("EnvSecrets : sans hôtes = ignoré", EnvSecrets_MissingHosts_Ignored);` — `TEST_SOURCES` : ajouter `"%TESTS%\SecretStoreTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'InMemorySecretStore'`.

- [ ] **Step 3: Écrire `src\IrisKit\SecretStore\InMemorySecretStore.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Coffre en mémoire : tests et mode `--in-memory-secrets`. Même contrat que KeePassSecretStore.</summary>
    public sealed class InMemorySecretStore : ISecretStore
    {
        private sealed class Entry
        {
            public Secret Meta;
            public byte[] Value;
        }

        private readonly object gate = new object();
        private readonly Dictionary<string, Entry> items = new Dictionary<string, Entry>(StringComparer.Ordinal);

        internal static IList<string> NormalizeHosts(IList<string> hosts)
        {
            List<string> result = new List<string>();
            if (hosts != null)
                foreach (string h in hosts)
                {
                    string n = HostName.Normalize(h);
                    if (n.Length > 0 && !result.Contains(n)) result.Add(n);
                }
            Secret.ValidateAllowedHosts(result);
            return result;
        }

        private Entry Find(string name)
        {
            Entry e;
            if (name == null || !items.TryGetValue(name, out e))
                throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return e;
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt)
        {
            Secret.ValidateName(name);
            IList<string> hosts = NormalizeHosts(allowedHosts);
            lock (gate)
            {
                foreach (string existing in items.Keys)
                    if (string.Equals(existing, name, StringComparison.OrdinalIgnoreCase))
                        throw new SecretStoreException(SecretStoreErrorKind.Duplicate, name, "secret déjà présent : " + existing);
                Entry e = new Entry();
                e.Meta = new Secret(name, hosts, createdAt, null, 0, false);
                e.Value = (byte[])value.Clone();
                items[name] = e;
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts)
        {
            IList<string> hosts = NormalizeHosts(allowedHosts);
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithAllowedHosts(hosts);
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Value = (byte[])newValue.Clone();
                return Task.FromResult(e.Meta);
            }
        }

        public Task DeleteAsync(string name)
        {
            lock (gate)
            {
                Find(name);
                items.Remove(name);
                return Task.FromResult(0);
            }
        }

        public Task<byte[]> ValueAsync(string name)
        {
            lock (gate) { return Task.FromResult((byte[])Find(name).Value.Clone()); }
        }

        public Task<Secret> SecretAsync(string name)
        {
            lock (gate) { return Task.FromResult(Find(name).Meta); }
        }

        public Task<IList<Secret>> ListAsync()
        {
            lock (gate)
            {
                List<Secret> list = new List<Secret>();
                foreach (Entry e in items.Values) list.Add(e.Meta);
                list.Sort(delegate(Secret a, Secret b) { return string.CompareOrdinal(a.Name, b.Name); });
                return Task.FromResult((IList<Secret>)list);
            }
        }

        public Task<Secret> RecordUsageAsync(string name, DateTime at)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithUsage(at, e.Meta.UsageCount + 1);
                return Task.FromResult(e.Meta);
            }
        }

        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined)
        {
            lock (gate)
            {
                Entry e = Find(name);
                e.Meta = e.Meta.WithQuarantined(quarantined);
                return Task.FromResult(e.Meta);
            }
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\SecretStore\SecretCache.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Décorateur LRU (32 valeurs, TTL 5 min) devant un ISecretStore (spec §4.4). Invalidé par Rotate et Delete.</summary>
    public sealed class SecretCache : ISecretStore
    {
        public const int DefaultCapacity = 32;
        public static readonly TimeSpan DefaultTtl = TimeSpan.FromMinutes(5);

        private sealed class Cached
        {
            public byte[] Value;
            public DateTime Expires;
            public LinkedListNode<string> Node;
        }

        private readonly object gate = new object();
        private readonly ISecretStore inner;
        private readonly int capacity;
        private readonly TimeSpan ttl;
        private readonly Func<DateTime> clock;
        private readonly Dictionary<string, Cached> map = new Dictionary<string, Cached>(StringComparer.Ordinal);
        private readonly LinkedList<string> order = new LinkedList<string>(); // tête = plus récent

        public SecretCache(ISecretStore inner) : this(inner, DefaultCapacity, DefaultTtl, delegate { return DateTime.UtcNow; }) { }

        public SecretCache(ISecretStore inner, int capacity, TimeSpan ttl, Func<DateTime> clock)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            if (capacity <= 0) throw new ArgumentOutOfRangeException("capacity");
            this.inner = inner; this.capacity = capacity; this.ttl = ttl; this.clock = clock;
        }

        public int CachedCount { get { lock (gate) { return map.Count; } } }

        public void Invalidate(string name)
        {
            lock (gate)
            {
                Cached c;
                if (name != null && map.TryGetValue(name, out c))
                {
                    order.Remove(c.Node);
                    map.Remove(name);
                    Array.Clear(c.Value, 0, c.Value.Length);
                }
            }
        }

        public void Clear()
        {
            lock (gate)
            {
                foreach (Cached c in map.Values) Array.Clear(c.Value, 0, c.Value.Length);
                map.Clear();
                order.Clear();
            }
        }

        public async Task<byte[]> ValueAsync(string name)
        {
            lock (gate)
            {
                Cached hit;
                if (map.TryGetValue(name, out hit))
                {
                    if (hit.Expires > clock())
                    {
                        order.Remove(hit.Node);
                        order.AddFirst(hit.Node);
                        return (byte[])hit.Value.Clone();
                    }
                    order.Remove(hit.Node);
                    map.Remove(name);
                }
            }
            byte[] value = await inner.ValueAsync(name).ConfigureAwait(false);
            lock (gate)
            {
                Cached c;
                if (map.TryGetValue(name, out c)) order.Remove(c.Node);
                c = new Cached();
                c.Value = (byte[])value.Clone();
                c.Expires = clock() + ttl;
                c.Node = order.AddFirst(name);
                map[name] = c;
                while (map.Count > capacity)
                {
                    string oldest = order.Last.Value;
                    order.RemoveLast();
                    Array.Clear(map[oldest].Value, 0, map[oldest].Value.Length);
                    map.Remove(oldest);
                }
            }
            return value;
        }

        public async Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            Secret s = await inner.RotateAsync(name, newValue).ConfigureAwait(false);
            Invalidate(name);
            return s;
        }

        public async Task DeleteAsync(string name)
        {
            await inner.DeleteAsync(name).ConfigureAwait(false);
            Invalidate(name);
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt) { return inner.AddAsync(name, value, allowedHosts, createdAt); }
        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts) { return inner.UpdateAsync(name, allowedHosts); }
        public Task<Secret> SecretAsync(string name) { return inner.SecretAsync(name); }
        public Task<IList<Secret>> ListAsync() { return inner.ListAsync(); }
        public Task<Secret> RecordUsageAsync(string name, DateTime at) { return inner.RecordUsageAsync(name, at); }
        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined) { return inner.SetQuarantinedAsync(name, quarantined); }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\SecretStore\EnvSecrets.cs`**

```csharp
using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Mode DEBUG `--in-memory-secrets` (spec §4.3) : `IRIS_SECRET_&lt;NAME&gt;=valeur` et `IRIS_SECRET_&lt;NAME&gt;_HOSTS=h1,h2`.
    /// Un secret sans `_HOSTS` valide est ignoré avec avertissement : jamais de secret sans scoping.
    /// Les messages ne citent jamais la valeur.
    /// </summary>
    public static class EnvSecrets
    {
        public const string Prefix = "IRIS_SECRET_";
        public const string HostsSuffix = "_HOSTS";

        public static int LoadInto(InMemorySecretStore store, IDictionary env, DateTime now)
        {
            int loaded = 0;
            List<string> keys = new List<string>();
            foreach (object k in env.Keys) keys.Add(k.ToString());
            keys.Sort(StringComparer.Ordinal);
            foreach (string key in keys)
            {
                if (!key.StartsWith(Prefix, StringComparison.Ordinal) || key.EndsWith(HostsSuffix, StringComparison.Ordinal)) continue;
                string name = key.Substring(Prefix.Length);
                string value = env[key] as string;
                if (string.IsNullOrEmpty(value)) { Log.Warn("secrets", key + " : valeur vide, ignoré"); continue; }
                if (!Secret.NameRegex.IsMatch(name)) { Log.Warn("secrets", key + " : nom de secret invalide, ignoré"); continue; }
                string hostsRaw = env[key + HostsSuffix] as string;
                if (string.IsNullOrEmpty(hostsRaw)) { Log.Warn("secrets", key + " : " + key + HostsSuffix + " absent, secret ignoré (aucun secret sans allowed_hosts)"); continue; }
                List<string> hosts = new List<string>();
                foreach (string h in hostsRaw.Split(','))
                    if (h.Trim().Length > 0) hosts.Add(h.Trim());
                try
                {
                    store.AddAsync(name, Encoding.UTF8.GetBytes(value), hosts, now).GetAwaiter().GetResult();
                    loaded++;
                    Log.Warn("secrets", "DEBUG : secret " + name + " chargé depuis l'environnement, hôtes : " + hostsRaw.Trim());
                }
                catch (SecretStoreException ex)
                {
                    Log.Warn("secrets", key + " : " + ex.Message + ", ignoré");
                }
            }
            return loaded;
        }
    }
}
```

- [ ] **Step 6: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\SecretStore\InMemorySecretStore.cs" "%SRC%\IrisKit\SecretStore\SecretCache.cs" "%SRC%\IrisKit\SecretStore\EnvSecrets.cs"`. → `43 test(s) réussi(s)`.

- [ ] **Step 7: Commit**

```bash
git add src/IrisKit/SecretStore tests/SecretStoreTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): ISecretStore en mémoire, cache LRU/TTL, secrets d'environnement (debug)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: `SecretsMetaStore` — `secrets-meta.json` avec débounce

**Files:**
- Create: `src\IrisKit\SecretStore\SecretsMetaStore.cs`
- Create: `tests\MetaStoreTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Json`, `JsonObject`, `Log`.
- Produces: `SecretMeta` (`LastUsedAt : DateTime?`, `UsageCount : long`, `Quarantined : bool`, `static Empty`) ; `SecretsMetaStore(string path, Func<ICollection<string>> existingNames, TimeSpan debounce, Func<DateTime> clock) : IDisposable` (`Get(name) : SecretMeta`, `RecordUsage(name, at) : SecretMeta`, `SetQuarantined(name, bool) : SecretMeta`, `Remove(name)`, `Flush() : bool`, `Dirty`, `DefaultDebounce = 2 s`).

- [ ] **Step 1: Écrire `tests\MetaStoreTests.cs` (RED)**

```csharp
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
```

`Main` : `Check.Run("MetaStore : défauts, Flush, purge, format", MetaStore_DefaultsAndFlush); Check.Run("MetaStore : débounce et Dispose", MetaStore_DebounceAndDispose); Check.Run("MetaStore : fichier corrompu = repart vide", MetaStore_CorruptFileStartsEmpty);` — `TEST_SOURCES` : ajouter `"%TESTS%\MetaStoreTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'SecretsMetaStore'`.

- [ ] **Step 3: Écrire `src\IrisKit\SecretStore\SecretsMetaStore.cs`**

```csharp
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
```

- [ ] **Step 4: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\SecretStore\SecretsMetaStore.cs"`. → `46 test(s) réussi(s)`. Le test de débounce attend 400 ms : s'il est instable en CI, porter l'attente à 1 s avant de conclure à un bug.

- [ ] **Step 5: Commit**

```bash
git add src/IrisKit/SecretStore/SecretsMetaStore.cs tests/MetaStoreTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): secrets-meta.json avec débounce, purge et écriture atomique

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 8: Coffre KeePass — `KeePassVault`, `KeePassSecretStore`

**Files:**
- Create: `src\IrisKit\CA\CAMaterial.cs` (type partagé avec la tâche 9)
- Create: `src\IrisKit\SecretStore\KeePassVault.cs`, `src\IrisKit\SecretStore\KeePassSecretStore.cs`
- Create: `tests\KeePassTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `ISecretStore`, `SecretStoreException`, `Secret`, `InMemorySecretStore.NormalizeHosts` (internal), `SecretsMetaStore`, `Backups`, `Log`, `KeePassLib` (`PwDatabase`, `PwGroup`, `PwEntry`, `CompositeKey`, `KcpPassword`, `ProtectedString`, `IOConnectionInfo`, `NullStatusLogger`, `Argon2Kdf`, `InvalidCompositeKeyException`).
- Produces: `CAMaterial(byte[] privateKeyPkcs8, byte[] certificateDer, DateTime createdAt)` ; `VaultSecretEntry` (`Name`, `AllowedHosts`, `CreatedAt`) ; `KeePassVault : IDisposable` (`static Create(path, SecureString, DateTime now)`, `static Open(path, SecureString)`, `Path`, `LockPath`, `BackupsDir`, `MaxBackups`, `Clock`, `IsBusy`, `ListSecrets() : IList<VaultSecretEntry>`, `FindSecret(name)`, `ReadValue(name) : byte[]`, `AddSecret(name, value, hosts, createdAt)`, `SetAllowedHosts(name, hosts)`, `SetValue(name, value)`, `DeleteSecret(name) : bool`, `ReadCA() : CAMaterial`, `WriteCA(CAMaterial)`, `SecretNames() : ICollection<string>`, constantes `DatabaseName = "iris"`, `SecretsGroup = "secrets"`, `CAGroup = "ca"`, `CAEntryTitle = "root"`, `HostsField = "allowed_hosts"`, `CreatedAtField = "created_at"`, `CertificateField = "certificate"`) ; `KeePassSecretStore(KeePassVault vault, SecretsMetaStore meta) : ISecretStore`.

- [ ] **Step 1: Écrire `tests\KeePassTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IrisKit;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- KeePass (base temporaire, jamais une base utilisateur) ----

        private static string FileHash(string path)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(path)));
        }

        private static SecretsMetaStore MetaFor(KeePassVault vault, string dir)
        {
            return new SecretsMetaStore(Path.Combine(dir, "secrets-meta.json"), delegate { return vault.SecretNames(); }, TimeSpan.FromHours(1), delegate { return T0; });
        }

        private static void KeePass_CreateContractReopen()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("maître-é"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    Check.True(File.Exists(kdbx) && !vault.IsBusy, "base créée");
                    SecretStoreContract(new KeePassSecretStore(vault, meta));
                }
                using (KeePassVault again = KeePassVault.Open(kdbx, Secure("maître-é")))
                using (SecretsMetaStore meta = MetaFor(again, dir))
                {
                    KeePassSecretStore store = new KeePassSecretStore(again, meta);
                    IList<Secret> list = Wait(store.ListAsync());
                    Check.True(list.Count == 1 && list[0].Name == "anthropic_api_key" && list[0].AllowedHosts[0] == "api.anthropic.com" && list[0].CreatedAt == T0, "secret relu après réouverture");
                    Check.Eq("sk-ant-1", Encoding.UTF8.GetString(Wait(store.ValueAsync("anthropic_api_key"))), "valeur relue");
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("maître-é"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                Check.True(raw.KdfParameters.KdfUuid.Equals(new KeePassLib.Cryptography.KeyDerivation.Argon2Kdf().Uuid), "KDF Argon2d");
                Check.Eq("iris", raw.Name, "nom de base");
                PwGroup secrets = null;
                foreach (PwGroup g in raw.RootGroup.Groups) if (g.Name == "secrets") secrets = g;
                Check.True(secrets != null && secrets.Entries.UCount == 1, "groupe secrets, une entrée");
                PwEntry entry = secrets.Entries.GetAt(0);
                Check.True(entry.Strings.GetSafe(PwDefs.PasswordField).IsProtected, "valeur en champ protégé");
                Check.Eq("[\"api.anthropic.com\"]", entry.Strings.ReadSafe("allowed_hosts"), "allowed_hosts = tableau JSON");
                Check.Eq("2023-11-14T22:13:20Z", entry.Strings.ReadSafe("created_at"), "created_at ISO");
                raw.Close();
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_WrongPasswordAndCorruption()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                KeePassVault.Create(kdbx, Secure("bon"), T0).Dispose();
                SecretStoreException ex = Check.Throws<SecretStoreException>(delegate { KeePassVault.Open(kdbx, Secure("mauvais")); }, "mauvais mot de passe");
                Check.Eq(SecretStoreErrorKind.VaultLocked, ex.Kind, "VaultLocked");
                Check.True(!ex.Message.Contains("mauvais"), "le mot de passe n'est pas dans le message");
                File.WriteAllText(Path.Combine(dir, "corrupt.kdbx"), "ceci n'est pas une base");
                Check.Eq(SecretStoreErrorKind.DataCorruption, Check.Throws<SecretStoreException>(delegate { KeePassVault.Open(Path.Combine(dir, "corrupt.kdbx"), Secure("x")); }, "fichier corrompu").Kind, "DataCorruption");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_LockFile_VaultBusy()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    KeePassSecretStore store = new KeePassSecretStore(vault, meta);
                    Wait(store.AddAsync("k", Bytes("v"), new[] { "h.example" }, T0));
                    string before = FileHash(kdbx);
                    int backupsBefore = Directory.GetFiles(vault.BackupsDir).Length;
                    File.WriteAllText(vault.LockPath, "KeePass a la base ouverte");
                    Check.True(vault.IsBusy, "lock détecté");
                    Check.Eq("v", Encoding.UTF8.GetString(Wait(store.ValueAsync("k"))), "lecture permise");
                    Check.Eq(1, Wait(store.ListAsync()).Count, "liste permise");
                    foreach (Action write in new Action[] {
                        delegate { Wait(store.AddAsync("k2", Bytes("v"), new[] { "h.example" }, T0)); },
                        delegate { Wait(store.UpdateAsync("k", new[] { "other.example" })); },
                        delegate { Wait(store.RotateAsync("k", Bytes("v2"))); },
                        delegate { Wait(store.DeleteAsync("k")); } })
                    {
                        SecretStoreException ex = Check.Throws<SecretStoreException>(write, "écriture refusée");
                        Check.Eq(SecretStoreErrorKind.VaultBusy, ex.Kind, "VaultBusy");
                        Check.True(ex.Message.Contains("KeePass"), "message explicite");
                    }
                    Check.Eq(before, FileHash(kdbx), "base intacte");
                    Check.Eq(backupsBefore, Directory.GetFiles(vault.BackupsDir).Length, "aucun backup créé");
                    Wait(store.RecordUsageAsync("k", T0));
                    Check.True(Wait(store.SetQuarantinedAsync("k", true)).Quarantined, "métadonnées modifiables malgré le lock (hors kdbx)");
                    Check.Eq(before, FileHash(kdbx), "les métadonnées n'écrivent jamais le kdbx");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_BackupsBeforeWrite()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.MaxBackups = 2;
                    int tick = 0;
                    vault.Clock = delegate { return T0.AddSeconds(tick++); };
                    KeePassSecretStore store = new KeePassSecretStore(vault, meta);
                    Wait(store.AddAsync("a", Bytes("1"), new[] { "h.example" }, T0));
                    string[] one = Directory.GetFiles(vault.BackupsDir, "iris-*.kdbx");
                    Check.Eq(1, one.Length, "copie avant la première écriture");
                    Check.True(new FileInfo(one[0]).Length > 0, "copie non vide");
                    Wait(store.AddAsync("b", Bytes("2"), new[] { "h.example" }, T0));
                    Wait(store.RotateAsync("a", Bytes("3")));
                    Check.Eq(2, Directory.GetFiles(vault.BackupsDir, "iris-*.kdbx").Length, "rotation à MaxBackups");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_ForeignContentIgnored()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.AddSecret("mine", Bytes("v"), new[] { "h.example" }, T0);
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("p"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                PwEntry stray = new PwEntry(true, true);
                stray.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "perso"));
                stray.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "x"));
                raw.RootGroup.AddEntry(stray, true);
                PwGroup other = new PwGroup(true, true, "banque", PwIcon.Money);
                other.AddEntry(new PwEntry(true, true), true);
                raw.RootGroup.AddGroup(other, true);
                raw.Save(new NullStatusLogger());
                raw.Close();
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                {
                    IList<VaultSecretEntry> list = vault.ListSecrets();
                    Check.True(list.Count == 1 && list[0].Name == "mine", "seul le groupe secrets est lu");
                    Check.True(vault.ReadCA() == null, "pas de CA encore");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_CAEntry()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                byte[] keyBytes = Bytes("pkcs8-factice");
                byte[] certBytes = Bytes("der-factice");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.WriteCA(new CAMaterial(keyBytes, certBytes, T0));
                    vault.WriteCA(new CAMaterial(keyBytes, certBytes, T0.AddDays(1)));
                }
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                {
                    CAMaterial ca = vault.ReadCA();
                    Check.True(ca != null && Convert.ToBase64String(ca.PrivateKeyPkcs8) == Convert.ToBase64String(keyBytes) && Convert.ToBase64String(ca.CertificateDer) == Convert.ToBase64String(certBytes) && ca.CreatedAt == T0.AddDays(1), "CA relu, la réécriture remplace l'entrée root");
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("p"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                PwGroup ca2 = null;
                foreach (PwGroup g in raw.RootGroup.Groups) if (g.Name == "ca") ca2 = g;
                Check.True(ca2 != null && ca2.Entries.UCount == 1, "groupe ca, une seule entrée root");
                PwEntry root = ca2.Entries.GetAt(0);
                Check.True(root.Strings.ReadSafe(PwDefs.TitleField) == "root" && root.Strings.GetSafe(PwDefs.PasswordField).IsProtected, "clé privée en champ protégé");
                Check.Eq(Convert.ToBase64String(certBytes), root.Strings.ReadSafe("certificate"), "certificat en base64 dans un champ libre");
                raw.Close();
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
```

`Main` :

```csharp
            Check.Run("KeePass : création, contrat, réouverture, schéma", KeePass_CreateContractReopen);
            Check.Run("KeePass : mauvais mot de passe et corruption", KeePass_WrongPasswordAndCorruption);
            Check.Run("KeePass : .lock = VaultBusy en écriture seulement", KeePass_LockFile_VaultBusy);
            Check.Run("KeePass : backup avant écriture et rotation", KeePass_BackupsBeforeWrite);
            Check.Run("KeePass : contenu étranger ignoré", KeePass_ForeignContentIgnored);
            Check.Run("KeePass : entrée CA du groupe ca", KeePass_CAEntry);
```

`TEST_SOURCES` : ajouter `"%TESTS%\KeePassTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'KeePassVault'`.

- [ ] **Step 3: Écrire `src\IrisKit\CA\CAMaterial.cs`**

```csharp
using System;

namespace IrisKit
{
    /// <summary>Clé privée (PKCS#8 DER) et certificat (DER) du CA, tels que stockés dans le coffre (spec §4.1, groupe `ca`).</summary>
    public sealed class CAMaterial
    {
        public byte[] PrivateKeyPkcs8 { get; private set; }
        public byte[] CertificateDer { get; private set; }
        public DateTime CreatedAt { get; private set; }

        public CAMaterial(byte[] privateKeyPkcs8, byte[] certificateDer, DateTime createdAt)
        {
            PrivateKeyPkcs8 = (byte[])privateKeyPkcs8.Clone();
            CertificateDer = (byte[])certificateDer.Clone();
            CreatedAt = createdAt;
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\SecretStore\KeePassVault.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

namespace IrisKit
{
    public sealed class VaultSecretEntry
    {
        public string Name { get; private set; }
        public IList<string> AllowedHosts { get; private set; }
        public DateTime CreatedAt { get; private set; }

        public VaultSecretEntry(string name, IList<string> allowedHosts, DateTime createdAt)
        {
            Name = name; AllowedHosts = allowedHosts; CreatedAt = createdAt;
        }
    }

    /// <summary>
    /// Accès bas niveau à iris.kdbx (spec §4.1, §4.5) via KeePassLib : groupe `secrets` (une entrée par secret,
    /// valeur en champ protégé, `allowed_hosts` JSON, `created_at` ISO) et groupe `ca` (entrée `root`).
    /// Tout autre contenu est ignoré. Toute mutation : refus si `.lock` → backup → modification → Save, sous verrou.
    /// </summary>
    public sealed class KeePassVault : IDisposable
    {
        public const string DatabaseName = "iris";
        public const string SecretsGroup = "secrets";
        public const string CAGroup = "ca";
        public const string CAEntryTitle = "root";
        public const string HostsField = "allowed_hosts";
        public const string CreatedAtField = "created_at";
        public const string CertificateField = "certificate";

        private readonly object gate = new object();
        private PwDatabase db;

        public string Path { get; private set; }
        public string LockPath { get { return Path + ".lock"; } }
        public string BackupsDir { get; set; }
        public int MaxBackups { get; set; }
        public Func<DateTime> Clock { get; set; }
        public bool IsBusy { get { return File.Exists(LockPath); } }

        private KeePassVault(string path, PwDatabase db)
        {
            Path = path;
            this.db = db;
            BackupsDir = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(path), "backups");
            MaxBackups = 10;
            Clock = delegate { return DateTime.UtcNow; };
        }

        // ---- Ouverture / création -------------------------------------

        public static KeePassVault Create(string path, SecureString password, DateTime now)
        {
            PwDatabase db = new PwDatabase();
            db.New(IOConnectionInfo.FromPath(path), MakeKey(password));
            db.Name = DatabaseName;
            db.KdfParameters = new Argon2Kdf(Argon2Type.D).GetDefaultParameters();
            db.RootGroup.AddGroup(new PwGroup(true, true, SecretsGroup, PwIcon.Key), true);
            db.RootGroup.AddGroup(new PwGroup(true, true, CAGroup, PwIcon.Certificate), true);
            KeePassVault vault = new KeePassVault(path, db);
            vault.SaveUnlocked();
            Log.Info("vault", "coffre créé : " + path);
            return vault;
        }

        /// <summary>Mauvais mot de passe → VaultLocked ; fichier illisible → DataCorruption.</summary>
        public static KeePassVault Open(string path, SecureString password)
        {
            PwDatabase db = new PwDatabase();
            try
            {
                db.Open(IOConnectionInfo.FromPath(path), MakeKey(password), new NullStatusLogger());
            }
            catch (InvalidCompositeKeyException ex)
            {
                throw new SecretStoreException(SecretStoreErrorKind.VaultLocked, null, "mot de passe maître refusé pour " + path, ex);
            }
            catch (Exception ex)
            {
                throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "coffre illisible : " + path + " (" + ex.GetType().Name + " : " + ex.Message + ")", ex);
            }
            return new KeePassVault(path, db);
        }

        /// <summary>CompositeKey depuis une SecureString : les octets UTF-8 transitoires sont effacés aussitôt.</summary>
        private static CompositeKey MakeKey(SecureString password)
        {
            IntPtr unicode = IntPtr.Zero;
            byte[] utf8 = null;
            try
            {
                unicode = Marshal.SecureStringToGlobalAllocUnicode(password);
                string plain = Marshal.PtrToStringUni(unicode);
                utf8 = Encoding.UTF8.GetBytes(plain);
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword(utf8));
                return key;
            }
            finally
            {
                if (utf8 != null) Array.Clear(utf8, 0, utf8.Length);
                if (unicode != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(unicode);
            }
        }

        // ---- Lecture ---------------------------------------------------

        private PwGroup Group(string name, bool create)
        {
            foreach (PwGroup g in db.RootGroup.Groups) if (g.Name == name) return g;
            if (!create) return null;
            PwGroup created = new PwGroup(true, true, name, PwIcon.Key);
            db.RootGroup.AddGroup(created, true);
            return created;
        }

        private PwEntry Entry(string groupName, string title)
        {
            PwGroup g = Group(groupName, false);
            if (g == null) return null;
            foreach (PwEntry e in g.Entries) if (e.Strings.ReadSafe(PwDefs.TitleField) == title) return e;
            return null;
        }

        private static VaultSecretEntry ToEntry(PwEntry e)
        {
            string name = e.Strings.ReadSafe(PwDefs.TitleField);
            List<string> hosts = new List<string>();
            string hostsJson = e.Strings.ReadSafe(HostsField);
            try
            {
                if (hostsJson.Length > 0)
                    foreach (object h in (IList<object>)Json.Parse(hostsJson)) hosts.Add((string)h);
            }
            catch (Exception ex)
            {
                if (ex is JsonException || ex is InvalidCastException)
                    throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, name, "allowed_hosts illisible pour " + name, ex);
                throw;
            }
            string created = e.Strings.ReadSafe(CreatedAtField);
            DateTime createdAt;
            try { createdAt = created.Length > 0 ? Json.ParseDate(created) : e.CreationTime.ToUniversalTime(); }
            catch (JsonException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, name, "created_at illisible pour " + name, ex); }
            return new VaultSecretEntry(name, hosts.AsReadOnly(), createdAt);
        }

        public IList<VaultSecretEntry> ListSecrets()
        {
            lock (gate)
            {
                List<VaultSecretEntry> list = new List<VaultSecretEntry>();
                PwGroup g = Group(SecretsGroup, false);
                if (g != null) foreach (PwEntry e in g.Entries) list.Add(ToEntry(e));
                list.Sort(delegate(VaultSecretEntry a, VaultSecretEntry b) { return string.CompareOrdinal(a.Name, b.Name); });
                return list;
            }
        }

        public ICollection<string> SecretNames()
        {
            List<string> names = new List<string>();
            foreach (VaultSecretEntry e in ListSecrets()) names.Add(e.Name);
            return names;
        }

        public VaultSecretEntry FindSecret(string name)
        {
            lock (gate)
            {
                PwEntry e = Entry(SecretsGroup, name);
                return e == null ? null : ToEntry(e);
            }
        }

        public byte[] ReadValue(string name)
        {
            lock (gate)
            {
                PwEntry e = Entry(SecretsGroup, name);
                return e == null ? null : e.Strings.GetSafe(PwDefs.PasswordField).ReadUtf8();
            }
        }

        public CAMaterial ReadCA()
        {
            lock (gate)
            {
                PwEntry e = Entry(CAGroup, CAEntryTitle);
                if (e == null) return null;
                try
                {
                    string created = e.Strings.ReadSafe(CreatedAtField);
                    return new CAMaterial(
                        Convert.FromBase64String(e.Strings.GetSafe(PwDefs.PasswordField).ReadString()),
                        Convert.FromBase64String(e.Strings.ReadSafe(CertificateField)),
                        created.Length > 0 ? Json.ParseDate(created) : e.CreationTime.ToUniversalTime());
                }
                catch (FormatException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, CAEntryTitle, "entrée CA illisible", ex); }
                catch (JsonException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, CAEntryTitle, "entrée CA illisible", ex); }
            }
        }

        // ---- Écriture --------------------------------------------------

        public void AddSecret(string name, byte[] value, IList<string> hosts, DateTime createdAt)
        {
            Mutate(delegate
            {
                PwGroup g = Group(SecretsGroup, true);
                foreach (PwEntry existing in g.Entries)
                    if (string.Equals(existing.Strings.ReadSafe(PwDefs.TitleField), name, StringComparison.OrdinalIgnoreCase))
                        throw new SecretStoreException(SecretStoreErrorKind.Duplicate, name, "secret déjà présent : " + existing.Strings.ReadSafe(PwDefs.TitleField));
                PwEntry e = new PwEntry(true, true);
                e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, name));
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, value));
                e.Strings.Set(HostsField, new ProtectedString(false, Json.EmitCompact(new List<string>(hosts))));
                e.Strings.Set(CreatedAtField, new ProtectedString(false, Json.FormatDate(createdAt)));
                g.AddEntry(e, true);
            });
        }

        public void SetAllowedHosts(string name, IList<string> hosts)
        {
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                e.Strings.Set(HostsField, new ProtectedString(false, Json.EmitCompact(new List<string>(hosts))));
                e.Touch(true);
            });
        }

        public void SetValue(string name, byte[] value)
        {
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, value));
                e.Touch(true);
            });
        }

        public bool DeleteSecret(string name)
        {
            bool removed = false;
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                removed = Group(SecretsGroup, false).Entries.Remove(e);
            });
            return removed;
        }

        public void WriteCA(CAMaterial material)
        {
            Mutate(delegate
            {
                PwGroup g = Group(CAGroup, true);
                PwEntry e = Entry(CAGroup, CAEntryTitle);
                if (e == null)
                {
                    e = new PwEntry(true, true);
                    e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, CAEntryTitle));
                    g.AddEntry(e, true);
                }
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, Convert.ToBase64String(material.PrivateKeyPkcs8)));
                e.Strings.Set(CertificateField, new ProtectedString(false, Convert.ToBase64String(material.CertificateDer)));
                e.Strings.Set(CreatedAtField, new ProtectedString(false, Json.FormatDate(material.CreatedAt)));
                e.Touch(true);
            });
        }

        /// <summary>Verrou process → refus si KeePass.exe a la base (`.lock`) → backup horodaté + rotation → mutation → Save.</summary>
        private void Mutate(Action action)
        {
            lock (gate)
            {
                if (db == null) throw new ObjectDisposedException("KeePassVault");
                if (IsBusy)
                    throw new SecretStoreException(SecretStoreErrorKind.VaultBusy, null,
                        "la base est ouverte dans KeePass (" + LockPath + " présent) : fermez-la dans KeePass avant de modifier des secrets");
                try
                {
                    Backups.CopyWithStamp(Path, BackupsDir, "iris", ".kdbx", Clock());
                    Backups.Rotate(BackupsDir, "iris", ".kdbx", MaxBackups);
                }
                catch (IOException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "backup du coffre impossible : " + ex.Message, ex); }
                catch (UnauthorizedAccessException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "backup du coffre impossible : " + ex.Message, ex); }
                action();
                SaveUnlocked();
            }
        }

        private void SaveUnlocked()
        {
            try { db.Save(new NullStatusLogger()); }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                    throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "écriture du coffre impossible : " + ex.Message, ex);
                throw;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (db == null) return;
                db.Close();
                db = null;
            }
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\SecretStore\KeePassSecretStore.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// ISecretStore de production (spec §4.4) : identité et valeurs dans KeePassVault, usage et quarantaine
    /// dans SecretsMetaStore (jamais de réécriture du kdbx sur le chemin chaud).
    /// </summary>
    public sealed class KeePassSecretStore : ISecretStore
    {
        private readonly KeePassVault vault;
        private readonly SecretsMetaStore meta;

        public KeePassSecretStore(KeePassVault vault, SecretsMetaStore meta)
        {
            if (vault == null) throw new ArgumentNullException("vault");
            if (meta == null) throw new ArgumentNullException("meta");
            this.vault = vault;
            this.meta = meta;
        }

        private Secret Compose(VaultSecretEntry e)
        {
            SecretMeta m = meta.Get(e.Name);
            return new Secret(e.Name, e.AllowedHosts, e.CreatedAt, m.LastUsedAt, m.UsageCount, m.Quarantined);
        }

        private Secret Require(string name)
        {
            VaultSecretEntry e = vault.FindSecret(name);
            if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return Compose(e);
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt)
        {
            Secret.ValidateName(name);
            IList<string> hosts = InMemorySecretStore.NormalizeHosts(allowedHosts);
            vault.AddSecret(name, value, hosts, createdAt);
            meta.Remove(name);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts)
        {
            IList<string> hosts = InMemorySecretStore.NormalizeHosts(allowedHosts);
            Require(name);
            vault.SetAllowedHosts(name, hosts);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> RotateAsync(string name, byte[] newValue)
        {
            Require(name);
            vault.SetValue(name, newValue);
            return Task.FromResult(Require(name));
        }

        public Task DeleteAsync(string name)
        {
            Require(name);
            vault.DeleteSecret(name);
            meta.Remove(name);
            return Task.FromResult(0);
        }

        public Task<byte[]> ValueAsync(string name)
        {
            byte[] value = vault.ReadValue(name);
            if (value == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
            return Task.FromResult(value);
        }

        public Task<Secret> SecretAsync(string name) { return Task.FromResult(Require(name)); }

        public Task<IList<Secret>> ListAsync()
        {
            List<Secret> list = new List<Secret>();
            foreach (VaultSecretEntry e in vault.ListSecrets()) list.Add(Compose(e));
            return Task.FromResult((IList<Secret>)list);
        }

        public Task<Secret> RecordUsageAsync(string name, DateTime at)
        {
            Require(name);
            meta.RecordUsage(name, at);
            return Task.FromResult(Require(name));
        }

        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined)
        {
            Require(name);
            meta.SetQuarantined(name, quarantined);
            return Task.FromResult(Require(name));
        }
    }
}
```

- [ ] **Step 6: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\CA\CAMaterial.cs" "%SRC%\IrisKit\SecretStore\KeePassVault.cs" "%SRC%\IrisKit\SecretStore\KeePassSecretStore.cs"`. → `52 test(s) réussi(s)`.

Points d'attention à l'exécution : (a) si `ProtectedString.ReadUtf8()` ou le constructeur `ProtectedString(bool, byte[])` n'existent pas sous ce nom dans KeePassLib 2.61.1, les remplacer par `Encoding.UTF8.GetBytes(ps.ReadString())` / `new ProtectedString(true, Encoding.UTF8.GetString(value))` et consigner ; (b) `PwIcon.Certificate` existe dans l'enum `PwIcon` (sinon `PwIcon.Key`) ; (c) `Argon2Kdf(Argon2Type.D)` est le constructeur public de KeePassLib 2.35+ ; (d) Argon2 par défaut prend ~1 s par création/ouverture (64 Mo, 2 itérations) : six tests KeePass ≈ 10–15 s, c'est attendu.

- [ ] **Step 7: Commit**

```bash
git add src/IrisKit/CA/CAMaterial.cs src/IrisKit/SecretStore/KeePassVault.cs src/IrisKit/SecretStore/KeePassSecretStore.cs tests/KeePassTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): coffre KeePass (schéma kdbx, .lock, backups) et ISecretStore de production

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: CA — `CACrypto`, `ICAKeyStore`, `CAManager`

**Files:**
- Create: `src\IrisKit\CA\CACrypto.cs`, `src\IrisKit\CA\CAKeyStore.cs`, `src\IrisKit\CA\CAManager.cs`
- Create: `tests\CATests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `CAMaterial`, `KeePassVault.ReadCA/WriteCA`, `Log`.
- Produces: `CACrypto` (`Subject = "CN=IRIS local CA, O=iris"`, `GenerateKey() : ECDsaCng`, `ExportPkcs8(ECDsaCng) : byte[]`, `ImportPkcs8(byte[]) : ECDsaCng`, `CreateRootCertificate(ECDsaCng, DateTime now, int validityYears) : X509Certificate2` (public seul), `RandomSerial() : byte[]`, `Fingerprint(byte[] der) : string`, `ToPem(byte[] der) : string`, `SameKey(ECDsa, X509Certificate2) : bool`) ; `ICAKeyStore { CAMaterial Load(); void Store(CAMaterial m); }`, `InMemoryCAKeyStore`, `KeePassCAKeyStore(KeePassVault)` ; `CACertificate` (`Der`, `Pem`, `FingerprintSha256`, `NotBefore`, `NotAfter`, `Subject`) ; `CAManager(ICAKeyStore store, string pemPath, Func<DateTime> clock) : IDisposable` (`EnsureCA() : CACertificate`, `Certificate : X509Certificate2`, `SigningKey : ECDsaCng`, `Info : CACertificate`, `Regenerated : bool`, `ValidityYears = 10`).

- [ ] **Step 1: Écrire `tests\CATests.cs` (RED)**

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IrisKit;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- CA ------------------------------------------------------

        private static void CA_GenerateAndReload()
        {
            string dir = TestDir.Create();
            try
            {
                string pem = Path.Combine(dir, "ca.pem");
                InMemoryCAKeyStore store = new InMemoryCAKeyStore();
                CACertificate info;
                string thumbprint;
                using (CAManager ca = new CAManager(store, pem, delegate { return T0; }))
                {
                    info = ca.EnsureCA();
                    Check.True(ca.Regenerated, "première génération");
                    X509Certificate2 cert = ca.Certificate;
                    thumbprint = cert.Thumbprint;
                    Check.Eq("CN=IRIS local CA, O=iris", cert.Subject, "sujet");
                    Check.Eq(cert.Subject, cert.Issuer, "auto-signé");
                    Check.True(!cert.HasPrivateKey, "Certificate est la partie publique seulement");
                    bool caTrue = false, keyUsageOk = false;
                    foreach (X509Extension ext in cert.Extensions)
                    {
                        X509BasicConstraintsExtension bc = ext as X509BasicConstraintsExtension;
                        if (bc != null) caTrue = bc.CertificateAuthority && bc.Critical;
                        X509KeyUsageExtension ku = ext as X509KeyUsageExtension;
                        if (ku != null) keyUsageOk = (ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0 && (ku.KeyUsages & X509KeyUsageFlags.CrlSign) != 0;
                    }
                    Check.True(caTrue && keyUsageOk, "basicConstraints CA:TRUE critique, keyUsage keyCertSign+cRLSign");
                    Check.True(cert.NotBefore.ToUniversalTime() <= T0 && cert.NotAfter.ToUniversalTime() >= T0.AddYears(10).AddDays(-1), "validité 10 ans, notBefore antidaté");
                    Check.True(info.FingerprintSha256.Length == 95 && info.FingerprintSha256.Contains(":"), "empreinte SHA-256 hex avec deux-points");
                    Check.True(File.ReadAllText(pem).StartsWith("-----BEGIN CERTIFICATE-----\n") && File.ReadAllText(pem).EndsWith("-----END CERTIFICATE-----\n"), "ca.pem PEM");
                    Check.Eq(thumbprint, new X509Certificate2(pem).Thumbprint, "ca.pem = le certificat");
                    byte[] data = Encoding.UTF8.GetBytes("tbs");
                    byte[] sig = ca.SigningKey.SignData(data, HashAlgorithmName.SHA256);
                    Check.True(cert.GetECDsaPublicKey().VerifyData(data, sig, HashAlgorithmName.SHA256), "la clé de signature correspond au certificat");
                }
                Check.True(store.Load() != null && store.Load().CertificateDer.Length > 0 && store.Load().PrivateKeyPkcs8.Length > 100, "matériel stocké");
                File.WriteAllText(pem, "périmé");
                using (CAManager again = new CAManager(store, pem, delegate { return T0.AddDays(1); }))
                {
                    again.EnsureCA();
                    Check.True(!again.Regenerated && again.Certificate.Thumbprint == thumbprint, "rechargé depuis le store, pas régénéré");
                    Check.Eq(thumbprint, new X509Certificate2(pem).Thumbprint, "ca.pem réécrit s'il ne correspond plus");
                    byte[] data = Encoding.UTF8.GetBytes("tbs2");
                    Check.True(again.Certificate.GetECDsaPublicKey().VerifyData(data, again.SigningKey.SignData(data, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256), "clé réimportée depuis PKCS#8 utilisable");
                }
                using (CAManager noPem = new CAManager(store, null, delegate { return T0; }))
                {
                    noPem.EnsureCA();
                    Check.True(!noPem.Regenerated, "pemPath null : pas d'export, pas de régénération");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void CA_MismatchOrExpiredRegenerates()
        {
            InMemoryCAKeyStore store = new InMemoryCAKeyStore();
            using (ECDsaCng k1 = CACrypto.GenerateKey())
            using (ECDsaCng k2 = CACrypto.GenerateKey())
            {
                X509Certificate2 certOfK2 = CACrypto.CreateRootCertificate(k2, T0, 10);
                store.Store(new CAMaterial(CACrypto.ExportPkcs8(k1), certOfK2.Export(X509ContentType.Cert), T0));
                using (CAManager ca = new CAManager(store, null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(ca.Regenerated && ca.Certificate.Thumbprint != certOfK2.Thumbprint, "clé et certificat désaccordés → régénéré");
                    Check.True(CACrypto.SameKey(ca.SigningKey, ca.Certificate), "nouveau couple cohérent");
                }
                X509Certificate2 expired = CACrypto.CreateRootCertificate(k1, T0.AddYears(-11), 10);
                store.Store(new CAMaterial(CACrypto.ExportPkcs8(k1), expired.Export(X509ContentType.Cert), T0.AddYears(-11)));
                using (CAManager ca = new CAManager(store, null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(ca.Regenerated, "certificat expiré → régénéré");
                }
            }
        }

        private static void CA_KeePassKeyStore()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                string thumbprint;
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (CAManager ca = new CAManager(new KeePassCAKeyStore(vault), Path.Combine(dir, "ca.pem"), delegate { return T0; }))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    ca.EnsureCA();
                    thumbprint = ca.Certificate.Thumbprint;
                }
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                using (CAManager ca = new CAManager(new KeePassCAKeyStore(vault), null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(!ca.Regenerated && ca.Certificate.Thumbprint == thumbprint, "CA persisté dans le coffre et rechargé");
                }
                string pemText = File.ReadAllText(Path.Combine(dir, "ca.pem"));
                byte[] kdbxBytes = File.ReadAllBytes(kdbx);
                Check.True(Encoding.ASCII.GetString(kdbxBytes).IndexOf("BEGIN", StringComparison.Ordinal) < 0, "rien en clair dans le kdbx (chiffré)");
                Check.True(!pemText.Contains("PRIVATE"), "ca.pem ne contient que le certificat");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
```

`Main` : `Check.Run("CA : génération, export PEM, rechargement", CA_GenerateAndReload); Check.Run("CA : désaccord clé/certificat ou expiration → régénération", CA_MismatchOrExpiredRegenerates); Check.Run("CA : persistance dans le coffre KeePass", CA_KeePassKeyStore);` — `TEST_SOURCES` : ajouter `"%TESTS%\CATests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'CAManager'`.

- [ ] **Step 3: Écrire `src\IrisKit\CA\CACrypto.cs`**

```csharp
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Primitives du CA (SPECS §11.1, spec socle §6.1) sur CNG : ECDSA P-256, PKCS#8 (`Pkcs8PrivateBlob`),
    /// racine auto-signée CN=IRIS local CA, O=iris, 10 ans, basicConstraints CA:TRUE, keyUsage keyCertSign+cRLSign.
    /// </summary>
    public static class CACrypto
    {
        public const string Subject = "CN=IRIS local CA, O=iris";

        public static ECDsaCng GenerateKey()
        {
            return new ECDsaCng(ECCurve.NamedCurves.nistP256);
        }

        public static byte[] ExportPkcs8(ECDsaCng key)
        {
            return key.Key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }

        public static ECDsaCng ImportPkcs8(byte[] pkcs8)
        {
            return new ECDsaCng(CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob));
        }

        /// <summary>Racine auto-signée ; rend la partie publique seulement (la clé reste dans `key`). notBefore antidaté d'une heure.</summary>
        public static X509Certificate2 CreateRootCertificate(ECDsaCng key, DateTime now, int validityYears)
        {
            CertificateRequest req = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            DateTimeOffset notBefore = new DateTimeOffset(now.ToUniversalTime()).AddHours(-1);
            using (X509Certificate2 withKey = req.CreateSelfSigned(notBefore, notBefore.AddYears(validityYears).AddHours(1)))
            {
                return new X509Certificate2(withKey.Export(X509ContentType.Cert));
            }
        }

        public static byte[] RandomSerial()
        {
            byte[] serial = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) rng.GetBytes(serial);
            serial[0] &= 0x7f;
            if (serial[0] == 0) serial[0] = 1;
            return serial;
        }

        public static string Fingerprint(byte[] der)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(der);
                StringBuilder sb = new StringBuilder(95);
                for (int i = 0; i < digest.Length; i++)
                {
                    if (i > 0) sb.Append(':');
                    sb.Append(digest[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        public static string ToPem(byte[] der)
        {
            StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
            string b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64)
                sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
            sb.Append("-----END CERTIFICATE-----\n");
            return sb.ToString();
        }

        /// <summary>La clé publique de `key` est-elle celle du certificat ?</summary>
        public static bool SameKey(ECDsa key, X509Certificate2 certificate)
        {
            using (ECDsa pub = certificate.GetECDsaPublicKey())
            {
                if (pub == null) return false;
                ECParameters a = key.ExportParameters(false);
                ECParameters b = pub.ExportParameters(false);
                return Convert.ToBase64String(a.Q.X) == Convert.ToBase64String(b.Q.X) && Convert.ToBase64String(a.Q.Y) == Convert.ToBase64String(b.Q.Y);
            }
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\CA\CAKeyStore.cs`**

```csharp
namespace IrisKit
{
    /// <summary>Persistance du matériel CA : coffre KeePass en production, mémoire pour les tests et `--in-memory-ca`.</summary>
    public interface ICAKeyStore
    {
        /// <summary>null si aucun CA n'est stocké.</summary>
        CAMaterial Load();
        void Store(CAMaterial material);
    }

    public sealed class InMemoryCAKeyStore : ICAKeyStore
    {
        private CAMaterial material;
        public CAMaterial Load() { return material; }
        public void Store(CAMaterial m) { material = m; }
    }

    /// <summary>Entrée `root` du groupe `ca` de iris.kdbx (spec §4.1) ; clé privée en champ protégé.</summary>
    public sealed class KeePassCAKeyStore : ICAKeyStore
    {
        private readonly KeePassVault vault;
        public KeePassCAKeyStore(KeePassVault vault) { this.vault = vault; }
        public CAMaterial Load() { return vault.ReadCA(); }
        public void Store(CAMaterial m) { vault.WriteCA(m); }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\CA\CAManager.cs`**

```csharp
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IrisKit
{
    public sealed class CACertificate
    {
        public byte[] Der { get; private set; }
        public string Pem { get; private set; }
        public string FingerprintSha256 { get; private set; }
        public DateTime NotBefore { get; private set; }
        public DateTime NotAfter { get; private set; }
        public string Subject { get; private set; }

        public CACertificate(X509Certificate2 certificate)
        {
            Der = certificate.Export(X509ContentType.Cert);
            Pem = CACrypto.ToPem(Der);
            FingerprintSha256 = CACrypto.Fingerprint(Der);
            NotBefore = certificate.NotBefore.ToUniversalTime();
            NotAfter = certificate.NotAfter.ToUniversalTime();
            Subject = certificate.Subject;
        }
    }

    /// <summary>
    /// Charge le CA depuis le store ou le génère (clé + certificat stockés ensemble), vérifie la cohérence
    /// clé/certificat et la validité (sinon régénère, avec avertissement), exporte ca.pem si demandé.
    /// </summary>
    public sealed class CAManager : IDisposable
    {
        public const int ValidityYears = 10;
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        private readonly ICAKeyStore store;
        private readonly string pemPath;
        private readonly Func<DateTime> clock;

        public X509Certificate2 Certificate { get; private set; }
        public ECDsaCng SigningKey { get; private set; }
        public CACertificate Info { get; private set; }
        public bool Regenerated { get; private set; }

        public CAManager(ICAKeyStore store, string pemPath, Func<DateTime> clock)
        {
            if (store == null) throw new ArgumentNullException("store");
            this.store = store;
            this.pemPath = pemPath;
            this.clock = clock;
        }

        public CACertificate EnsureCA()
        {
            DateTime now = clock();
            CAMaterial material = store.Load();
            if (material != null && TryLoad(material, now))
            {
                Regenerated = false;
            }
            else
            {
                if (material != null) Log.Warn("ca", "CA stocké inutilisable (clé et certificat désaccordés, ou certificat hors validité) : régénération, les clients devront réapprouver data\\ca.pem");
                Generate(now);
                Regenerated = true;
            }
            Info = new CACertificate(Certificate);
            ExportPem();
            Log.Info("ca", "CA " + (Regenerated ? "généré" : "chargé") + " : " + Info.Subject + ", empreinte SHA-256 " + Info.FingerprintSha256 + ", valide jusqu'au " + Json.FormatDate(Info.NotAfter));
            return Info;
        }

        private bool TryLoad(CAMaterial material, DateTime now)
        {
            ECDsaCng key = null;
            X509Certificate2 cert = null;
            try
            {
                key = CACrypto.ImportPkcs8(material.PrivateKeyPkcs8);
                cert = new X509Certificate2(material.CertificateDer);
                if (!CACrypto.SameKey(key, cert)) return false;
                if (cert.NotBefore.ToUniversalTime() > now || cert.NotAfter.ToUniversalTime() <= now) return false;
                if (cert.Subject != CACrypto.Subject) return false;
                SigningKey = key;
                Certificate = cert;
                key = null;
                return true;
            }
            catch (CryptographicException ex)
            {
                Log.Warn("ca", "matériel CA illisible : " + ex.Message);
                return false;
            }
            finally
            {
                if (key != null) key.Dispose();
            }
        }

        private void Generate(DateTime now)
        {
            ECDsaCng key = CACrypto.GenerateKey();
            X509Certificate2 cert = CACrypto.CreateRootCertificate(key, now, ValidityYears);
            store.Store(new CAMaterial(CACrypto.ExportPkcs8(key), cert.Export(X509ContentType.Cert), now));
            SigningKey = key;
            Certificate = cert;
        }

        private void ExportPem()
        {
            if (pemPath == null) return;
            try
            {
                if (File.Exists(pemPath) && File.ReadAllText(pemPath, Encoding.UTF8) == Info.Pem) return;
                Directory.CreateDirectory(Path.GetDirectoryName(pemPath));
                File.WriteAllText(pemPath, Info.Pem, Utf8NoBom);
                Log.Info("ca", "certificat public exporté : " + pemPath);
            }
            catch (IOException ex) { Log.Error("ca", "export de " + pemPath + " impossible : " + ex.Message); }
            catch (UnauthorizedAccessException ex) { Log.Error("ca", "export de " + pemPath + " impossible : " + ex.Message); }
        }

        public void Dispose()
        {
            if (SigningKey != null) { SigningKey.Dispose(); SigningKey = null; }
            if (Certificate != null) { Certificate.Reset(); Certificate = null; }
        }
    }
}
```

- [ ] **Step 6: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\CA\CACrypto.cs" "%SRC%\IrisKit\CA\CAKeyStore.cs" "%SRC%\IrisKit\CA\CAManager.cs"`. → `55 test(s) réussi(s)`. Note : `ECDsaCng(ECCurve)` et `CertificateRequest` existent depuis .NET Framework 4.7.2 ; `X509Certificate2.Reset()` libère le contexte natif.

- [ ] **Step 7: Commit**

```bash
git add src/IrisKit/CA tests/CATests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): CA ECDSA P-256 persisté dans le coffre, export ca.pem, rechargement vérifié

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 10: Daemon — `DataDir`, `VaultSession`, `ConsoleInput`, `Daemon`, `Entry`, codes de sortie

**Files:**
- Create: `src\IrisKit\DataDir.cs`, `src\IrisKit\SecretStore\VaultSession.cs`
- Create: `src\irisd\ExitCodes.cs`, `src\irisd\IConsoleInput.cs`, `src\irisd\Daemon.cs`, `src\irisd\Entry.cs`
- Modify: `src\irisd\Arguments.cs` (niveaux IRIS, valeur blanche refusée), `src\irisd\Program.cs` (délègue à `Entry.Run`)
- Modify: `docs\superpowers\specs\2026-10-17-socle-design.md` §5.5 (niveaux de log IRIS)
- Create: `tests\DaemonTests.cs` ; Modify: `tests\TestSupport.cs` (`ScriptedConsoleInput`), `tests\Tests.cs` (tests d'arguments ajustés), `test.bat`, `build.bat`

**Interfaces:**
- Consumes: tout IrisKit (tâches 1–9), `Arguments`.
- Produces: `DataDir.Resolve(string overridePath) : string`, `DataDir.Prepare(string) ` (crée `data\`, `events\`, `backups\`, teste l'écriture), `DataDirException` ; `SecureStrings.Equal(SecureString, SecureString)` ; `VaultSession(string dataDir) : IDisposable` (`KdbxPath`, `Exists`, `Vault : KeePassVault`, `IsUnlocked`, `Unlock(SecureString) : KeePassVault`, `Create(SecureString, DateTime) : KeePassVault`) ; `Irisd.ExitCodes { Ok = 0, Data = 1, Vault = 2, Port = 3, Arguments = 4 }` ; `IConsoleInput.ReadPassword(string prompt) : SecureString` (null = entrée fermée), `ConsoleInput` ; `Daemon(Arguments, TextWriter stdout, TextWriter stderr, IConsoleInput)` avec `Run(CancellationToken) : int`, `MaxPasswordAttempts = 3` ; `Entry.Run(string[] args, TextWriter stdout, TextWriter stderr, IConsoleInput console, CancellationToken cancel) : int` ; `Arguments.LogLevels` = `LogLevelWire.Names` ; `ScriptedConsoleInput(params string[] answers)` (`Prompts : IList<string>`) côté tests.

- [ ] **Step 1: Ajuster les tests d'arguments dans `tests\Tests.cs`**

Dans `Arguments_AllOptions`, remplacer `Check.Eq(4, Arguments.LogLevels.Length, "quatre niveaux : debug, info, warning, error");` par `Check.Eq("trace,debug,info,warn,error", string.Join(",", Arguments.LogLevels), "niveaux IRIS");`. Dans `Arguments_MissingValue`, ajouter : `Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--data", "  " }); }, "--data fait d'espaces (revue phase 0)");`. Dans `Arguments_BadLogLevel`, ajouter : `Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level", "warning" }); }, "warning n'est pas une valeur IRIS (warn)");`. Dans `Arguments_UsageText`, remplacer la vérification `DEBUG` par deux : `Check.True(usage.Contains("DEBUG"), "…")` inchangée et `Check.True(usage.Contains("trace | debug | info | warn | error"), "niveaux IRIS dans l'aide");`.

- [ ] **Step 2: Ajouter `ScriptedConsoleInput` à `tests\TestSupport.cs`**

```csharp
    /// <summary>Console scriptée : chaque ReadPassword rend la réponse suivante, null quand la liste est épuisée (EOF).</summary>
    public sealed class ScriptedConsoleInput : Irisd.IConsoleInput
    {
        private readonly System.Collections.Generic.Queue<string> answers;
        public System.Collections.Generic.List<string> Prompts = new System.Collections.Generic.List<string>();

        public ScriptedConsoleInput(params string[] answers)
        {
            this.answers = new System.Collections.Generic.Queue<string>(answers);
        }

        public SecureString ReadPassword(string prompt)
        {
            Prompts.Add(prompt);
            return answers.Count == 0 ? null : TestMain.Secure(answers.Dequeue());
        }
    }
```

- [ ] **Step 3: Écrire `tests\DaemonTests.cs` (RED)**

```csharp
using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Threading;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Daemon (Entry.Run) ----------------------------------------

        private sealed class RunResult
        {
            public int Code;
            public string Out;
            public string Err;
            public string All { get { return Out + "\n" + Err; } }
        }

        private static RunResult RunDaemon(ScriptedConsoleInput console, params string[] args)
        {
            StringWriter stdout = new StringWriter();
            StringWriter stderr = new StringWriter();
            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel(); // le daemon démarre tout puis s'arrête aussitôt
            Log.Reset();
            RunResult r = new RunResult();
            try { r.Code = Entry.Run(args, stdout, stderr, console, cts.Token); }
            finally { Log.Reset(); }
            r.Out = stdout.ToString();
            r.Err = stderr.ToString();
            return r;
        }

        private static void Entry_ArgumentsAndExitCodes()
        {
            RunResult r = RunDaemon(new ScriptedConsoleInput(), "--bogus");
            Check.True(r.Code == ExitCodes.Arguments && r.Err.Contains("option inconnue : --bogus") && r.Err.Contains("Usage :"), "option inconnue → 4 + usage sur stderr");
            r = RunDaemon(new ScriptedConsoleInput());
            Check.True(r.Code == 1 && r.Err.Contains("Usage :") && r.Out.Length == 0, "sans --foreground → 1");
            r = RunDaemon(new ScriptedConsoleInput(), "--version");
            Check.True(r.Code == ExitCodes.Ok && r.Out.Trim() == "irisd " + IrisVersion.Value, "--version");
            r = RunDaemon(new ScriptedConsoleInput(), "--help");
            Check.True(r.Code == ExitCodes.Ok && r.Out.StartsWith("Usage :"), "--help");
            r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", "  ");
            Check.Eq(ExitCodes.Arguments, r.Code, "--data blanc → 4");
            string def = DataDir.Resolve(null);
            Check.True(def.EndsWith("\\data") && Path.GetDirectoryName(def) == Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "data\\ à côté de l'exécutable par défaut");
            Check.Eq(Path.GetFullPath("rel\\x"), DataDir.Resolve("rel\\x"), "--data relatif résolu depuis le répertoire courant");
        }

        private static void Entry_CreatesVaultAndCA()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                ScriptedConsoleInput console = new ScriptedConsoleInput("maître", "maître");
                RunResult r = RunDaemon(console, "--foreground", "--data", data, "--log-level", "debug");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage puis arrêt propre : " + r.Err);
                Check.Eq(2, console.Prompts.Count, "mot de passe et confirmation demandés");
                Check.True(console.Prompts[0].Contains("nouveau coffre"), "invite de création explicite");
                foreach (string f in new[] { "config.json", "iris.kdbx", "ca.pem", "events", "backups" })
                    Check.True(File.Exists(Path.Combine(data, f)) || Directory.Exists(Path.Combine(data, f)), "créé : " + f);
                Check.True(r.Out.Contains("coffre créé") && r.Out.Contains("CA généré") && r.Out.Contains("prêt"), "journal de démarrage");
                Check.True(!r.All.Contains("maître"), "le mot de passe n'apparaît nulle part");
                string pem = File.ReadAllText(Path.Combine(data, "ca.pem"));

                console = new ScriptedConsoleInput("maître");
                r = RunDaemon(console, "--foreground", "--data", data);
                Check.Eq(ExitCodes.Ok, r.Code, "réouverture");
                Check.True(console.Prompts.Count == 1 && r.Out.Contains("coffre ouvert") && r.Out.Contains("CA chargé"), "coffre et CA rechargés");
                Check.Eq(pem, File.ReadAllText(Path.Combine(data, "ca.pem")), "ca.pem stable entre deux démarrages");
                Check.True(!r.Out.Contains("DEBUG"), "aucun avertissement de mode debug");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_WrongPasswordThreeTimes_Exit2()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                RunDaemon(new ScriptedConsoleInput("bon", "bon"), "--foreground", "--data", data);
                ScriptedConsoleInput console = new ScriptedConsoleInput("mauvais-un", "mauvais-deux", "mauvais-trois");
                RunResult r = RunDaemon(console, "--foreground", "--data", data);
                Check.Eq(ExitCodes.Vault, r.Code, "trois échecs → 2");
                Check.Eq(3, console.Prompts.Count, "trois tentatives");
                Check.True(r.Err.Contains("refusé") && r.Err.Contains("3/3"), "message clair avec le compte");
                Check.True(!r.All.Contains("mauvais-un") && !r.All.Contains("mauvais-deux") && !r.All.Contains("mauvais-trois") && !r.All.Contains("bon"), "aucun mot de passe dans les sorties");
                r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data);
                Check.True(r.Code == ExitCodes.Vault && r.Err.Contains("entrée fermée"), "EOF sur l'invite → 2");
                r = RunDaemon(new ScriptedConsoleInput("mauvais", "bon"), "--foreground", "--data", data);
                Check.Eq(ExitCodes.Ok, r.Code, "réussite à la deuxième tentative");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_PasswordMismatchOnCreate()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                // essai 1 : x/y (différents) ; essai 2 : "" (vide, pas de confirmation demandée) ; essai 3 : x/x
                RunResult r = RunDaemon(new ScriptedConsoleInput("x", "y", "", "x", "x"), "--foreground", "--data", data);
                Check.True(r.Code == ExitCodes.Ok && r.Err.Contains("ne correspondent pas") && r.Err.Contains("vide"), "confirmation différente puis vide : nouvelles tentatives, puis création");
                Check.True(File.Exists(Path.Combine(data, "iris.kdbx")), "coffre créé au troisième essai");
                r = RunDaemon(new ScriptedConsoleInput("a", "b", "c", "d", "e", "f"), "--foreground", "--data", Path.Combine(dir, "data2"));
                Check.Eq(ExitCodes.Vault, r.Code, "trois confirmations ratées → 2");
                Check.True(!File.Exists(Path.Combine(dir, "data2", "iris.kdbx")), "aucun coffre créé");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_DataDirNotWritable_Exit1()
        {
            string dir = TestDir.Create();
            try
            {
                string asFile = Path.Combine(dir, "data");
                File.WriteAllText(asFile, "je suis un fichier");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", asFile, "--in-memory-secrets", "--in-memory-ca");
                Check.True(r.Code == ExitCodes.Data && r.Err.Contains(asFile), "data\\ inutilisable → 1 avec le chemin");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_CorruptedConfig_StillStarts()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                Directory.CreateDirectory(data);
                File.WriteAllText(Path.Combine(data, "config.json"), "{ corrompu");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage dégradé, pas d'arrêt");
                Check.Eq(1, Directory.GetFiles(Path.Combine(data, "backups"), "config-corrupted-*.json").Length, "copie du fichier corrompu");
                string[] events = Directory.GetFiles(Path.Combine(data, "events"), "events-*.jsonl");
                Check.True(events.Length == 1 && File.ReadAllText(events[0]).Contains("\"kind\":\"systemAlert\"") && File.ReadAllText(events[0]).Contains("\"severity\":\"high\""), "event systemAlert high journalisé");
                Check.True(r.Out.Contains("corrompu"), "erreur journalisée");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_InMemorySecretsAndCA()
        {
            string dir = TestDir.Create();
            Environment.SetEnvironmentVariable("IRIS_SECRET_test_key", "sk-test-value", EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable("IRIS_SECRET_test_key_HOSTS", "api.example.com", EnvironmentVariableTarget.Process);
            try
            {
                string data = Path.Combine(dir, "data");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Ok, r.Code, "mode debug complet");
                Check.True(r.Out.Contains("DEBUG") && r.Out.Contains("in-memory-secrets") && r.Out.Contains("in-memory-ca") && r.Out.Contains("1 secret(s)"), "avertissements visibles, un secret chargé");
                Check.True(!File.Exists(Path.Combine(data, "iris.kdbx")) && File.Exists(Path.Combine(data, "ca.pem")), "pas de coffre, mais ca.pem exporté");
                RunResult r2 = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets");
                Check.True(r2.Code == ExitCodes.Ok && r2.Out.Contains("aussi éphémère"), "--in-memory-secrets sans --in-memory-ca : CA éphémère, avertissement");
            }
            finally
            {
                Environment.SetEnvironmentVariable("IRIS_SECRET_test_key", null, EnvironmentVariableTarget.Process);
                Environment.SetEnvironmentVariable("IRIS_SECRET_test_key_HOSTS", null, EnvironmentVariableTarget.Process);
                TestDir.Delete(dir);
            }
        }

        private static void Security_NoSecretValueInDumps()
        {
            string dir = TestDir.Create();
            const string value = "sk-ant-TOPSECRET-9f8e7d";
            Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe", value, EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe_HOSTS", "api.example.com", EnvironmentVariableTarget.Process);
            try
            {
                string data = Path.Combine(dir, "data");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca", "--log-level", "trace");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage");
                Check.True(!r.All.Contains(value), "stdout/stderr sans la valeur");
                foreach (string f in Directory.GetFiles(data, "*", SearchOption.AllDirectories))
                    Check.True(!File.ReadAllText(f).Contains(value), "fichier sans la valeur : " + Path.GetFileName(f));

                InMemorySecretStore store = new InMemorySecretStore();
                Wait(store.AddAsync("leak_probe", Bytes(value), new[] { "api.example.com" }, T0));
                Wait(store.RecordUsageAsync("leak_probe", T0));
                EventRing ring = new EventRing(10);
                EventsBus bus = new EventsBus();
                StringWriter log = new StringWriter();
                Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Trace;
                using (JsonlEventStore jsonl = new JsonlEventStore(Path.Combine(data, "events2"), 7, delegate { return T0; }))
                {
                    EventPipeline p = new EventPipeline(ring, jsonl, bus);
                    p.Emit(new Event(Guid.NewGuid(), T0, EventKind.Substituted, "api.example.com", "POST", "/v1", 200, 12, new[] { "leak_probe" }, null, null, EventFlags.None));
                    p.Emit(new Event(Guid.NewGuid(), T0, EventKind.ExfilBlocked, "evil.example", "POST", "/", null, null, new string[0],
                        new Alert(AlertSeverity.High, ExfilRule.HostMismatch, "leak_probe", AlertLocation.Header, Redaction.Redact(value)), null, EventFlags.None));
                    Log.Info("proxy", "substitution de leak_probe (" + Redaction.Redact(value) + ")");
                }
                Log.Reset();
                string dump = Json.Emit(new System.Collections.Generic.List<object>(new System.Collections.Generic.List<Event>(ring.All).ConvertAll(delegate(Event e) { return (object)e.ToJson(); })))
                    + File.ReadAllText(Path.Combine(data, "events2", "events-2023-11-14.jsonl")) + log.ToString();
                Check.True(dump.Contains("leak_probe") && dump.Contains("[REDACTED:"), "le nom et la redaction apparaissent");
                Check.True(!dump.Contains(value), "la valeur n'apparaît ni dans le ring, ni dans le journal, ni dans le log");
            }
            finally
            {
                Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe", null, EnvironmentVariableTarget.Process);
                Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe_HOSTS", null, EnvironmentVariableTarget.Process);
                TestDir.Delete(dir);
            }
        }
    }
}
```

`Main` :

```csharp
            Check.Run("Daemon : arguments, codes de sortie, résolution de data\\", Entry_ArgumentsAndExitCodes);
            Check.Run("Daemon : crée le coffre, le CA et ca.pem, puis les recharge", Entry_CreatesVaultAndCA);
            Check.Run("Daemon : trois mots de passe refusés → 2, EOF → 2", Entry_WrongPasswordThreeTimes_Exit2);
            Check.Run("Daemon : confirmation du mot de passe à la création", Entry_PasswordMismatchOnCreate);
            Check.Run("Daemon : data\\ inutilisable → 1", Entry_DataDirNotWritable_Exit1);
            Check.Run("Daemon : config.json corrompu = démarrage dégradé", Entry_CorruptedConfig_StillStarts);
            Check.Run("Daemon : --in-memory-secrets et --in-memory-ca", Entry_InMemorySecretsAndCA);
            Check.Run("Sécurité : aucune valeur de secret dans les dumps", Security_NoSecretValueInDumps);
```

`TEST_SOURCES` : ajouter `"%TESTS%\DaemonTests.cs"`. `IRISD_SOURCES` de `test.bat` : `"%SRC%\irisd\Arguments.cs" "%SRC%\irisd\ExitCodes.cs" "%SRC%\irisd\IConsoleInput.cs" "%SRC%\irisd\Daemon.cs" "%SRC%\irisd\Entry.cs"` (toujours sans `Program.cs`).

- [ ] **Step 4: Vérifier l'échec** — `CS0246 'ExitCodes'` / `'Entry'` / `'Irisd.IConsoleInput'`.

- [ ] **Step 5: Modifier `src\irisd\Arguments.cs`**

Remplacer `public static readonly string[] LogLevels = { "debug", "info", "warning", "error" };` par `public static readonly string[] LogLevels = IrisKit.LogLevelWire.Names;`. Dans `Usage()`, remplacer `"  --log-level <niveau>   debug | info | warning | error (défaut : config.json)",` par `"  --log-level <niveau>   trace | debug | info | warn | error (défaut : config.json)",`. Dans `ValueOf`, remplacer `args[i + 1].Length == 0` par `string.IsNullOrWhiteSpace(args[i + 1])`.

- [ ] **Step 6: Écrire `src\irisd\ExitCodes.cs`**

```csharp
namespace Irisd
{
    /// <summary>Codes de sortie de irisd (spec §7).</summary>
    public static class ExitCodes
    {
        public const int Ok = 0;
        public const int Data = 1;       // données ou config (et aide sans --foreground)
        public const int Vault = 2;      // coffre : mot de passe refusé trois fois, base illisible
        public const int Port = 3;       // port occupé (phase 2)
        public const int Arguments = 4;  // ligne de commande invalide
    }
}
```

- [ ] **Step 7: Écrire `src\irisd\IConsoleInput.cs`**

```csharp
using System;
using System.Security;

namespace Irisd
{
    /// <summary>Saisie du mot de passe maître. null = entrée fermée (EOF). Jamais loguée.</summary>
    public interface IConsoleInput
    {
        SecureString ReadPassword(string prompt);
    }

    /// <summary>Console réelle : saisie masquée (ReadKey) ; si l'entrée est redirigée, ReadLine avec avertissement unique.</summary>
    public sealed class ConsoleInput : IConsoleInput
    {
        private bool warnedRedirected;

        public SecureString ReadPassword(string prompt)
        {
            Console.Error.Write(prompt);
            SecureString s = new SecureString();
            if (Console.IsInputRedirected)
            {
                if (!warnedRedirected)
                {
                    Console.Error.WriteLine();
                    Console.Error.WriteLine("(entrée redirigée : la saisie ne peut pas être masquée)");
                    warnedRedirected = true;
                }
                string line = Console.In.ReadLine();
                if (line == null) return null;
                foreach (char c in line) s.AppendChar(c);
                s.MakeReadOnly();
                return s;
            }
            while (true)
            {
                ConsoleKeyInfo key;
                try { key = Console.ReadKey(true); }
                catch (InvalidOperationException) { return null; }
                if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (s.Length > 0) s.RemoveAt(s.Length - 1); continue; }
                if (key.KeyChar != '\0') s.AppendChar(key.KeyChar);
            }
            Console.Error.WriteLine();
            s.MakeReadOnly();
            return s;
        }
    }
}
```

- [ ] **Step 8: Écrire `src\IrisKit\DataDir.cs`**

```csharp
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
```

- [ ] **Step 9: Écrire `src\IrisKit\SecretStore\VaultSession.cs`**

```csharp
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;

namespace IrisKit
{
    public static class SecureStrings
    {
        /// <summary>Comparaison en temps constant sur la longueur commune, sans laisser de copie en clair.</summary>
        public static bool Equal(SecureString a, SecureString b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            IntPtr pa = IntPtr.Zero, pb = IntPtr.Zero;
            try
            {
                pa = Marshal.SecureStringToGlobalAllocUnicode(a);
                pb = Marshal.SecureStringToGlobalAllocUnicode(b);
                int diff = 0;
                for (int i = 0; i < a.Length; i++) diff |= Marshal.ReadInt16(pa, i * 2) ^ Marshal.ReadInt16(pb, i * 2);
                return diff == 0;
            }
            finally
            {
                if (pa != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pa);
                if (pb != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pb);
            }
        }
    }

    /// <summary>
    /// Cycle de vie du coffre (spec §4.3) : chemin `data\iris.kdbx`, création ou déverrouillage par SecureString.
    /// L'API `Unlock(SecureString)` sera aussi appelée par le lot IPC (`vault.unlock`).
    /// </summary>
    public sealed class VaultSession : IDisposable
    {
        public string KdbxPath { get; private set; }
        public KeePassVault Vault { get; private set; }
        public bool Exists { get { return File.Exists(KdbxPath); } }
        public bool IsUnlocked { get { return Vault != null; } }

        public VaultSession(string dataDir)
        {
            KdbxPath = Path.Combine(dataDir, "iris.kdbx");
        }

        public KeePassVault Unlock(SecureString password)
        {
            if (Vault != null) return Vault;
            Vault = KeePassVault.Open(KdbxPath, password);
            return Vault;
        }

        public KeePassVault Create(SecureString password, DateTime now)
        {
            if (Exists) throw new SecretStoreException(SecretStoreErrorKind.Duplicate, null, "le coffre existe déjà : " + KdbxPath);
            Vault = KeePassVault.Create(KdbxPath, password, now);
            return Vault;
        }

        public void Dispose()
        {
            if (Vault != null) { Vault.Dispose(); Vault = null; }
        }
    }
}
```

- [ ] **Step 10: Écrire `src\irisd\Daemon.cs`**

```csharp
using System;
using System.IO;
using System.Security;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Séquence de démarrage de la spec §7 (phase 1, sans proxy) : data\ → config → events → coffre → CA → attente → arrêt propre.
    /// Rend un code de sortie ; n'écrit sur stderr que les erreurs fatales, le reste passe par Log (stdout).
    /// </summary>
    public sealed class Daemon
    {
        public const int MaxPasswordAttempts = 3;

        private readonly Arguments options;
        private readonly TextWriter stdout;
        private readonly TextWriter stderr;
        private readonly IConsoleInput console;

        public Daemon(Arguments options, TextWriter stdout, TextWriter stderr, IConsoleInput console)
        {
            this.options = options; this.stdout = stdout; this.stderr = stderr; this.console = console;
        }

        public int Run(CancellationToken cancel)
        {
            Func<DateTime> clock = delegate { return DateTime.UtcNow; };
            Log.Writer = stdout;
            LogLevel requested;
            if (options.LogLevel != null && LogLevelWire.TryParse(options.LogLevel, out requested)) Log.Minimum = requested;

            // 1. data\
            string dataDir = DataDir.Resolve(options.Data);
            try { DataDir.Prepare(dataDir); }
            catch (DataDirException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Data; }

            // 2. config.json
            ConfigStore config;
            try { config = ConfigStore.Open(dataDir, clock()); }
            catch (ConfigIOException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Data; }
            if (options.LogLevel == null) Log.Minimum = config.Current.Broker.LogLevel;
            Log.Info("irisd", "irisd " + IrisVersion.Value + ", données : " + dataDir);

            // 3. events
            EventRing ring = new EventRing(config.Current.Broker.EventRingSize);
            EventsBus bus = new EventsBus();
            JsonlEventStore eventStore = new JsonlEventStore(Path.Combine(dataDir, "events"), config.Current.Broker.EventRetentionDays, clock);
            eventStore.Purge();
            EventPipeline events = new EventPipeline(ring, eventStore, bus);
            if (config.RecoveredFromCorruption)
                events.Emit(Event.System(clock(), AlertSeverity.High, "config",
                    "config.json corrompu, valeurs par défaut rétablies (copie dans backups\\) : " + config.CorruptionDetail));

            VaultSession session = null;
            SecretsMetaStore meta = null;
            SecretCache secrets = null;
            CAManager ca = null;
            try
            {
                // 4. secrets
                KeePassVault vault = null;
                if (options.InMemorySecrets)
                {
                    Log.Warn("secrets", "DEBUG : --in-memory-secrets, aucun coffre ouvert, secrets lus depuis IRIS_SECRET_<NAME> / IRIS_SECRET_<NAME>_HOSTS");
                    InMemorySecretStore memory = new InMemorySecretStore();
                    int n = EnvSecrets.LoadInto(memory, Environment.GetEnvironmentVariables(), clock());
                    Log.Info("secrets", n + " secret(s) chargé(s) depuis l'environnement");
                    secrets = new SecretCache(memory);
                }
                else
                {
                    session = new VaultSession(dataDir);
                    int rc = UnlockInteractive(session, clock);
                    if (rc != ExitCodes.Ok) return rc;
                    vault = session.Vault;
                    vault.MaxBackups = config.Current.Backups.MaxCount;
                    vault.Clock = clock;
                    meta = new SecretsMetaStore(Path.Combine(dataDir, "secrets-meta.json"), vault.SecretNames, SecretsMetaStore.DefaultDebounce, clock);
                    secrets = new SecretCache(new KeePassSecretStore(vault, meta));
                    Log.Info("vault", "coffre ouvert : " + session.KdbxPath + ", " + vault.SecretNames().Count + " secret(s)");
                }

                // 5. CA
                ICAKeyStore caStore;
                if (options.InMemoryCa)
                {
                    Log.Warn("ca", "DEBUG : --in-memory-ca, CA régénéré à chaque démarrage, jamais persisté");
                    caStore = new InMemoryCAKeyStore();
                }
                else if (vault == null)
                {
                    Log.Warn("ca", "--in-memory-secrets sans coffre ouvert : le CA est aussi éphémère (équivalent à --in-memory-ca)");
                    caStore = new InMemoryCAKeyStore();
                }
                else caStore = new KeePassCAKeyStore(vault);
                ca = new CAManager(caStore, Path.Combine(dataDir, "ca.pem"), clock);
                try { ca.EnsureCA(); }
                catch (SecretStoreException ex) { stderr.WriteLine("irisd : CA : " + ex.Message); return ExitCodes.Vault; }

                // 6. prêt (phase 1 : pas de proxy)
                Log.Info("irisd", "prêt (phase 1 : proxy non démarré). ca=" + Path.Combine(dataDir, "ca.pem") + " empreinte=" + ca.Info.FingerprintSha256 + ". Ctrl+C pour arrêter.");
                cancel.WaitHandle.WaitOne();
                Log.Info("irisd", "arrêt demandé");
                return ExitCodes.Ok;
            }
            finally
            {
                if (secrets != null) secrets.Clear();
                if (meta != null) meta.Dispose();
                if (ca != null) ca.Dispose();
                if (session != null) session.Dispose();
                eventStore.Dispose();
            }
        }

        /// <summary>Création (mot de passe + confirmation) ou ouverture ; trois échecs consécutifs ou entrée fermée → code 2.</summary>
        private int UnlockInteractive(VaultSession session, Func<DateTime> clock)
        {
            if (!session.Exists)
            {
                stderr.WriteLine("Aucun coffre dans " + session.KdbxPath + " : création d'un nouveau coffre KeePass.");
                for (int attempt = 1; attempt <= MaxPasswordAttempts; attempt++)
                {
                    SecureString first = console.ReadPassword("Mot de passe maître du nouveau coffre : ");
                    if (first == null) return Closed();
                    if (first.Length == 0) { stderr.WriteLine("Le mot de passe ne peut pas être vide (" + attempt + "/" + MaxPasswordAttempts + ")."); continue; }
                    SecureString second = console.ReadPassword("Confirmez le mot de passe maître : ");
                    if (second == null) return Closed();
                    if (!SecureStrings.Equal(first, second)) { stderr.WriteLine("Les deux saisies ne correspondent pas (" + attempt + "/" + MaxPasswordAttempts + ")."); continue; }
                    try { session.Create(first, clock()); return ExitCodes.Ok; }
                    catch (SecretStoreException ex) { stderr.WriteLine("irisd : création du coffre impossible : " + ex.Message); return ExitCodes.Vault; }
                }
                stderr.WriteLine("Trois échecs : arrêt sans créer de coffre.");
                return ExitCodes.Vault;
            }
            for (int attempt = 1; attempt <= MaxPasswordAttempts; attempt++)
            {
                SecureString password = console.ReadPassword("Mot de passe maître (" + session.KdbxPath + ") : ");
                if (password == null) return Closed();
                try { session.Unlock(password); return ExitCodes.Ok; }
                catch (SecretStoreException ex)
                {
                    if (ex.Kind == SecretStoreErrorKind.VaultLocked)
                    {
                        stderr.WriteLine("Mot de passe refusé (" + attempt + "/" + MaxPasswordAttempts + ").");
                        continue;
                    }
                    stderr.WriteLine("irisd : " + ex.Message);
                    return ExitCodes.Vault;
                }
            }
            stderr.WriteLine("Trois échecs : arrêt.");
            return ExitCodes.Vault;
        }

        private int Closed()
        {
            stderr.WriteLine("irisd : entrée fermée pendant la saisie du mot de passe, arrêt.");
            return ExitCodes.Vault;
        }
    }
}
```

- [ ] **Step 11: Écrire `src\irisd\Entry.cs` et réécrire `src\irisd\Program.cs`**

`Entry.cs` :

```csharp
using System;
using System.IO;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>Point d'entrée testable (revue phase 0) : analyse des arguments, aide, version, puis Daemon.Run.</summary>
    public static class Entry
    {
        public static int Run(string[] args, TextWriter stdout, TextWriter stderr, IConsoleInput console, CancellationToken cancel)
        {
            Arguments options;
            try { options = Arguments.Parse(args); }
            catch (ArgumentsException ex)
            {
                stderr.WriteLine("irisd : " + ex.Message);
                stderr.WriteLine();
                stderr.Write(Arguments.Usage());
                return ExitCodes.Arguments;
            }
            if (options.ShowHelp) { stdout.Write(Arguments.Usage()); return ExitCodes.Ok; }
            if (options.ShowVersion) { stdout.WriteLine("irisd " + IrisVersion.Value); return ExitCodes.Ok; }
            if (!options.Foreground)
            {
                // Sans --foreground le socle affiche l'aide et sort code 1 (le mode arrière-plan arrive avec le lot autostart).
                stderr.Write(Arguments.Usage());
                return ExitCodes.Data;
            }
            return new Daemon(options, stdout, stderr, console).Run(cancel);
        }
    }
}
```

`Program.cs` (contenu complet) :

```csharp
using System;
using System.Text;
using System.Threading;

namespace Irisd
{
    /// <summary>Main réel : encodage UTF-8, Ctrl+C → annulation coopérative, tout le reste dans Entry.Run.</summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            CancellationTokenSource cts = new CancellationTokenSource();
            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                cts.Cancel();
            };
            return Entry.Run(args, Console.Out, Console.Error, new ConsoleInput(), cts.Token);
        }
    }
}
```

- [ ] **Step 12: Corriger la spec §5.5 et mettre à jour `build.bat`**

Dans `docs\superpowers\specs\2026-10-17-socle-design.md`, remplacer `` `Log` : niveaux `debug|info|warning|error`, sortie console horodatée, `log_level` de la config. `` par `` `Log` : niveaux `trace|debug|info|warn|error` (valeurs de `broker.log_level` d'IRIS, reprises telles quelles par `--log-level`), sortie console horodatée, `log_level` de la config. `` ; et dans le §2, ligne « Compilateur », rien ne change. Dans `build.bat`, `IRISD_SOURCES` devient `"%SRC%\irisd\Arguments.cs" "%SRC%\irisd\ExitCodes.cs" "%SRC%\irisd\IConsoleInput.cs" "%SRC%\irisd\Daemon.cs" "%SRC%\irisd\Entry.cs" "%SRC%\irisd\Program.cs"` et `IRISKIT_SOURCES` (les deux `.bat`) reçoit `"%SRC%\IrisKit\DataDir.cs" "%SRC%\IrisKit\SecretStore\VaultSession.cs"`.

- [ ] **Step 13: Vérifier le vert et le build**

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
cmd //c 'D:\Dev\irispc\build.bat' | tail -1
```

Attendu : `63 test(s) réussi(s), 0 échec(s)`, `[SUCCES]`. Les tests du daemon créent chacun un coffre Argon2 : compter 20 à 40 s pour la suite complète.

- [ ] **Step 14: Vérifier le daemon réel (démonstration de la phase 1)**

```powershell
$d = Join-Path $env:TEMP ("irispc-demo-" + [guid]::NewGuid().ToString("N"))
$p = Start-Process -FilePath D:\Dev\irispc\build\Iris\irisd.exe -ArgumentList "--foreground","--data","$d","--in-memory-secrets","--in-memory-ca" -PassThru -NoNewWindow -RedirectStandardOutput "$d.log"
Start-Sleep -Seconds 4
Get-ChildItem $d -Recurse | Select-Object -ExpandProperty FullName
Get-Content "$d.log"
Stop-Process -Id $p.Id -Force
Remove-Item -Recurse -Force $d, "$d.log"
```

Attendu : `config.json`, `ca.pem`, `events\`, `backups\` dans le dossier ; le log montre les deux avertissements DEBUG, `CA généré`, `prêt (phase 1 : proxy non démarré)`. Puis, avec un vrai coffre, en interactif dans un terminal (pas depuis l'agent) : `build\Iris\irisd.exe --foreground --data %TEMP%\irispc-demo2` demande le mot de passe deux fois, crée `iris.kdbx`, et Ctrl+C affiche `arrêt demandé` avec code 0 — à cocher dans la PR.

- [ ] **Step 15: Commit**

```bash
git add src/irisd src/IrisKit/DataDir.cs src/IrisKit/SecretStore/VaultSession.cs tests/DaemonTests.cs tests/TestSupport.cs tests/Tests.cs test.bat build.bat docs/superpowers/specs/2026-10-17-socle-design.md
git commit -m "feat(irisd): démarrage de la phase 1 (data, config, events, coffre interactif, CA) et Entry.Run testable

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: CI, CLAUDE.md, push et PR de la phase 1

**Files:**
- Modify: `.github\workflows\ci.yml`, `CLAUDE.md`

**Interfaces:**
- Consumes: la branche complète.
- Produces: CI verte, PR vers `main` (merge en squash après confirmation explicite de l'utilisateur, hors plan).

- [ ] **Step 1: Mettre à jour `.github\workflows\ci.yml`** (contenu complet)

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: true

jobs:
  build-test:
    runs-on: windows-latest
    timeout-minutes: 20
    defaults:
      run:
        shell: cmd
    steps:
      - uses: actions/checkout@v4

      - name: Compilateur csc.exe natif
        run: dir "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

      - name: Tests (test.bat)
        run: call test.bat

      - name: Build (build.bat)
        run: call build.bat

      - name: Dossier portable
        uses: actions/upload-artifact@v4
        with:
          name: irispc-portable
          path: build/Iris
          if-no-files-found: error
```

- [ ] **Step 2: Mettre à jour `CLAUDE.md`**

Dans « Build, tests, rendu », remplacer « Les trois fichiers KeePass sont commités dans `vendor\` et copiés dans le dossier portable. » par « Les trois fichiers d'exécution de KeePass (`KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll`), plus `License.txt`, sont commités dans `vendor\` (empreintes dans son README) et copiés dans le dossier portable. ». Dans « Conventions », ajouter la puce : « Niveaux de log : valeurs IRIS `trace|debug|info|warn|error` partout (`config.json`, `--log-level`, `Log`). ». Dans « Phasage », remplacer la ligne 2 par « 2. **Phase 1** — `IrisKit` : `Json`, `Config`, modèles, `ISecretStore` + `KeePassSecretStore`, coffre, CA dans le coffre, events et log ; `irisd --foreground` crée le coffre, le CA et `ca.pem` puis attend. ».

- [ ] **Step 3: Vérifier la liste complète des sources des deux `.bat`**

`IRISKIT_SOURCES` (identique dans `test.bat` et `build.bat`) doit être exactement :

```bat
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs" "%SRC%\IrisKit\DataDir.cs" "%SRC%\IrisKit\Json\JsonParser.cs" "%SRC%\IrisKit\Json\JsonObject.cs" "%SRC%\IrisKit\Json\JsonWriter.cs" "%SRC%\IrisKit\Models\HostName.cs" "%SRC%\IrisKit\Models\Secret.cs" "%SRC%\IrisKit\Models\MITMRule.cs" "%SRC%\IrisKit\Models\Alert.cs" "%SRC%\IrisKit\Models\Event.cs" "%SRC%\IrisKit\Logging\Log.cs" "%SRC%\IrisKit\Logging\Redaction.cs" "%SRC%\IrisKit\Config\Config.cs" "%SRC%\IrisKit\Config\Backups.cs" "%SRC%\IrisKit\Config\ConfigStore.cs" "%SRC%\IrisKit\Events\EventRing.cs" "%SRC%\IrisKit\Events\EventsBus.cs" "%SRC%\IrisKit\Events\JsonlEventStore.cs" "%SRC%\IrisKit\Events\EventPipeline.cs" "%SRC%\IrisKit\SecretStore\ISecretStore.cs" "%SRC%\IrisKit\SecretStore\InMemorySecretStore.cs" "%SRC%\IrisKit\SecretStore\SecretCache.cs" "%SRC%\IrisKit\SecretStore\EnvSecrets.cs" "%SRC%\IrisKit\SecretStore\SecretsMetaStore.cs" "%SRC%\IrisKit\SecretStore\KeePassVault.cs" "%SRC%\IrisKit\SecretStore\KeePassSecretStore.cs" "%SRC%\IrisKit\SecretStore\VaultSession.cs" "%SRC%\IrisKit\CA\CAMaterial.cs" "%SRC%\IrisKit\CA\CACrypto.cs" "%SRC%\IrisKit\CA\CAKeyStore.cs" "%SRC%\IrisKit\CA\CAManager.cs"
```

`TEST_SOURCES` : `"%TESTS%\Check.cs" "%TESTS%\TestSupport.cs" "%TESTS%\Tests.cs" "%TESTS%\JsonTests.cs" "%TESTS%\ModelsTests.cs" "%TESTS%\LoggingTests.cs" "%TESTS%\ConfigTests.cs" "%TESTS%\EventsTests.cs" "%TESTS%\SecretStoreTests.cs" "%TESTS%\MetaStoreTests.cs" "%TESTS%\KeePassTests.cs" "%TESTS%\CATests.cs" "%TESTS%\DaemonTests.cs"`.

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -2 && cmd //c 'D:\Dev\irispc\build.bat' | tail -1 && git status --short
```

Attendu : `63 test(s) réussi(s)`, `[SUCCES]`, seuls `ci.yml` et `CLAUDE.md` modifiés.

- [ ] **Step 4: Commit, push, CI**

```bash
git add .github/workflows/ci.yml CLAUDE.md
git commit -m "ci: un seul run par PR, permissions minimales ; docs: CLAUDE.md phase 1

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -u origin feat/phase-1-iriskit
```

Le workflow ne se déclenche plus sur `push` d'une branche de fonctionnalité : la CI tourne à l'ouverture de la PR (étape 5). Après `gh pr create`, attendre le run :

```bash
RUN=$(gh run list --branch feat/phase-1-iriskit --limit 1 --json databaseId --jq '.[0].databaseId'); gh run watch --exit-status "$RUN"; echo "EXIT=$?"
gh api repos/Sandjab/irispc/actions/runs/$RUN/artifacts --jq '.artifacts[].name'
```

Attendu : `EXIT=0`, `irispc-portable`. Un échec : `gh run view "$RUN" --log-failed`, corriger, commiter `fix(ci): …`, re-pousser.

- [ ] **Step 5: Ouvrir la PR** (corps dans le scratchpad, puis `gh pr create --base main --head feat/phase-1-iriskit --title "Phase 1 : IrisKit — JSON, config, modèles, coffre KeePass, CA, events ; irisd --foreground" --body-file <scratchpad>/pr-body.md`)

```markdown
## Phase 1 — IrisKit : coffre, config, CA, events

Spec : `docs/superpowers/specs/2026-10-17-socle-design.md` (§3, §4, §5, §7, §8, §9, §11). Plan : `docs/superpowers/plans/2026-10-17-phase-1-iriskit.md`.

- `Json` (parse, lecture typée, émission ordonnée, dates ISO), modèles au format de fil IRIS (fixtures reprises de `ModelsTests.swift`), `Log` + `Redaction`.
- `Config` + `ConfigStore` : seed, validation par champ, écriture atomique, backups rotatifs, démarrage dégradé sur corruption (`config-corrupted-*`, event `systemAlert` high).
- Events : ring borné avec totaux, bus d'abonnés, journal JSONL par jour UTC avec purge.
- Secrets : `ISecretStore`, mémoire, cache LRU 32 / 5 min, `IRIS_SECRET_*` (debug), `secrets-meta.json` débouncé, `KeePassVault` (Argon2d, groupes `secrets` / `ca`, `.lock` → `VaultBusy`, backup avant écriture), `KeePassSecretStore`, `VaultSession`.
- CA ECDSA P-256 persisté dans le coffre (PKCS#8 en champ protégé), `ca.pem` exporté, rechargement vérifié (clé/certificat/validité).
- `irisd --foreground` : `data\`, config, events, coffre interactif (création avec confirmation, 3 essais), CA, attente Ctrl+C ; `Entry.Run` testable avec console scriptée.
- Mineurs de la revue de phase 0 repris : `--data` blanc refusé, `ExitCodes`, `Entry.Run`, CI sans double run + permissions, CLAUDE.md.
- Niveaux de log alignés sur IRIS (`trace|debug|info|warn|error`), spec §5.5 corrigée.

## Smoke testing

- [ ] `test.bat` : 63 tests OK, code 0 (≈ 30 s, Argon2)
- [ ] `build.bat` : `build\Iris\irisd.exe` compilé, dossier portable complet
- [ ] `irisd.exe --foreground --data %TEMP%\demo` : demande le mot de passe deux fois, crée `config.json`, `iris.kdbx`, `ca.pem`, `events\`, `backups\`, affiche `prêt`, Ctrl+C → `arrêt demandé`, code 0
- [ ] Relance avec le bon mot de passe : `coffre ouvert`, `CA chargé`, `ca.pem` inchangé
- [ ] Relance avec trois mauvais mots de passe : `Mot de passe refusé (3/3)`, code 2, aucun mot de passe affiché
- [ ] `iris.kdbx` s'ouvre dans `build\Iris\KeePass.exe` : groupes `secrets` (vide) et `ca` (entrée `root`, mot de passe = clé PKCS#8 base64, champ `certificate`)
- [ ] Avec `iris.kdbx` ouvert dans KeePass.exe (fichier `.lock` présent) : le daemon démarre toujours (lecture) ; la vérification de l'écriture refusée est couverte par le test `KeePass : .lock = VaultBusy`
- [ ] `config.json` remplacé par `{ corrompu` : démarrage, `backups\config-corrupted-*.json`, ligne `systemAlert` dans `events\events-*.jsonl`
- [ ] `--in-memory-secrets --in-memory-ca` avec `IRIS_SECRET_x` / `IRIS_SECRET_x_HOSTS` : avertissements DEBUG, `1 secret(s)`, pas de `iris.kdbx`
- [ ] `--log-level warning` → code 4 ; `--log-level warn` accepté
- [ ] CI verte sur la PR, artefact `irispc-portable`
- [ ] `git status` propre après `build.bat` + `test.bat`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 6: Rendre compte** — URL de la PR, état de la CI, rappel que le merge en squash attend la confirmation explicite de l'utilisateur. Ne pas merger.

---

## Auto-revue du plan

- **Couverture de la spec** : §3 dossier portable et résolution de `data\` (tâche 10 `DataDir`) ; §4.1 schéma kdbx (8), §4.2 `secrets-meta.json` (7), §4.3 déverrouillage, 3 échecs, `--in-memory-*` (10), §4.4 interface et erreurs (2, 6, 8), cache (6), §4.5 écritures avec `.lock` et backups (8) ; §5.1 config et démarrage dégradé (4), §5.2 JSON (1), §5.3 modèles et enums (2), §5.5 events, journal et log (3, 5) ; §6.1 `CAManager` (9) — `LeafCertCache` est en phase 2 ; §7 séquence et codes 0/1/2/4 (10), code 3 en phase 2 ; §8 invariants 1 (test `Security_NoSecretValueInDumps`), 3 (console scriptée, aucune trace), 4 partiellement (clé CA chiffrée dans le kdbx ; clés des feuilles en phase 2), 5 (aucun mode ne désactive quoi que ce soit : les modes debug n'existent que pour la source des secrets et du CA), 7 (ACL héritée, rien d'autre) ; §9 lignes Json, Config, Modèles, InMemorySecretStore, KeePassSecretStore, CAManager (les lignes Scanner, Engine, HttpParser, Proxy, LeafCertCache sont en phase 2) ; §11 phase 1 démontrable (tâche 10 étape 14).
- **Placeholders** : aucun ; chaque étape porte son code ou sa commande.
- **Cohérence des types** : `Json.Parse/ParseObject/Emit/EmitCompact/FormatDate/ParseDate`, `JsonObject.String/OptionalString/Int/OptionalInt/Bool/Object/OptionalObject/Array/OptionalArray/StringArray/Raw/Has/Keys` utilisés identiquement dans 2, 4, 5, 7, 8 ; `Secret(name, hosts, createdAt, lastUsedAt, usageCount, quarantined)` à six arguments partout ; `Event` à douze arguments partout ; `SecretStoreException(kind, name, message[, inner])` ; `Backups.CopyWithStamp(source, dir, prefix, ext, now)` / `Rotate(dir, prefix, ext, max)` dans 4 et 8 ; `SecretsMetaStore(path, existingNames, debounce, clock)` dans 7, 8, 10 ; `KeePassVault.Create(path, pwd, now)` / `Open(path, pwd)` dans 8, 9, 10 ; `CAManager(store, pemPath, clock)` dans 9 et 10 ; `InMemorySecretStore.NormalizeHosts` est `internal static` et appelé depuis `KeePassSecretStore` (même assembly) ; `AlertWire.IndexOf` est `internal` et réutilisé par `EventWire`, `ExfilPolicyWire`.
- **Review Focus** : 1 → `Entry_WrongPasswordThreeTimes_Exit2` (10) ; 2 → `ConfigStore_Corrupted_DegradedBoot` (4) et `Entry_CorruptedConfig_StillStarts` (10) ; 3 → `KeePass_LockFile_VaultBusy` (8) ; 4 → `Security_NoSecretValueInDumps` (10) ; 5 → `EnvSecrets_MissingHosts_Ignored` (6).
- **Décisions prises par le plan, à confirmer en revue** : niveaux de log alignés sur IRIS (spec corrigée) ; clé `flags` optionnelle sur l'`Event` ; `--in-memory-secrets` implique un CA éphémère ; `secrets-meta.json` illisible → repart vide avec avertissement ; rétention du journal = « les N derniers jours, aujourd'hui compris » ; `plugins` conservé brut et réémis.
