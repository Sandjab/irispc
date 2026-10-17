# irispc — Spec « socle » (phases 0 à 2)

Date : 2026-10-17. Statut : approuvée en brainstorming, en attente de relecture du document.

Source de vérité amont : `../Iris/SPECS.md` (IRIS 1.0.1, macOS). Ce document ne redit pas ce que SPECS.md fixe déjà ; il consigne **les décisions propres au portage Windows** et le périmètre exact des trois premières phases. Quand ce document est muet, SPECS.md s'applique. Quand les deux divergent, ce document prime pour irispc et la divergence est listée au §2.

## 1. Périmètre

Le socle livre un daemon `irisd.exe` capable, en avant-plan, de :

1. créer ou ouvrir le coffre KeePass et le CA local ;
2. écouter en proxy sur `127.0.0.1:8888` ;
3. tunneler sans déchiffrer les hôtes hors whitelist ;
4. déchiffrer les hôtes whitelistés, substituer les placeholders `{{kc:NAME}}` selon le scoping `allowed_hosts` et les règles R1–R5, relayer la réponse en streaming ;
5. consigner les events en mémoire et sur disque.

Hors socle, traités par les specs suivantes : IPC admin (named pipe JSON-RPC) et flux SSE, CLI `iris`, app de la zone de notification, `mcp wrap`, `doctor`, lancement avec Windows, installation du CA dans le magasin Windows, zip de release, manuel et GitHub Pages, plugins.

Le socle est démontrable ainsi : `irisd --foreground`, `HTTPS_PROXY=http://127.0.0.1:8888`, `curl --cacert data\ca.pem -H "x-api-key: {{kc:anthropic_api_key}}" https://api.anthropic.com/v1/models` reçoit une réponse authentifiée, et un event `substituted` apparaît dans `data\events\`.

## 2. Décisions de portage

| Sujet | IRIS macOS | irispc | Pourquoi |
|---|---|---|---|
| Coffre | Keychain login + ACL sur binaire signé | Base KeePass `data\iris.kdbx` ouverte par **mot de passe maître saisi une fois par session** et conservé en mémoire du daemon | Seul moyen sans service dédié de garder la frontière de confiance : un processus de l'utilisateur (l'agent) ne peut pas ouvrir la base sans le mot de passe. DPAPI utilisateur aurait été déchiffrable par l'agent. |
| Moteur du coffre | — | `KeePassLib` **tel que compilé dans `KeePass.exe` 2.61.1** (pas de `KeePassLib.dll` séparée dans le zip portable), référencé par csc avec `-r:KeePass.exe`, comme un plugin KeePass | Vérifié par spike : création, écriture, relecture, rejet d'un mauvais mot de passe. |
| Distribution de KeePass | — | `KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll` commités dans `vendor\KeePass-2.61.1\` et copiés dans le dossier portable | SourceForge sert un captcha aux clients non-navigateur : aucun téléchargement au build ni en CI. L'utilisateur ouvre `iris.kdbx` avec ce même KeePass pour auditer. GPLv2 compatible MIT ; le zip combiné est sous GPL, sans effet pour un projet ouvert. |
| Clé privée du CA | Keychain système + ACL | Entrée `root` du groupe `ca` de la base KeePass (PKCS#8 base64, champ protégé) | Jamais en clair sur disque, même garantie que le reste des secrets, aucun second mécanisme. |
| Emplacement des données | `~/Library/Application Support/iris/` | `data\` **à côté des exécutables**, résolu par chaque exe depuis son propre chemin | Portable au sens d'ImPactHUD : un dossier déplaçable. Pas de repli vers AppData : si `data\` n'est pas inscriptible, refus de démarrer avec message. |
| Processus | `irisd`, `iris`, `Iris.app` | `irisd.exe`, `iris.exe`, `IrisApp.exe` (le socle ne produit que le premier) | Parité : le daemon survit à l'app, la CLI est scriptable. |
| IPC admin | socket Unix 0600 | named pipe `\\.\pipe\iris-admin`, ACL utilisateur courant ; clé de config `broker.admin_pipe` remplace `broker.admin_socket` | Même propriété d'isolation, natif .NET. Hors socle, mais la clé de config est fixée ici. |
| Persistance des events | SQLite | fichiers JSONL journaliers `data\events\events-AAAA-MM-JJ.jsonl` | SQLite n'existe pas dans le .NET Framework sans DLL native. |
| Métadonnées d'usage des secrets | attributs Keychain réécrits à chaque usage | `data\secrets-meta.json` écrit avec débounce | Réécrire un `.kdbx` (KDF comprise) à chaque requête est exclu. |
| Compilateur | Swift 5.9, SwiftPM | `csc.exe` natif de `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319` : **C# 5**, .NET Framework 4.8, aucun SDK ni NuGet | Contrainte du projet (méthode ImPactHUD). Vérifié : `CertificateRequest` et `SslStream` suffisent pour le MITM ; cf. §6. |
| HTTP/2 | ALPN `http/1.1` seul | `SslStream` du .NET Framework n'émet pas d'ALPN : les deux côtés retombent naturellement sur HTTP/1.1 | Même résultat que §7.6 d'IRIS sans rien faire. |
| Pooling amont | pool de connexions inter-clients | une connexion amont par connexion cliente, réutilisée en keep-alive | Reporté : simplicité d'abord. |
| Plugins | hooks sandboxés | hors socle ; `config.plugins` accepté et ignoré | Lot ultérieur à décider. |

## 3. Dossier portable

```
Iris\
  irisd.exe            irisd.exe.config
  iris.exe             iris.exe.config        (lot CLI)
  IrisApp.exe          IrisApp.exe.config     (lot app)
  KeePass.exe  KeePass.exe.config  KeePass.XmlSerializers.dll
  data\
    config.json
    iris.kdbx          (+ iris.kdbx.lock quand KeePass.exe l'a ouverte)
    secrets-meta.json
    ca.pem
    events\events-AAAA-MM-JJ.jsonl
    backups\config-<horodatage>.json, iris-<horodatage>.kdbx, config-corrupted-<horodatage>.json
```

Chaque `.exe.config` contient, repris de `KeePass.exe.config` : `<supportedRuntime version="v4.0"/>`, la `bindingRedirect` de l'assembly `KeePass` (`oldVersion="2.0.9.0-2.61.0.127" newVersion="2.61.1.0"`, à faire évoluer avec la version embarquée) et `<enforceFIPSPolicy enabled="false"/>` (KeePassLib refuse de fonctionner sous politique FIPS).

Résolution de `data\` : `Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "data")`, surchargeable par `--data <dossier>` (tests, démos). Au démarrage le daemon crée `data\`, `events\`, `backups\` si absents, puis vérifie l'écriture par création et suppression d'un fichier témoin ; échec = sortie code 1 avec le chemin et la cause.

## 4. Coffre KeePass

### 4.1 Schéma de `iris.kdbx`

- Chiffrement AES-256, KDF Argon2d avec les paramètres par défaut de KeePassLib (`KdfPool` → `Argon2Kdf`, paramètres `GetDefaultParameters()`). Nom de base : `iris`.
- Groupe racine → groupe `secrets` : une entrée par secret.
  - `Title` = nom du secret, validé par `^[a-zA-Z0-9_-]{1,64}$`, unique (insensible à la casse pour le contrôle d'unicité, conservé tel quel).
  - `Password` = valeur, champ protégé (`ProtectedString(true, …)`).
  - champ `allowed_hosts` = tableau JSON de noms d'hôtes en minuscules, sans port.
  - champ `created_at` = ISO 8601 UTC.
- Groupe racine → groupe `ca` : entrée `root`.
  - `Password` = clé privée ECDSA P-256, PKCS#8 DER en base64, champ protégé.
  - champ `certificate` = certificat X.509 DER en base64.
  - champ `created_at`.
- Toute autre entrée ou groupe est ignoré en lecture (l'utilisateur peut ranger ce qu'il veut dans la base, mais iris n'écrit que dans `secrets` et `ca`).

### 4.2 Métadonnées volatiles : `secrets-meta.json`

```json
{ "version": 1,
  "secrets": { "anthropic_api_key": { "last_used_at": "2026-10-17T07:49:47Z", "usage_count": 1234, "quarantined": false } } }
```

Écrit par `SecretsMetaStore` au plus une fois toutes les 2 s (débounce) et à l'arrêt, atomiquement. Une entrée sans métadonnées vaut `usage_count = 0`, `quarantined = false`. Une métadonnée sans entrée correspondante est purgée à l'écriture suivante.

### 4.3 Déverrouillage et cycle de vie

- `irisd --foreground` demande le mot de passe sur la console avec saisie masquée. Si `iris.kdbx` n'existe pas : demande, confirmation, création. Trois échecs consécutifs = sortie code 2.
- Le mot de passe n'est jamais écrit, logué ni passé en argument. Le daemon conserve la `CompositeKey` KeePassLib en mémoire pour la durée du processus ; la `PwDatabase` reste ouverte en lecture.
- La transmission du mot de passe par l'app via le pipe admin (`vault.unlock`) relève de la spec IPC ; le socle expose déjà l'API interne `VaultSession.Unlock(SecureString)` qu'elle utilisera.
- `--in-memory-secrets` : pas de base ; les secrets viennent des variables d'environnement `IRIS_SECRET_<NAME>=<valeur>` et `IRIS_SECRET_<NAME>_HOSTS=h1,h2`. `--in-memory-ca` : CA régénéré à chaque démarrage, non persisté. Les deux drapeaux loguent un avertissement visible au démarrage. Ils ne désactivent **ni le scoping ni les règles** (règle 6 du CLAUDE.md d'IRIS).

### 4.4 Interface

```csharp
public interface ISecretStore
{
    Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt);
    Task<Secret> UpdateAsync(string name, IList<string> allowedHosts);
    Task<Secret> RotateAsync(string name, byte[] newValue);
    Task DeleteAsync(string name);
    Task<byte[]> ValueAsync(string name);          // jamais loguée, jamais mise dans un Event
    Task<Secret> SecretAsync(string name);
    Task<IList<Secret>> ListAsync();
    Task<Secret> RecordUsageAsync(string name, DateTime at);
    Task<Secret> SetQuarantinedAsync(string name, bool quarantined);
}
```

Erreurs : `SecretStoreException` avec un `Kind` (`InvalidName`, `InvalidAllowedHosts`, `UnknownSecret`, `Duplicate`, `VaultLocked`, `VaultBusy`, `DataCorruption`). `VaultBusy` est levé pour toute écriture quand `iris.kdbx.lock` existe (KeePass.exe a la base ouverte) ; la lecture reste permise.

Implémentations : `KeePassSecretStore` (production) et `InMemorySecretStore` (tests, et mode `--in-memory-secrets`). `SecretCache` : LRU de 32 valeurs, TTL 5 min, invalidé par `Rotate` et `Delete`, devant l'une ou l'autre.

### 4.5 Écritures

Toute mutation du coffre : vérification de `iris.kdbx.lock` → copie `iris.kdbx` vers `backups\iris-<horodatage>.kdbx` (rotation `backups.max_count`, même compteur que les backups de config) → mutation en mémoire → `PwDatabase.Save`. Une écriture à la fois (verrou en process).

## 5. IrisKit cœur

### 5.1 Config

`config.json` au format SPECS §6, avec `broker.admin_pipe` à la place de `broker.admin_socket`. Défauts : `listen 127.0.0.1:8888`, `events_listen 127.0.0.1:8899`, `admin_pipe iris-admin`, `log_level info`, `event_retention_days 7`, `event_ring_size 10000`, `on_exfil_attempt block_and_notify`, `max_substitutions_per_minute 60`, `backups.max_count 10`, `hosts = [api.anthropic.com, origin default]`. `plugins` est lu et réécrit tel quel, jamais interprété.

`ConfigStore` : `Load()` (seed si absent), `Validate()` (adresses `ip:port`, port 1–65535, hôtes DNS valides, politiques connues, entiers positifs), `Save(config)` atomique (écriture dans `config.json.tmp` puis `File.Replace`), backup horodaté avant chaque `Save`. Fichier illisible ou invalide au démarrage : copie vers `backups\config-corrupted-<horodatage>.json`, reseed, event système de sévérité haute, démarrage continué. Erreur d'E/S irrécupérable : sortie code 1.

### 5.2 JSON

Module `Json` au-dessus de `JavaScriptSerializer` : `Parse(string) → object` (dictionnaires, listes, string, double, bool, null), `Emit(object, indent: 2)` avec des `OrderedDictionary` pour maîtriser l'ordre des clés, dates émises en ISO 8601 UTC (`yyyy-MM-ddTHH:mm:ssZ`), lues depuis ISO 8601 avec ou sans fraction. Les modèles ont des méthodes `ToJson()` / `FromJson()` explicites, pas de réflexion.

### 5.3 Modèles

`Secret` (name, allowedHosts, createdAt, lastUsedAt?, usageCount, quarantined — sans valeur), `MITMRule` (host, origin `default|user`, createdAt), `Event` (id, timestamp, kind, host, method, path, statusCode?, durationMs?, substitutedSecrets, alert?, flags `bodyTooLarge|nonUtf8|compressedBody|paused`), `Alert` (severity, rule, secretName, detectedAt, snippet ≤ 256). Enums sérialisés avec les mêmes chaînes qu'IRIS (`substituted`, `passThrough`, `noMatch`, `exfilBlocked`, `error`, `hostMismatch`, …).

### 5.4 Placeholder et exfiltration

- `PlaceholderScanner.Scan(request) → IList<Match>` : regex `\{\{kc:([a-zA-Z0-9_-]{1,64})\}\}` appliquée aux noms et valeurs d'en-têtes, au chemin, à la query, et au corps si ≤ 4 MiB reçus et UTF-8 valide. Chaque `Match` porte le nom, l'emplacement (`header(nom)`, `urlPath`, `queryString`, `body`) et les offsets.
- `PlaceholderEngine.Resolve(host, matches, secrets) → Decision` : par nom, inconnu = laissé tel quel + event d'avertissement ; hôte absent de `allowed_hosts` = R1 ; sinon valeur via `ISecretStore` (cache). Comparaison d'hôtes : minuscules, sans port, exacte.
- `ExfilRuleEngine` : R1 hostMismatch (high), R2 nonCanonicalLocation (high ; canoniques : en-têtes `Authorization`, `x-api-key`, `api-key`, `x-auth-token`), R3 multipleSecrets (medium ; ≥ 2 secrets **connus** distincts), R4 suspiciousContentType (medium ; conservé pour la défense en profondeur), R5 volumeAnomaly (low ; `SlidingMinuteCounter` par secret). Une alerte par event, sévérité = max. Toute règle déclenchée = **aucune substitution** pour cette requête, transmise intacte.
- Politique `on_exfil_attempt` : `block_only` ; `block_and_notify` (le socle émet l'event, l'app notifiera) ; `block_notify_pause` (le daemon passe `Paused = true`, plus aucune substitution jusqu'à reprise ; la reprise est une méthode interne, exposée par le lot IPC).
- Substitution : octet à octet sur l'UTF-8, en-têtes reconstruits, `Content-Length` recalculé.

### 5.5 Events et journal

`EventRing` (capacité `event_ring_size`), `EventsBus` (abonnés synchrones in-process ; le SSE s'y abonnera), `JsonlEventStore` (un fichier par jour UTC, une ligne par event, flush à chaque écriture, purge au démarrage et à minuit UTC des fichiers plus vieux que `event_retention_days`). `Log` : niveaux `trace|debug|info|warn|error` (valeurs de `broker.log_level` d'IRIS, reprises telles quelles par `--log-level`), sortie console horodatée, `log_level` de la config. **Aucune valeur de secret** n'entre jamais dans un `Event`, un `Alert.snippet` ou une ligne de log : les snippets sont pris sur la requête **avant** substitution et tronqués.

## 6. Proxy MITM

### 6.1 Composants

| Classe | Rôle |
|---|---|
| `ProxyServer` | `TcpListener` sur `broker.listen`, boucle d'acceptation, une `Task` par connexion, arrêt coopératif par `CancellationToken`, `UpdateRules(IList<MITMRule>)` à chaud. |
| `HttpParser` | Lecture d'une tête HTTP/1.1 depuis un `Stream` (ligne de requête ou de statut, en-têtes, limites : tête ≤ 64 KiB, 100 en-têtes), lecture de corps `Content-Length` ou `chunked`, écriture de tête. Aucune dépendance. |
| `ConnectHandler` | Première requête d'une connexion cliente : `GET /__iris_ping` → `200 ok` et fermeture ; non-CONNECT → `405` ; autorité illisible → `400` ; sinon décision whitelist. |
| `TunnelHandler` | Hôte hors whitelist : connexion TCP amont, `200 Connection Established`, pompe bidirectionnelle, event `passThrough` à la fermeture. |
| `MITMHandler` | Hôte whitelisté : `200 Connection Established`, `SslStream` serveur avec la feuille de `LeafCertCache`, boucle keep-alive de requêtes : parse → scan → décision → substitution → envoi amont → relais de la réponse → event. |
| `UpstreamClient` | Connexion TCP + `SslStream` client (TLS 1.2 minimum, validation standard via le magasin Windows, SNI = hôte), délai de connexion 10 s, réutilisée tant que les deux côtés sont en keep-alive. |
| `CAManager` | Charge ou génère le CA (ECDSA P-256, `CN=IRIS local CA, O=iris`, 10 ans, `basicConstraints CA:TRUE`, `keyUsage keyCertSign,cRLSign`, pas de `NameConstraints`), le stocke dans le coffre, exporte `ca.pem`. |
| `LeafCertCache` | Feuille par hôte : CN = hôte, SAN DNS = hôte, 90 jours, `serverAuth`, signée par le CA ; aller-retour PFX avec `PersistKeySet` car Schannel refuse les clés éphémères ; la clé CNG est **supprimée** (`CngKey.Delete`) à l'éviction, au renouvellement et à l'arrêt. Cache mémoire, jamais sur disque. |

### 6.2 Flux par requête déchiffrée

1. Lire la tête ; répondre `100 Continue` si `Expect: 100-continue`.
2. Lire le corps : jusqu'à 4 MiB bufferisés ; au-delà, relayer tel quel en streaming avec `bodyTooLarge`, sans scan du corps (les en-têtes et l'URL sont quand même scannés). Corps non UTF-8 : `nonUtf8`, pas de scan du corps. `Content-Encoding` présent : `compressedBody`, pas de substitution dans le corps, avertissement.
3. Retirer `Accept-Encoding` (SPECS §7.5), retirer `Proxy-Connection`.
4. Scan → `PlaceholderEngine` → `ExfilRuleEngine`. Si le daemon est en pause (`Paused = true`) : les placeholders sont laissés intacts, aucune règle n'est évaluée, et l'event porte `kind = noMatch` avec le drapeau `paused = true` ; `exfilBlocked` reste réservé aux règles R1–R5.
5. Écrire la tête recalculée et le corps vers l'amont.
6. Lire la tête de réponse ; relayer tête puis corps par blocs de 16 KiB (ou chunks) jusqu'à `Content-Length`, fin de chunked, ou fermeture ; `flush` après chaque bloc (SSE).
7. Émettre l'`Event` (kind, host, method, path, statusCode, durationMs, substitutedSecrets, alert) ; `RecordUsage` pour chaque secret substitué ; incrémenter R5.
8. Si l'un des côtés a demandé `Connection: close`, fermer ; sinon boucler.

### 6.3 Erreurs et délais

| Situation | Comportement |
|---|---|
| Poignée de main côté agent échoue (CA non approuvé par le client) | event `error` avec `host`, log `warning` avec l'indice « le client ne fait pas confiance à data\ca.pem » ; connexion fermée. |
| DNS, connexion ou TLS amont en échec | `502 Bad Gateway` au client (corps texte court), event `error`. |
| Tête HTTP malformée ou trop grande | `400` et fermeture. |
| Inactivité > 120 s sur une connexion déchiffrée ou un tunnel | fermeture des deux côtés. |
| Port occupé au démarrage | sortie code 3 avec le port. |
| Ctrl+C | annulation : le listener ferme, les connexions en cours reçoivent 5 s pour finir, puis fermeture forcée ; `secrets-meta.json` et le journal sont flushés ; clés CNG des feuilles supprimées. |

## 7. Daemon `irisd`

`irisd.exe --foreground [--data <dossier>] [--in-memory-secrets] [--in-memory-ca] [--log-level <niveau>]`. Sans `--foreground` le socle affiche l'aide et sort code 1 (le mode arrière-plan arrive avec le lot autostart).

Séquence : `data\` → `ConfigStore.Load` → `VaultSession` (ouverture ou création) → `CAManager` → `JsonlEventStore` + purge → `ProxyServer.Start` → log `irisd ready on 127.0.0.1:8888, ca=data\ca.pem` → attente Ctrl+C.

Codes de sortie : 0 arrêt normal, 1 données ou config, 2 coffre, 3 port occupé, 4 argument invalide.

## 8. Sécurité (invariants testés)

1. Aucune valeur de secret dans les logs, les events, les snippets. Test : un dump complet du ring et du journal après un scénario de substitution ne contient pas la valeur.
2. Aucune substitution sans correspondance explicite `hôte ∈ allowed_hosts`. Tests de régression R1 ; toute modification de `PlaceholderEngine` ou `ExfilRuleEngine` ajoute un test.
3. Le mot de passe maître et les valeurs ne transitent jamais par les arguments de ligne de commande ni par l'environnement, sauf le mode `--in-memory-secrets` explicitement marqué debug.
4. Le CA privé ne touche le disque que chiffré dans `iris.kdbx`. Les clés des feuilles ne survivent pas à leur éviction (test : le conteneur CNG n'existe plus après `LeafCertCache.Evict`).
5. Pas de mode qui désactive le scoping ou les règles.
6. Le daemon n'ouvre de connexion sortante que vers l'hôte du `CONNECT` reçu ; aucune télémétrie.
7. Les fichiers de `data\` sont créés avec l'ACL héritée du dossier ; le socle ne restreint pas davantage (le dossier est sous le contrôle de l'utilisateur), mais ne contient rien d'exploitable sans le mot de passe maître.

## 9. Tests

Pas de framework : `tests\Tests.cs` est un programme avec `Main`, une classe `Check` (assertions, compteur, liste des échecs), code de sortie non nul si un test échoue. Compilation par `test.bat` avec `-r:KeePass.exe` et toutes les sources de `src\IrisKit` ; `src\irisd\Program.cs` exclu.

| Domaine | Tests |
|---|---|
| Json | aller-retour objets, ordre des clés, dates, caractères non ASCII, erreurs de parse |
| Config | seed, validation (chaque champ), écriture atomique, rotation des backups, démarrage dégradé |
| Modèles | sérialisation identique aux fixtures JSON d'IRIS (copiées depuis `../Iris/Tests`) |
| Scanner | en-têtes, chemin, query, corps, limite 4 MiB sur octets reçus, non UTF-8, noms invalides ignorés, jeux adverses repris de `PlaceholderFuzzTests` |
| Engine + règles | R1 à R5 un par un et combinés, sévérité max, secrets inconnus, insensibilité à la casse, pause |
| InMemorySecretStore | CRUD, erreurs, cache (TTL, invalidation) |
| KeePassSecretStore | sur une base temporaire dans `%TEMP%` : création, CRUD, relecture après réouverture, mauvais mot de passe, `VaultBusy` avec un `.lock` factice, backup avant écriture |
| CAManager / LeafCertCache | génération, persistance dans le coffre, rechargement, SAN, validité, suppression de la clé CNG |
| HttpParser | têtes, chunked, limites, `Expect` |
| Proxy (intégration en process) | `MockUpstream` (TcpListener + `SslStream` avec un certificat de test) ; client de test faisant `CONNECT` puis TLS en faisant confiance au CA de test : substitution d'en-tête, passthrough hors whitelist, R1 bloqué et relayé intact, streaming chunked relayé sans attendre la fin, corps > 4 MiB relayé, `__iris_ping`, `405`, `502` amont, redaction |

## 10. Dépôt, build, CI

```
irispc\
  CLAUDE.md  LICENSE  README.md
  build.bat  test.bat
  app.manifest                       (PerMonitorV2, asInvoker ; utilisé par IrisApp, posé dès le socle)
  src\IrisKit\{Config,Json,Models,SecretStore,CA,Placeholder,Events,Proxy,Logging}\*.cs
  src\irisd\Program.cs, Daemon.cs, ConsoleInput.cs
  src\AssemblyInfo.cs
  config\irisd.exe.config            (copié à côté de l'exe par build.bat)
  vendor\KeePass-2.61.1\KeePass.exe, KeePass.exe.config, KeePass.XmlSerializers.dll, License.txt, README.md (origine, SHA-256 3952354d…ea864 du zip, date)
  tests\Tests.cs, Check.cs, MockUpstream.cs, TestProxyClient.cs
  docs\superpowers\specs\, docs\superpowers\plans\
  .github\workflows\ci.yml
```

`build.bat` : localise csc (Framework64 puis Framework), compile `irisd.exe` (`-target:exe -optimize+ -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll,vendor\KeePass-2.61.1\KeePass.exe`) avec une **liste explicite** de sources, puis assemble `build\Iris\` (exe, `.exe.config`, les trois fichiers KeePass). Les lots suivants ajoutent `iris.exe` et `IrisApp.exe` au même script. `test.bat` : compile les sources d'IrisKit et de `tests\` vers `tests\Iris.Tests.exe` (sans `src\irisd\Program.cs`, remplacé par le `Main` des tests, comme ImPactHUD) et l'exécute, code de retour propagé.

`ci.yml` : `windows-latest`, `test.bat` puis `build.bat`, artefact `build\Iris`. Pas de lint imposé (pas d'outil sans SDK) ; la revue tient lieu de lint.

Conventions C# : C# 5 strict (pas d'interpolation, `?.`, `nameof`, `out var`, tuples, fonctions locales, membres expression-bodied), 4 espaces, 120 colonnes, un fichier par responsabilité, ~300 lignes max, `// ----` pour sectionner les gros fichiers, exceptions typées, messages utilisateur en français, identifiants et protocole en anglais.

## 11. Découpage en phases du socle

- **Phase 0** : squelette du dépôt, `vendor\`, `build.bat` et `test.bat` qui compilent un `irisd.exe` vide et un test trivial, `ci.yml` vert, CLAUDE.md à jour.
- **Phase 1** : `Json`, `Config`, modèles, `ISecretStore` + `InMemorySecretStore` + `KeePassSecretStore` + `SecretsMetaStore`, `VaultSession`, `CAManager`, events et log. Démontrable : `irisd --foreground` crée le coffre, le CA, `ca.pem`, et attend (sans proxy).
- **Phase 2** : `HttpParser`, `ProxyServer`, tunnel, MITM, `LeafCertCache`, scanner, engine, règles, intégration. Démontrable : le scénario `curl` du §1.

Chaque phase a sa branche `feat/phase-<N>-<slug>`, ses tests, et une PR avec checklist de smoke testing.
