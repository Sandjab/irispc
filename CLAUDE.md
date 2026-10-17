# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Ce qu'est ce projet

**irispc** est le portage Windows d'**IRIS** (Interception · Resolution · Injection · Substitution), le broker de credentials local pour macOS développé dans `../Iris` (GitHub `Sandjab/Iris`, Swift). IRIS expose un proxy HTTPS MITM local qui substitue à la volée des placeholders `{{kc:NAME}}` par les vraies valeurs d'un coffre, puis forwarde la requête : l'outil hôte (Claude Code, `gh`, `curl`, serveurs MCP) ne voit jamais les secrets.

Le portage obéit à quatre contraintes fixées par le propriétaire du dépôt :

1. **Cible C# / .NET Framework natif de Windows, compilé avec `csc.exe`** — sans Visual Studio, sans SDK, sans NuGet, sans `dotnet`. Même méthode que `../CLAUDE/tools/ImPactHUD` (voir « Build »).
2. **Le trousseau macOS (Keychain) est remplacé par KeePass en version portable** (base `.kdbx`).
3. **Le look & feel est celui du thème « Instrument » d'ImPactHUD** (voir « Thème Instrument »).
4. **Tout le reste se comporte à l'identique d'IRIS macOS**, et le projet a sa page GitHub Pages dédiée : `https://sandjab.github.io/irispc`.

Les décisions de portage (coffre, données, IPC, processus, events, build) sont fixées dans `docs/superpowers/specs/2026-10-17-socle-design.md`, qui prime sur ce fichier en cas de doute. Les specs des lots suivants s'ajoutent dans le même dossier.

## Sources de vérité — à lire avant de coder

| Fichier | Rôle |
|---|---|
| `../Iris/SPECS.md` | Spec technique complète d'IRIS : threat model, data model, format `config.json`, syntaxe des placeholders, scoping `allowed_hosts`, règles d'exfiltration R1–R5, flux de requête, MITM TLS, IPC admin (JSON-RPC) et flux d'events (SSE), app menu bar, CLI, `mcp wrap`. **C'est le comportement à reproduire.** |
| `../Iris/CLAUDE.md` | Règles de sécurité non négociables (§6) et posture de travail d'IRIS. Les règles de sécurité s'appliquent telles quelles ici, transposées à Windows. |
| `../Iris/README.md`, `../Iris/docs/user-guide.md`, `../Iris/docs/manual/manuel.html` | Vue utilisateur ; le manuel HTML est ce que publie GitHub Pages côté Mac. |
| `../Iris/Sources/` | Implémentation Swift de référence : `IrisKit/` (cœur), `irisd/` (daemon), `iris/` (CLI), `IrisAppCore/` (modèle de l'app, testable sans UI), `../Iris/IrisApp/` (SwiftUI). Porter la logique, pas la syntaxe. |
| `../Iris/Tests/` | Les tests Swift décrivent les invariants attendus (substitution, scoping, redaction, fuzzing du scanner de placeholders). Les reporter en C#. |
| `../CLAUDE/tools/ImPactHUD/` | Modèle de build (`build.bat`, `test.bat`, `render.bat`, `app.manifest`), thème Instrument (`src/Theme.cs`, `src/SkinInstrument.cs`, `src/ThemedControls.cs`, `docs/specs/2026-10-17-themes-design.md` §5.1), chiffrement DPAPI (`src/AppConfig.cs`). |

Si une décision n'est pas tranchée dans `SPECS.md` ni dans ce fichier : **ne pas spéculer, demander**. Si le code Swift et la spec divergent, la spec prime, et on le signale.

## Build, tests, rendu

Pattern ImPactHUD, à reproduire : un `.bat` par cible, liste explicite des sources (pas de glob), compilateur natif.

```bat
rem csc.exe natif (.NET Framework 4.x), présent sur tout Windows 10/11
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe  (repli : Framework\v4.0.30319)

build.bat    compile les exécutables (/target:winexe pour l'app tray, /target:exe pour le daemon et la CLI)
test.bat     compile src\ + tests\Tests.cs en un exe de tests et l'exécute ; code de retour non nul si échec
render.bat   rend chaque vue de l'UI en PNG dans tests\out, sans réseau ni daemon (captures pour le manuel)
```

- Flags csc de référence : `-nologo -codepage:65001 -optimize+ -win32icon:app.ico -win32manifest:app.manifest -r:System.dll,System.Core.dll,System.Web.Extensions.dll,System.Security.dll` (plus `System.Windows.Forms.dll,System.Drawing.dll` pour l'app). `-codepage:65001` est obligatoire : les sources sont en UTF-8 sans BOM et contiennent des accents. Depuis Git Bash, utiliser la forme `-flag` (`/flag` est réécrit en chemin) et des chemins de sources à antislash entre apostrophes (`'src\IrisKit\X.cs'`, sinon csc perd le répertoire) ; les `.bat` s'appellent par chemin absolu : `cmd //c 'D:\Dev\irispc\test.bat'`. Jamais de package NuGet.
- KeePass : l'espace de noms `KeePassLib` est compilé dans `KeePass.exe` (pas de DLL séparée dans le zip portable) ; on le référence avec `-r:vendor\KeePass-2.61.1\KeePass.exe`, comme un plugin KeePass. Les trois fichiers d'exécution de KeePass (`KeePass.exe`, `KeePass.exe.config`, `KeePass.XmlSerializers.dll`), plus `License.txt`, sont commités dans `vendor\` (empreintes dans son README) et copiés dans le dossier portable.
- `app.manifest` : DPI `PerMonitorV2`, `asInvoker` (pas d'élévation). L'installation du CA dans le magasin `CurrentUser\Root` ne demande pas d'élévation ; si une opération l'exige, elle est isolée et explicite, jamais l'app entière.
- Pas de framework de test : `tests\Tests.cs` est un programme avec son propre `Main` qui remplace `Program.cs`, assertions maison, un compteur de vérifications. Les tests réseau utilisent un upstream HTTP mock local (cf. `../Iris/Tests/IntegrationTests/MockUpstream.swift`). Les tests du coffre créent une base temporaire dans `%TEMP%`, jamais une base utilisateur.
- Les tests d'intégration du proxy tournent en process : `tests\MockUpstream.cs` (TLS avec son propre CA) et `tests\TestProxyClient.cs` (`CONNECT` puis TLS en confiance au CA du proxy) ; tout sur `127.0.0.1` port 0, jamais de réseau externe.
- Dossier portable `build\Iris\` : les exécutables, leurs `.exe.config` (modèles dans `config\`), les fichiers KeePass, et `data\` (config, coffre, CA, events, backups) résolu par chaque exe depuis son propre emplacement. Pas de repli vers AppData.
- Versionner : `AssemblyInfo.cs`, `app.manifest`, et la constante de version applicative, ensemble.

## Architecture cible

Même découpage qu'IRIS, trois exécutables et une bibliothèque partagée, le tout compilé depuis `src/` par csc :

```
src/
  IrisKit/        cœur, sans UI — port de ../Iris/Sources/IrisKit
    Config/       config.json : seed, validation, écriture atomique, backups
    Models/       Secret, MITMRule, Event, Alert
    SecretStore/  ISecretStore + KeePassSecretStore (prod) + InMemorySecretStore (tests)
    CA/           génération CA + certificats feuilles par hôte, cache, magasin Windows
    Proxy/        listener 127.0.0.1:8888, CONNECT passthrough / MITM selon whitelist, relais streaming
    Placeholder/  scanner + moteur de substitution + ExfilRuleEngine (R1–R5)
    IPC/          JSON-RPC admin (named pipe) + flux d'events SSE 127.0.0.1:8899
    MCPConfig/    `mcp wrap` : patch JSON/JSONC en préservant l'ordre des clés, backup, watch
  irisd/          daemon : point d'entrée, boucle de vie, rechargement de config
  iris/           CLI : mêmes sous-commandes et codes de sortie qu'IRIS (SPECS §4.3, §16)
  IrisApp/        app de la zone de notification (WinForms, GDI+ owner-drawn), client léger du daemon
vendor/KeePass-2.61.1/  KeePass.exe, .config, XmlSerializers.dll, License.txt, README (SHA-256 épinglé)
tests/            Tests.cs (unitaires + intégration), MockUpstream.cs, Render.cs (captures)
docs/manual/      manuel utilisateur HTML publié sur GitHub Pages
docs/superpowers/ specs/ et plans/ par lot
.github/workflows/ ci.yml (windows-latest : test.bat puis build.bat), pages.yml (manuel)
```

Invariants d'architecture repris d'IRIS :
- **Le daemon est la seule source de vérité et le seul écrivain** de `config.json` et du coffre. CLI et app passent toujours par le RPC admin ; l'UI se met à jour après l'ack RPC.
- `IrisKit` ne dépend d'aucune UI. `IrisApp` ne contient que la présentation ; la logique d'état (équivalent de `IrisAppCore/AppModel`) est testable sans fenêtre.
- Accès au coffre derrière une interface (`ISecretStore`) avec un mock mémoire : **aucun test n'ouvre une vraie base KeePass**.

## Correspondances macOS → Windows

| IRIS macOS | irispc |
|---|---|
| Keychain (login) pour les secrets, attributs `kSecAttrGeneric` JSON (`allowed_hosts`, `created_at`) | Base KeePass `data\iris.kdbx` créée par iris, groupe `secrets` : une entrée par secret, `allowed_hosts` et `created_at` en champs personnalisés ; `last_used_at`, `usage_count`, `quarantined` dans `data\secrets-meta.json` (pas de réécriture du kdbx sur le chemin chaud) |
| ACL Keychain : accès silencieux réservé au binaire signé | Mot de passe maître saisi **une fois par session** (console en avant-plan, app via le pipe ensuite), conservé en mémoire du daemon ; aucun déverrouillage silencieux |
| Clé privée du CA en Keychain système + ACL liée au binaire signé | Entrée `root` du groupe `ca` de la base KeePass (PKCS#8 base64, champ protégé) ; **jamais en clair sur disque** |
| CA installé dans le trust store système | Magasin de certificats Windows `CurrentUser\Root` (`X509Store`) |
| Socket Unix `0600` pour l'IPC admin | Named pipe `\\.\pipe\iris-admin` avec ACL restreinte à l'utilisateur courant |
| SSE events sur `127.0.0.1:8899` | Identique (`HttpListener` ou socket brut) |
| LaunchAgent via `SMAppService` | Lancement avec Windows (`HKCU\...\Run`) ou tâche planifiée, au choix de l'utilisateur dans les réglages |
| Menu bar `NSStatusItem` + popover SwiftUI | Icône de la zone de notification + fenêtre WinForms ; mêmes états d'icône (idle / actif / pause / alertes / daemon arrêté) et mêmes onglets (Overview, Logs, Security, Secrets, Rules, Settings) |
| `UNUserNotificationCenter` | Notifications de la zone de notification (`NotifyIcon.ShowBalloonTip` ou toasts) |
| `~/Library/Application Support/iris/` | `data\` à côté des exécutables (dossier portable) |
| Events persistés en SQLite | Fichiers JSONL journaliers `data\events\events-AAAA-MM-JJ.jsonl`, purge selon `event_retention_days` |
| `~/.claude.json`, `<projet>/.mcp.json`, config Claude Desktop | `%USERPROFILE%\.claude.json`, `<projet>\.mcp.json`, `%APPDATA%\Claude\claude_desktop_config.json` |
| `.pkg` signé et notarisé | Zip portable publié en Release GitHub + `SHA256SUMS.txt`, exécutables non signés (procédure SmartScreen documentée, comme ImPactHUD) |
| FSEvents (`mcp wrap --watch`) | `FileSystemWatcher` avec le même debounce de 500 ms |

Ce qui ne change pas : ports par défaut, format et sémantique de `config.json` (SPECS §6, à la seule exception de `broker.admin_socket` renommé `broker.admin_pipe`), syntaxe `{{kc:NAME}}` et regex de nom `^[a-zA-Z0-9_-]{1,64}$`, scoping `allowed_hosts`, règles R1–R5 et leurs sévérités, politiques `on_exfil_attempt`, protocole JSON-RPC et liste des méthodes, format des events, sous-commandes et codes de sortie de la CLI, règles de patch de `mcp wrap`, idempotence, redaction des secrets dans logs/events/UI.

## KeePass portable comme coffre

- Le coffre est une base `.kdbx` dédiée, créée par iris, ouverte via `KeePassLib` compilé dans `KeePass.exe` 2.61.1 (référencé au build, redistribué à côté des exécutables). Vérifié par spike le 2026-10-17 : création, écriture, relecture, rejet d'un mauvais mot de passe, avec csc C# 5 et .NET 4.8.
- Déverrouillage par mot de passe maître une fois par session Windows, conservé en mémoire du daemon. Pas de DPAPI, pas de fichier clé : tout processus de l'utilisateur (l'agent compris) pourrait les lire, ce qui annulerait la frontière de confiance.
- Le daemon ouvre la base en lecture ; les écritures (`secret add/rotate/rm`) passent par le daemon comme sur macOS, précédées d'une copie dans `data\backups\`. Si `iris.kdbx.lock` existe (KeePass.exe a la base ouverte), toute écriture est refusée avec un message clair.
- Les `.exe.config` reprennent de `KeePass.exe.config` la `bindingRedirect` de l'assembly KeePass et `enforceFIPSPolicy=false`.
- Mêmes garanties qu'IRIS : un `config.json` volé ne révèle rien, les valeurs de secrets ne transitent jamais par les logs, l'UI ou le flux SSE, et un test vérifie qu'un dump d'event ne contient jamais une valeur brute.

## Thème Instrument (look & feel)

Reprendre tel quel le thème « Instrument » d'ImPactHUD (`docs/specs/2026-10-17-themes-design.md` §5.1 et `src/Theme.cs` → `ThemeCatalog.Instrument()`), un seul thème, pas de catalogue :

| Rôle | Valeur RGB |
|---|---|
| Bg | 34, 29, 24 |
| Surface (en-tête, panneaux) | 28, 23, 19 |
| Line / Track / Field | 55, 50, 44 / 57, 53, 48 / 45, 40, 34 |
| Fg / Fg2 / Muted | 241, 238, 233 / 199, 195, 189 / 157, 151, 144 |
| Accent | = Fg2 (pas de teinte d'accent, liens en Fg2 semi-gras) |
| Neutral / Good / Watch / Bad | Muted / 124, 197, 140 / 230, 181, 93 / 237, 118, 101 |
| Polices | Texte Segoe UI ; chiffres Bahnschrift SemiBold → Bahnschrift gras → Segoe UI Semibold ; mono Cascadia Mono → Consolas |
| Géométrie | rayon 10, en-tête 26 px, ligne mini 34 px (à 96 dpi) |

Principes : cadran calme sur graphite chaud, **seule la couleur d'état est colorée** (une couleur par sévérité, jamais deux), icônes d'en-tête en Line au repos, Muted quand la souris est sur la fenêtre, Fg au survol du bouton ; icônes vectorielles Segoe Fluent Icons avec repli Segoe MDL2 Assets. Contrôles owner-drawn GDI+ à la manière de `Controls.cs` / `ThemedControls.cs` (reprendre `DialGauge`, `StateMark`, `KvGrid`, `IconButton`), reconstruction de l'UI sur `WM_DPICHANGED`. Les états d'icône du tray et les sévérités des alertes (SPECS §5.4, §15.1) se mappent sur Neutral / Good / Watch / Bad.

## GitHub Pages

- Site : `https://sandjab.github.io/irispc`, source = manuel utilisateur `docs/manual/manuel.html`, à écrire en partant de `../Iris/docs/manual/manuel.html` (même structure et ancres : `#install`, `#config-json`, `#cli-overview`, `#threat`, `#provider-compat`, `#packaging`) avec le contenu Windows.
- Reprendre `../Iris/.github/workflows/pages.yml` et `../Iris/.github/scripts/build-pages.py` : assemblage dans `_site/` (manuel → `index.html`, images aplaties dans `assets/` et `screenshots/`), déploiement `actions/deploy-pages`. Les captures viennent de `render.bat`.
- Pages doit être activé sur le dépôt avec la source « GitHub Actions » (`build_type: workflow`, comme sur `Sandjab/Iris`) ; ce n'est pas encore fait.

## Conventions

- C# compatible avec le compilateur csc de `v4.0.30319` : **C# 5 au maximum** (pas d'interpolation `$""`, pas de `?.`, pas de `nameof`, pas de `out var`, pas de tuples, pas de fonctions locales, pas de membres expression-bodied). ImPactHUD s'en tient à cette règle ; vérifier qu'une construction compile avant de la généraliser.
- Pas d'I/O bloquante dans le proxy : tout en asynchrone (`async`/`await` existe en C# 5). Pas de `Thread.Sleep` comme synchronisation.
- Erreurs : exceptions typées, messages utilisateur en français. Logs avec niveaux explicites, **jamais de valeur de secret**, redaction par nom du secret.
- Textes UI et documentation en **français** ; identifiants de code, noms de commandes CLI, clés JSON et messages de protocole en anglais, identiques à IRIS.
- Un fichier par responsabilité ; au-delà d'environ 300 lignes, scinder.
- Niveaux de log : valeurs IRIS `trace|debug|info|warn|error` partout (`config.json`, `--log-level`, `Log`).
- Pas de télémétrie, pas de phone-home : le daemon ne contacte que les hôtes de la whitelist MITM.

## Workflow git (hérité d'IRIS)

- Une phase = une branche `feat/phase-<N>-<slug>` ; hors phasage `feat/`, `fix/`, `chore/`, `docs/`. Pas de push direct sur `main`.
- Commits conventionnels (`feat:`, `fix:`, `chore:`, `docs:`, `test:`, `refactor:`), un changement cohérent par commit.
- PR vers `main` avec une **checklist de smoke testing** (`- [ ]`) couvrant les critères de la phase ; `test.bat` et `build.bat` passent avant ouverture. Merge en squash, après confirmation explicite de l'utilisateur.

## Phasage

Les phases 0 à 2 forment le **socle**, spécifié dans `docs/superpowers/specs/2026-10-17-socle-design.md`. Les lots suivants reçoivent chacun leur spec.

1. **Phase 0** — squelette du dépôt, `vendor\KeePass`, `build.bat` / `test.bat`, `ci.yml` vert.
2. **Phase 1** — `IrisKit` : `Json`, `Config`, modèles, `ISecretStore` + `KeePassSecretStore`, coffre, CA dans le coffre, events et log ; `irisd --foreground` crée le coffre, le CA et `ca.pem` puis attend.
3. **Phase 2** — proxy MITM : `HttpParser`, tunnel, `LeafCertCache`, scanner, `ExfilRuleEngine` R1–R5, `RequestProcessor`, `MITMHandler` (keep-alive, streaming), `irisd --foreground` écoute sur `127.0.0.1:8888` ; démontrable avec le scénario `curl` de la spec §1.
4. **Phase 3** — IPC : named pipe JSON-RPC + SSE events.
5. **Phase 4** — scoping `allowed_hosts` + règles R1–R5.
6. **Phase 5** — CLI `iris` (dont `mcp wrap`, `doctor`).
7. **Phase 6** — app tray, thème Instrument (lecture seule, puis CRUD).
8. **Phase 7** — lancement avec Windows, installation CA, zip de release, manuel + Pages.
9. **Phase 8** — hardening (fuzzing du scanner, tests d'intégration).

Chaque phase est démontrable (build, run, test) avant la suivante.

## Décisions tranchées le 2026-10-17 (détail dans la spec socle)

- Coffre : mot de passe maître une fois par session, en mémoire du daemon. Base dédiée créée par iris.
- Données : `data\` à côté des exécutables, pas de repli AppData.
- Trois exécutables : `irisd.exe`, `iris.exe`, `IrisApp.exe`.
- IPC admin : named pipe `\\.\pipe\iris-admin`.
- Events : JSONL journaliers. Métadonnées d'usage : `secrets-meta.json`.
- HTTP/2 : `SslStream` du .NET Framework n'émet pas d'ALPN, les deux côtés retombent sur HTTP/1.1 comme IRIS.
- KeePass livré dans le zip (`vendor\`), référencé comme assembly `KeePass.exe`.

Toute nouvelle question de conception se pose avant d'implémenter et se consigne dans la spec du lot concerné.
