# irispc — Spec phase 5 : CLI `iris`

Date : 2026-10-18. Statut : approuvée en brainstorming (cinq sections), en attente de relecture du document.

Sources de vérité : `../Iris/SPECS.md` §4.3, §16, §16.1, Annexe A.11 ; implémentation de référence `../Iris/Sources/iris/` et `../Iris/Sources/IrisKit/MCPConfig/` ; spec socle `2026-10-17-socle-design.md` ; spec phase 3 `2026-10-18-phase-3-ipc-design.md` (protocole, méthodes, codes d'erreur). Ce document ne redit pas ce qu'elles fixent ; il consigne le périmètre de la phase 5 et les décisions propres au portage. Quand il est muet, SPECS.md s'applique, puis le code Swift. Quand le code Swift et SPECS.md divergent, SPECS.md prime et l'écart est listé au §2.

## 1. Périmètre

La phase 5 livre `iris.exe`, client du pipe admin, qui ne lit ni n'écrit jamais lui-même `config.json` ni le coffre (le daemon reste seul écrivain) :

1. les sous-commandes du code Swift, hors `ca install|uninstall`, `shell *` et `plugin *` : `secret` (add, list, show, edit, rotate, rm, quarantine, unquarantine), `rule` (add, list, rm), `status`, `pause`, `resume`, `config` (get, set, reload), `logs` (one-shot et `--follow`), `ca` (export, fingerprint, is-trusted), `doctor`, `mcp` (wrap, unwrap) ;
2. les sous-commandes propres à irispc `vault status|unlock|create` (le 503 du proxy renvoie déjà vers « l'app ou la CLI iris ») ;
3. dans IrisKit : le document JSON ordonné et tolérant au JSONC, le patcheur MCP, le registre des fichiers enrobés, l'observateur de fichier, les contrôles de `doctor`, réutilisables par l'app (phase 6) ;
4. la vérification d'identité du serveur du pipe par **identité de fichier** (mineur de la revue phase 3) ;
5. la saisie de mot de passe sans écho déplacée d'irisd vers IrisKit, partagée par les deux exécutables.

Hors périmètre : `ca install|uninstall` et l'équivalent Windows de `shell install|uninstall|status` (phase 7, avec l'installation du CA et le lancement avec Windows) ; `plugin *` (lot plugins, à décider) ; `admin.uninstall` (phase 7). Les mineurs différés des phases 2 et 3 restent différés, sauf l'identité du pipe.

## 2. Décisions et écarts

| Sujet | IRIS (SPECS / Swift) | irispc | Pourquoi |
|---|---|---|---|
| Analyse des arguments | swift-argument-parser | analyseur maison strict | Pas de NuGet. |
| Option de transport | `--socket-path` | `--pipe-name NOM` | Named pipe. |
| Nom du pipe par défaut | constante par défaut | `broker.admin_pipe` du `data\config.json` voisin de `iris.exe`, repli `iris-admin` | Un nom de pipe changé dans la config serait sinon ignoré. |
| Message « daemon injoignable » | `launchctl kickstart …` | `irisd ne tourne pas. Lancez : "<dossier>\irisd.exe" --foreground` | Pas de LaunchAgent avant la phase 7. |
| Langue des sorties lisibles | anglais | français ; JSON, noms de contrôles, `kind`, états en anglais identiques à IRIS | CLAUDE.md : textes UI en français, protocole en anglais. |
| Mot de passe maître | n/a (Keychain) | `vault unlock|create` à la console seulement, sans écho ; stdin redirigé → code 64 | Le mot de passe n'apparaît jamais dans un script, un fichier ou un historique. |
| Valeur de secret sur stdin | retire au plus un `\n` final | retire au plus un `\r\n` ou un `\n` final | Un pipe PowerShell ajoute `\r\n`. |
| `mcp wrap`, variables de proxy | Swift : `HTTPS_PROXY` et `HTTP_PROXY` traitées en bloc (l'une présente → aucune ajoutée) | SPECS §16.1 : chaque clé absente est ajoutée, jamais d'écrasement | **Divergence Swift / SPECS, SPECS prime.** Coût si faux : un `HTTP_PROXY` vers iris à côté d'un `HTTPS_PROXY` utilisateur, sans effet sur le trafic HTTPS. |
| `mcp wrap --json` | SPECS : `skipped` ; Swift : `skipped_http_sse` | `{patched, already_compliant, skipped, errors}` | **Divergence Swift / SPECS, SPECS prime.** |
| `mcp wrap --dry-run` | SPECS : « diff lisible » ; Swift : les deux documents entiers | diff sémantique, une ligne par clé ajoutée | Un `.claude.json` fait plusieurs Mo. Conforme à SPECS. |
| Écriture concurrente du fichier MCP | écrasement | SHA-256 relu juste avant le remplacement ; changé → abandon (code 1), ou cycle suivant en `--watch` | Claude Code réécrit souvent `.claude.json`. |
| BOM et fins de ligne | non traités | détectés à la lecture, conservés à l'écriture | Sinon un fichier CRLF n'est jamais « déjà conforme » pour un éditeur. |
| `doctor`, confiance du CA | `ca.is_trusted` (coffre requis) | empreinte calculée localement depuis `ca.pem`, cherchée dans `CurrentUser\Root` puis `LocalMachine\Root` | Répond coffre verrouillé ; voit une installation machine. |
| `doctor`, nouveaux contrôles | — | `vault-unlocked` ; valeur divergente des variables d'environnement → `warn` | Coffre fermé = MITM inactif ; mauvaise valeur = cause fréquente d'échec. |
| Identité du serveur du pipe | n/a (socket 0600) | identité de fichier (volume + index) au lieu du chemin | Faux refus via `subst`, jonction, nom 8.3. |

## 3. Squelette de la CLI

Fichiers de `src\iris\` : `Program.cs` (point d'entrée : construit le contexte réel), `CliArguments.cs` (analyseur), `CliContext.cs`, `Cli.cs` (table des commandes, dispatch, correspondance erreurs → codes), puis un fichier par groupe : `SecretCommands.cs`, `RuleCommands.cs`, `DaemonCommands.cs` (status, pause, resume), `ConfigCommands.cs`, `LogsCommand.cs`, `CaCommands.cs`, `VaultCommands.cs`, `DoctorCommand.cs`, `McpCommands.cs`, `TextFormatter.cs` (tableaux, durées, dates relatives).

**Analyseur.** Options longues exactes et sensibles à la casse, `--nom valeur` ou drapeau `--nom`, positionnels ; pas de forme courte sauf `-h`. Option inconnue, répétée ou sans valeur, positionnel manquant ou en trop, sous-commande inconnue, combinaison interdite → code 64, message sur stderr suivi de `voir : iris <commande> --help`. `--help` (ou `-h`) à chaque niveau et `iris --version` → aide ou version sur stdout, code 0. `iris` seul → aide générale, code 0 (comportement de swift-argument-parser).

**Options globales** (toute commande qui parle au daemon) : `--pipe-name NOM`, `--config-path CHEMIN` (lit `broker.admin_pipe` dans ce fichier ; illisible ou invalide → code 1). Priorité : `--pipe-name` > `--config-path` > `data\config.json` voisin > `iris-admin`. Le serveur attendu est `irisd.exe` du dossier de `iris.exe` (§8). Délai de connexion : 2 s.

**Codes de sortie** (IRIS) :

| Code | Cas |
|---|---|
| 0 | succès, no-op compris |
| 1 | erreur logique : erreur RPC, fichier introuvable ou illisible, `doctor` en échec, `ca is-trusted` faux, CA absent |
| 2 | daemon injoignable (pipe absent, délai dépassé) ou serveur d'identité inattendue |
| 3 | E/S locale : backup, copie, écriture, flux SSE interrompu |
| 64 | usage ; `rule rm` d'un hôte par défaut ou absent ; confirmation de `secret rm` erronée ; `vault unlock|create` sans console |

**Daemon injoignable** : stderr `irisd ne tourne pas. Lancez : "<dossier>\irisd.exe" --foreground` puis `  pipe : \\.\pipe\<nom>`, code 2. **Identité refusée** : message de `AdminServerIdentityException`, code 2, rien n'a été envoyé.

**Erreurs RPC** : stderr `erreur : <message du daemon>`, code 1, avec ces messages dédiés : -32020 `coffre verrouillé : lancez iris vault unlock` ; -32021 `mot de passe refusé` ; -32023 `trop d'essais : réessayez dans N s` (`data.retry_after_s`) ; -32024 `un coffre existe déjà`. Le pipe fermé en cours d'appel → code 2.

**Sorties.** `--json` émet le JSON d'IRIS (mêmes clés snake_case, dates ISO-8601 UTC) via `JsonWriter`, indenté ; ndjson compact pour `logs --follow --json`. Acquittements sans charge utile en `--json` : `{"ok": true, "message": "…"}`. Textes lisibles en français. stdout redirigé : UTF-8 sans BOM ; console : encodage de la console.

**Ctrl+C** (`logs --follow`, `mcp wrap --watch`) : `Console.CancelKeyPress` annule le `CancellationToken` du contexte (`e.Cancel = true`), sortie propre, code 0.

**Testabilité.** `Cli.Run(string[] args, CliContext ctx)` rend le code de sortie et ne touche ni `Console` ni `Environment.Exit`. `CliContext` porte : `Out`, `Err` (`TextWriter`), `In` (`Stream`), `IsStdinRedirected`, `Passwords` (`IPasswordReader`), `PipeName` par défaut, `ExpectedServerPath`, `DataDir`, `Environment` (dictionnaire, pour `doctor`), `UserProfile`, `Cancel` (`CancellationToken`), `Now` (horloge).

## 4. Commandes qui parlent au daemon

Toutes acceptent `--json` et les options globales, ouvrent **une** connexion et y enchaînent leurs appels.

| Commande | RPC | Comportement |
|---|---|---|
| `secret add NAME [--allowed-hosts a,b] (--value-from-stdin \| --value V)` | `secret.add` | Aucune source ou les deux → 64. `--value` : avertissement sur stderr (historique du shell). Sortie `secret ajouté : NAME (hôtes : a,b)`. |
| `secret list` | `secret.list` | Tableau `NOM ÉTAT CRÉÉ DERNIER_USAGE USAGES HÔTES` (`actif` / `QUARANTAINE`, durées relatives) ; vide → `aucun secret`. |
| `secret show NAME` | `secret.get` | Nom, hôtes, création, usages, quarantaine ; jamais la valeur. |
| `secret edit NAME --allowed-hosts a,b` | `secret.update` | Remplace la liste. |
| `secret rotate NAME` | `secret.rotate` | Console : saisie sans écho `Nouvelle valeur pour NAME : `. Stdin redirigé : lecture de stdin. |
| `secret rm NAME [--yes]` | `secret.delete` | Sans `--yes` : `Tapez le nom du secret pour confirmer : ` puis une ligne de stdin ; différente → 64. |
| `secret quarantine NAME` / `unquarantine NAME` | `secret.set_quarantined` | — |
| `rule add HOST` | `rule.add` | Idempotent ; affiche la règle. |
| `rule list` | `rule.list` | Tableau `HÔTE ORIGINE CRÉÉ`. |
| `rule rm HOST` | `rule.delete` | -32010 ou -32011 → message, code 64. |
| `status` | `daemon.status` | pid, uptime, version, compteurs, pause, état du coffre. |
| `pause` / `resume` | `daemon.pause` / `daemon.resume` | Idempotents ; affiche `en pause` ou `actif`. |
| `config get` | `config.get` | Rendu lisible par sections (`broker`, `security`, `backups`, `hosts`). |
| `config set KEY VALUE` | `config.set` | Affiche `appliqué : …` et `redémarrage requis : …`. |
| `config reload` | `config.reload` | Clés `ignored` : avertissement sur stderr. |
| `ca export [--path P \| --print]` | `ca.export_path` | Sans option : chemin. `--path` : copie (échec → 3). `--print` : PEM. Chemin vide → `CA absent`, code 1. `--path` et `--print` ensemble → 64. |
| `ca fingerprint` | `ca.fingerprint` | `sha256 : …`. |
| `ca is-trusted` | `ca.is_trusted` | `approuvé` / `non approuvé` ; non approuvé → code 1. |
| `vault status` | `vault.status` | `absent`, `locked` ou `unlocked`, chemin de la base. |
| `vault unlock` | `vault.status`, `vault.unlock` | Console exigée (§5). `unlocked` → `déjà déverrouillé`, 0, sans demander. `absent` → `aucun coffre : iris vault create`, 1. |
| `vault create` | `vault.status`, `vault.create` | Console exigée. Coffre présent → 1. Deux saisies ; différentes ou vides → 1. |
| `logs [--since T] [--until T] [--limit N] [--kind k1,k2] [--host H]` | `events.query` | Une ligne par event : `<date ISO> <kind> <hôte> <méthode> <chemin> sub=<noms> dur=<ms>` ; vide → `aucun event`. `kind` inconnu → 64. |
| `logs --follow [--kind k1,k2] [--host H]` | `config.get`, puis SSE | Abonnement à `events_listen` avec les filtres ; ndjson en `--json`. Avec `--since`, `--until` ou `--limit` → 64. Flux coupé → stderr, code 3 ; Ctrl+C → 0. |

## 5. Valeurs de secrets, mot de passe, temps

**Valeurs de secrets.** Lues en octets ; au plus un `\r\n` ou un `\n` final retiré ; valeur vide ou faite seulement d'espaces → `la valeur ne peut pas être vide`, code 1. Encodées en base64 dans la requête ; le tableau d'octets est effacé après l'envoi. Jamais affichées, jamais dans un message d'erreur. La phase 7 documente que PowerShell 5.1 réencode ce qu'il pipe vers un exe (`cmd /c "iris … < fichier"` conseillé).

**Mot de passe maître.** `src\irisd\IConsoleInput.cs` passe dans IrisKit (`ConsolePassword.cs` : interface `IPasswordReader`, implémentation console à base de `Console.ReadKey(true)` qui remplit directement une `SecureString`). irisd et iris l'utilisent. `vault unlock|create` vérifient `IsStdinRedirected` **avant** toute connexion : redirigé → `vault unlock|create exige une console`, code 64. Pas de nouvel essai dans la CLI : un refus donne le code 1 et le délai anti-force brute du daemon s'applique. La `SecureString` est convertie en `string` le plus tard possible pour la trame (limite du runtime déjà acceptée en phase 3), puis libérée.

**Temps relatifs** (`--since`, `--until`) : `<entier><s|m|h|d>` soustrait de `Now`, ou date ISO-8601 ; autre forme → 64. Convertis en dates UTC avant l'appel.

## 6. `mcp wrap` et `mcp unwrap`

### 6.1 IrisKit (`src\IrisKit\MCPConfig\`)

- `OrderedJson.cs` : valeur ordonnée (objet = liste de paires clé/valeur, tableau, chaîne, entier 64 bits, double, booléen, null) ; `OrderedJsonParser.cs` : RFC 8259 strict, ou mode JSONC (`//`, `/* */`, virgules finales) qui relève les positions des commentaires (ligne, colonne, type) ; clés en double refusées ; erreurs typées avec position. `OrderedJsonWriter.cs` : indentation de 2 espaces, `": "`, saut de ligne final, mêmes échappements que `OrderedJSONDocument.serialize`. Port d'`OrderedJSONDocument.swift`.
- `McpPatcher.cs` : fonction pure (document, `broker.listen`, chemin du CA) → (document patché, résumé `{patched, already_compliant, skipped}`). Localisation de `mcpServers` : à la racine, sinon dans le premier objet de premier niveau qui le contient. Pour chaque serveur objet : `type` `http` ou `sse` sans bloc `env` → `skipped` ; sinon les six clés de SPECS §16.1 absentes sont ajoutées en ordre alphabétique à la fin de `env` (créé si absent), les valeurs existantes sont laissées telles quelles ; rien d'ajouté → `already_compliant`. Valeurs : `http://<broker.listen>` pour `HTTPS_PROXY` et `HTTP_PROXY`, chemin Windows absolu de `ca.pem` pour les quatre autres. Rend aussi la liste des ajouts (chemin de clé, valeur) pour `--dry-run`. `Unwrap(path)` : §6.4.
- `WrappedPathsRegistry.cs` : `data\wrapped-paths.json`, tableau JSON de chemins absolus, sans doublon, ordre d'insertion, écriture atomique ; fichier absent → liste vide ; fichier présent mais invalide → exception (jamais traité comme vide).
- `McpFileWatcher.cs` : `FileSystemWatcher` sur le dossier parent, filtré sur le nom du fichier (changements, création, renommage vers ce nom), debounce de 500 ms, arrêt par `CancellationToken`.
- `McpWrapper.cs` : un cycle de wrap (lecture, empreinte, parse, contrôle des commentaires, patch, backup, écriture atomique, registre), partagé par le mode simple et `--watch`, rendant un résultat typé (déjà conforme, patché, refus avec raison).

### 6.2 `iris mcp wrap PATH [--dry-run] [--watch] [--log-level L] [--json]`

1. `~` en tête développé en `%USERPROFILE%` ; chemin rendu absolu. Nom finissant par `.iris.bak` → refus, code 1.
2. `config.get` puis `ca.export_path` (daemon injoignable → 2 ; chemin vide → `CA absent`, 1).
3. Lecture des octets (absent ou illisible → 1). BOM UTF-8 noté et retiré ; décodage UTF-8 strict (invalide → 1) ; CRLF noté si le texte contient `\r\n`. Parse JSONC (invalide → 1, avec la position).
4. Commentaires présents et pas `--dry-run` → `commentaires détectés en L<ligne>:<col> : retirez-les ou utilisez --dry-run`, code 1.
5. Patch. Sérialisation identique avant et après → `déjà conforme : PATH`, code 0, aucune écriture (registre inchangé).
6. `--dry-run` → diff sémantique (`+ mcpServers.<serveur>.env.<CLÉ> = "<valeur>"`, puis `ignoré (http/sse sans env) : <serveur>`), code 0, rien n'est écrit.
7. Écriture : copie des octets d'origine vers `PATH.iris.bak` (écrase le précédent ; échec → 3) ; résultat revalidé en JSON strict (échec → 1) ; BOM et CRLF restitués ; SHA-256 du fichier relu et comparé à celui de l'étape 3 (différent → `fichier modifié pendant le patch : relancez`, code 1, rien n'est remplacé) ; écriture dans un temporaire du même dossier puis `File.Replace` (ou `File.Move` si la cible a disparu ; échec → 3) ; ajout au registre (échec : avertissement, code 0).
8. Sortie : `patché : PATH (backup : PATH.iris.bak)` ; `--json` → `{patched, already_compliant, skipped, errors}` (`errors` = 0).

`--watch` : avec `--dry-run` → 64. Premier cycle comme ci-dessus mais daemon injoignable → 2 ; ensuite, à chaque événement après debounce, un cycle complet (config et chemin du CA relus). Le SHA-256 de ce qu'iris a écrit (ou du fichier déjà conforme) est gardé en mémoire : un événement dont le contenu a cette empreinte est ignoré. Daemon injoignable, fichier illisible ou invalide, commentaires, fichier modifié pendant le patch : avertissement sur stderr, attente de l'événement suivant. Journal sur stderr filtré par `--log-level` (`trace|debug|info|warn|error`, défaut `info`). Ctrl+C → code 0.

### 6.3 Sécurité du wrap

Les fichiers MCP ne reçoivent que l'URL du proxy et le chemin de `ca.pem`, jamais une valeur de secret. Une valeur placeholder `{{kc:NAME}}` existante n'est jamais modifiée (conséquence de la règle 4).

### 6.4 `iris mcp unwrap PATH [--json]`

Sans daemon. `PATH.iris.bak` absent ou illisible → `aucun backup : PATH.iris.bak`, code 1 ; backup non valide en JSONC → code 1, rien n'est touché. Sinon `File.Replace(PATH.iris.bak → PATH)` (le backup est consommé ; `File.Move` si `PATH` a disparu ; échec → 3), retrait du registre. Sortie `restauré : PATH` ; `--json` → `{"ok": true, "restored": PATH}`.

## 7. `doctor`

Logique dans IrisKit (`DoctorChecks.cs`), avec environnement, profil utilisateur et recherche dans les magasins de certificats injectés. Contrôles dans l'ordre, chacun `ok`, `warn` ou `fail` avec un détail :

| # | Nom | Vérification | Sévérité |
|---|---|---|---|
| 1 | `admin-pipe` | connexion au pipe, identité du serveur comprise | échec → `fail`, résultats affichés, **code 2** |
| 2 | `daemon-alive` | `daemon.status`, puis `Process.GetProcessById(pid)` répond | `fail` sinon ; détail `pid=… uptime=…` |
| 3 | `vault-unlocked` | `vault.status` | `locked` → `fail` « MITM inactif : iris vault unlock » ; `absent` → `fail` « iris vault create » |
| 4 | `ca-cert-present` | `ca.export_path` non vide et fichier présent | `fail` sinon |
| 5 | `ca-trusted` | empreinte SHA-1 du certificat de `ca.pem` présente dans `CurrentUser\Root` ou `LocalMachine\Root` (lecture seule) | `fail` sinon, indication : importer `data\ca.pem` dans les autorités de certification racines de confiance de l'utilisateur (`certmgr.msc`) ; non évalué si le contrôle 4 échoue |
| 6 | `shell-env-vars` | `HTTPS_PROXY` et `NODE_EXTRA_CA_CERTS` de l'environnement courant | absentes → `warn` ; valeur différente de `http://<broker.listen>` ou du chemin de `ca.pem` (comparaison insensible à la casse, chemins normalisés) → `warn` |
| 7 | `proxy-ping` | `GET /__iris_ping` en TCP brut sur `broker.listen`, délai 2 s, sans proxy système ni `HTTPS_PROXY` | `200` et `ok\n` → `ok`, sinon `fail` |
| 8 | `claude-apikeyhelper-absent` | `%USERPROFILE%\.claude\settings.json`, parse JSONC, clé racine `apiKeyHelper` | présente → `fail` (SPECS Annexe A.11) ; fichier absent ou sans la clé → `ok` ; illisible → `warn` |

Sortie lisible : `[ok]    nom — détail` (sévérité alignée). `--json` : tableau `[{name, severity, detail}]`. Code : 2 si `admin-pipe` échoue, 1 si un autre contrôle est en `fail`, 0 sinon (`warn` n'échoue pas).

## 8. Identité du serveur du pipe

`PipeNative` gagne `FileIdentity.Of(path)` : `CreateFile` (accès 0, partage lecture/écriture/suppression, `OPEN_EXISTING`, `FILE_FLAG_BACKUP_SEMANTICS`) puis `GetFileInformationByHandle` → (numéro de série du volume, index de fichier 64 bits). `AdminClient.Connect` compare l'identité de l'image du serveur (`GetNamedPipeServerProcessId` → `QueryFullProcessImageName`, inchangés) à celle de `expectedServerPath`. Un fichier impossible à ouvrir de l'un ou l'autre côté → refus (`AdminServerIdentityException`), jamais acceptation. Le chemin reste dans le message d'erreur. Un lien physique vers `irisd.exe` est accepté (même fichier).

## 9. Build

- `build.bat` : nouvelle cible `iris.exe` (`-target:exe`, liste explicite des sources d'IrisKit et de `src\iris\`, mêmes références que irisd, `KeePass.exe` compris puisqu'IrisKit en dépend) ; `config\iris.exe.config` (même `bindingRedirect` et `enforceFIPSPolicy=false` que `irisd.exe.config`) copié dans `build\Iris\`.
- `test.bat` : compile en plus les sources de `src\iris\` sauf `Program.cs`, et les nouveaux fichiers de tests.
- `ci.yml` inchangé.
- `CLAUDE.md` : phase 5 livrée, harnais CLI (`Cli.Run` + `CliContext`), `ca install|uninstall` et `shell` déplacés en phase 7.
- `AssemblyInfo` / version : pas de changement de version applicative dans cette phase.

## 10. Sécurité (invariants testés)

Les invariants des specs socle et phase 3 restent en vigueur. S'y ajoutent :

1. Aucune valeur de secret ni mot de passe maître dans stdout, stderr ou un fichier écrit par la CLI. Test : `secret add` puis `secret show`, `secret list`, `logs`, `logs --json`, `status`, `doctor`, erreurs RPC provoquées ; la valeur brute n'apparaît dans aucune sortie capturée.
2. Le mot de passe maître ne vient que d'une console : aucune option, aucune lecture de stdin.
3. La CLI n'envoie rien à un serveur de pipe dont l'image n'est pas le fichier `irisd.exe` attendu.
4. `mcp wrap` ne remplace jamais un fichier modifié depuis sa lecture, n'écrit jamais un résultat qui ne se relit pas en JSON strict, n'écrase jamais une valeur existante, et écrit le backup avant le fichier.
5. `mcp wrap` n'écrit jamais un fichier qui contient des commentaires.

## 11. Tests

Mêmes règles qu'aux phases 2 et 3 : tout en process, loopback, port 0, pipe `iris-admin-test-<guid>`, `WriteTestConfig`, coffre réel uniquement sur une base temporaire de `%TEMP%`, fichiers MCP et registre dans `%TEMP%`, jamais `%USERPROFILE%`.

| Domaine | Tests |
|---|---|
| `CliArgumentsTests` | options, drapeaux, positionnels, répétition, valeur manquante, inconnu → 64, `--help` à chaque niveau, `--version`, `iris` seul |
| `OrderedJsonTests` | aller-retour, ordre des clés, JSONC (commentaires ligne et bloc, positions, virgules finales), mode strict qui les refuse, clés en double, échappements et `\u`, nombres (entiers 64 bits, doubles, exposants), entrée vide, cas repris de `../Iris/Tests` |
| `McpPatcherTests` | règles 1 à 5 de SPECS §16.1, `mcpServers` racine et imbriqué, absence de `mcpServers`, entrée non objet, idempotence, résumé, liste des ajouts |
| `WrappedPathsRegistryTests` | ajout sans doublon, retrait, fichier absent, fichier corrompu → exception |
| `McpWrapCliTests` | wrap puis wrap (déjà conforme, pas de réécriture), `--dry-run`, commentaires refusés, `.iris.bak` refusé, BOM et CRLF conservés, fichier modifié entre lecture et remplacement → 1 sans remplacement (point d'injection de test), backup avant écriture, `unwrap` (absent, invalide, nominal), `--json`, `--watch` (écriture propre ignorée, re-patch après modification externe, daemon arrêté puis relancé, arrêt par le token) |
| `CliCommandTests` | chaque commande du §4 en lisible et en `--json` contre un daemon réel en process ; codes 0, 1, 2 (pipe absent, identité refusée), 3, 64 ; -32020 → message `vault unlock` ; `vault unlock|create` refusés stdin redirigé ; mot de passe fourni par un `IPasswordReader` de test ; `logs --follow` reçoit un event puis s'arrête sur le token |
| `DoctorTests` | chaque contrôle `ok`/`warn`/`fail` avec environnement, profil et magasins injectés ; code 2 sans daemon |
| `AdminClient` (identité) | accepté via un chemin de jonction (`mklink /J` dans `%TEMP%`), accepté malgré la casse, refusé pour une copie identique ailleurs, refusé si le fichier attendu n'existe pas |
| Redaction | invariant 1 du §10 |

## 12. Démonstration et critères de la phase

Sur un `build\Iris` propre, ports par défaut :

1. `irisd --foreground --locked` ; dans une autre console, `iris status` montre le coffre `locked`.
2. `iris vault unlock` (ou `iris vault create` au premier lancement), saisie sans écho.
3. `cmd /c "echo sk-test| iris secret add demo --allowed-hosts httpbin.org --value-from-stdin"`, puis `iris rule add httpbin.org`, `iris secret list`.
4. Dans une troisième console, `iris logs --follow`.
5. `curl --ssl-no-revoke -x http://127.0.0.1:8888 --cacert data\ca.pem https://httpbin.org/headers -H "X-Demo: {{kc:demo}}"` : la réponse montre la valeur substituée ; `logs --follow` affiche l'event `substituted` (appel réseau réel de démonstration, hors tests automatiques).
6. `iris mcp wrap <dossier de test>\.mcp.json` (patché), une seconde fois (déjà conforme), `--dry-run` sur une copie, puis `iris mcp unwrap`.
7. `iris doctor` : tout `ok` sauf `ca-trusted` et `shell-env-vars` si le CA n'est pas importé et les variables pas définies (phase 7).
8. `test.bat` et `build.bat` passent ; CI verte.
