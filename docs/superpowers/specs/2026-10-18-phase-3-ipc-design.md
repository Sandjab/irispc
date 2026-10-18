# irispc — Spec phase 3 : IPC admin et flux d'events

Date : 2026-10-18. Statut : approuvée en brainstorming (trois sections), en attente de relecture du document.

Sources de vérité : `../Iris/SPECS.md` §4.1, §6, §13, §14, §19 ; implémentation de référence `../Iris/Sources/IrisKit/IPC/` ; spec socle `2026-10-17-socle-design.md`. Ce document ne redit pas ce qu'elles fixent ; il consigne le périmètre de la phase 3 et les décisions propres au portage. Quand il est muet, SPECS.md s'applique, puis la spec socle. Quand le code Swift et SPECS.md divergent, SPECS.md prime et l'écart est listé au §2.

## 1. Périmètre

La phase 3 livre :

1. le serveur JSON-RPC 2.0 sur le named pipe `\\.\pipe\iris-admin` (nom tiré de `broker.admin_pipe`) et son client `AdminClient` ;
2. les méthodes admin d'IRIS (§5), plus les méthodes `vault.*` propres à irispc (§6) ;
3. le **mode coffre fermé** : le daemon démarre et sert sans coffre déverrouillé, le MITM s'active au déverrouillage (§3) ;
4. le rechargement à chaud de `security.*`, `backups.max_count` et des hôtes (§7), différé depuis la phase 2 ;
5. le flux SSE sur `127.0.0.1:8899/events` et son client `EventsClient` (§8) ;
6. dans `irisd`, le drapeau `--locked`, le nouvel ordre de démarrage et les nouveaux cas du code 3 (§9).

Hors périmètre : `plugin.*` (lot plugins, à décider), `admin.uninstall` (phase 7, avec le lancement avec Windows), la CLI `iris` (phase 5), l'app et les notifications de `block_and_notify` (phase 6), `--ssl-no-revoke` dans le manuel (phase 7).

**Phasage.** La phase 4 du `CLAUDE.md` (« scoping `allowed_hosts` + règles R1–R5 ») est absorbée : le scoping et R1–R5 sont livrés depuis la phase 2, le rechargement à chaud de `security.*` entre ici, la notification revient à la phase 6. Le `CLAUDE.md` est mis à jour en conséquence.

**Mineur différé de la phase 2 repris** : `SocketError.AccessDenied` au bind n'est plus présenté comme « port déjà utilisé » (proxy et SSE), car Windows le renvoie aussi pour les plages de ports réservées.

## 2. Décisions et écarts

| Sujet | IRIS | irispc | Pourquoi |
|---|---|---|---|
| Transport admin | socket Unix 0600, trames `[uint32 BE][JSON]` | named pipe, mêmes trames, ACL utilisateur courant + refus du réseau | Spec socle §2. Trames gardées pour la parité de protocole. |
| Démarrage sans coffre | n/a (Keychain toujours accessible) | mode coffre fermé, méthodes `vault.status/unlock/create` | Le daemon lancé à l'ouverture de session (phase 7) n'a pas de console ; l'app transmet le mot de passe par le pipe. |
| `daemon.status` | `pid, uptime_s, version, stats, paused` | + champ additif `vault` | Une seule interrogation pour l'icône du tray. Un client IRIS l'ignore. |
| `events.query` | code Swift : ring seul | ring, complété par le journal JSONL quand `since` précède le plus ancien event du ring | SPECS §13.2 dit « from SQLite » : le magasin durable fait foi. |
| `events.clear` | code Swift : ring seul | ring **et** fichiers JSONL | `clear` vide ce que `query` lit. |
| Taille de trame | 1 Mio dans les deux sens | requête ≤ 1 Mio côté serveur ; réponse ≤ 16 Mio côté client | Une réponse `events.query` de 10 000 events dépasse 1 Mio. |
| Rechargement | SIGHUP ou `config.reload` | `config.reload` seul | Pas de signal équivalent sous Windows. |
| Flux SSE | NIO HTTP, `Transfer-Encoding: chunked` | `TcpListener` + `HttpParser`, `Connection: close`, corps jusqu'à la fermeture | Pas de `HttpListener` (réservation d'URL http.sys hors administrateur), réutilisation du parseur de la phase 2. |
| Codes d'erreur | -32001…-32006, -32010…-32012, -32030… (plugins) | idem + -32020…-32024 (`vault.*`) | Plage libre, sans collision avec les plugins. |

## 3. VaultGate et mode coffre fermé

`VaultGate` (`src/IrisKit/SecretStore/VaultGate.cs`) détient l'état du coffre et, une fois ouvert, le magasin de secrets (`SecretCache` devant `KeePassSecretStore`) et le `CAManager`.

États : `Absent` (pas de `iris.kdbx`), `Locked` (base présente, non ouverte), `Unlocked`. Transitions sous verrou : `Absent → Unlocked` par création, `Locked → Unlocked` par déverrouillage. Pas de reverrouillage en phase 3.

Ouverture (console ou pipe) : `VaultSession.Unlock` ou `Create` → `SecretsMetaStore` → `KeePassSecretStore` → `SecretCache` → `CAManager.EnsureCA` sur `KeePassCAKeyStore` (ou `InMemoryCAKeyStore` avec `--in-memory-ca`) → publication atomique du couple (secrets, CA) → log info `coffre déverrouillé, MITM actif`. Si le CA échoue, le coffre est refermé, l'état reste `Locked` et l'erreur remonte (-32603 côté pipe, code 2 côté console).

`--in-memory-secrets` : la porte est ouverte dès le démarrage avec `InMemorySecretStore` et un CA en mémoire ; `vault.status` rend `unlocked` et `path: null`.

Le proxy lit secrets et CA **à travers la porte**, sans redémarrer l'écoute (les tunnels en cours survivent au déverrouillage) :

- hôte hors whitelist : tunnel, comme en phase 2, quel que soit l'état ;
- hôte whitelisté, porte fermée : réponse `503` texte `coffre verrouillé : déverrouillez-le depuis l'app ou la CLI iris`, `Connection: close`, event `error` (méthode `CONNECT`, statut 503). Log warn au premier 503 depuis le démarrage, debug ensuite ;
- hôte whitelisté, porte ouverte : MITM comme en phase 2.

`LeafCertCache` et `RequestProcessor` sont créés à l'ouverture de la porte.

## 4. Pipe admin : transport et serveur

Trame : 4 octets big-endian (longueur du JSON) puis le JSON UTF-8. Requête : objet JSON-RPC 2.0 `{jsonrpc, method, params?, id}`, `id` entier, chaîne ou null. Réponse : `{jsonrpc, id, result}` ou `{jsonrpc, id, error: {code, message, data?}}`. Clés JSON en snake_case, dates ISO-8601 UTC, valeurs binaires en base64.

Serveur (`AdminServer`) :

- nom `\\.\pipe\<broker.admin_pipe>`, mode octet, asynchrone, **16 instances** au plus ; au-delà, le client attend (sémantique native des pipes) ;
- ACL : une seule ACE d'autorisation (SID de l'utilisateur courant : lecture, écriture, création d'instance) et une ACE de refus pour `NETWORK` (S-1-5-2) ;
- première instance créée avec l'équivalent de `FILE_FLAG_FIRST_PIPE_INSTANCE` (P/Invoke `CreateNamedPipe` si le .NET Framework ne l'expose pas) : si le pipe existe déjà, `AdminPipeInUseException` → code 3. Une instance en écoute est recréée avant de traiter chaque connexion acceptée, pour qu'il en existe toujours une ;
- par connexion : boucle lecture de trame → dispatch → écriture de la réponse, jusqu'à EOF. Plusieurs requêtes successives par connexion ; le client attend chaque réponse (pas de pipelining) ;
- trame déclarant plus de 1 Mio : connexion fermée sans réponse, log warn. JSON illisible : -32700. Objet sans `method` ou `jsonrpc != "2.0"` : -32600. Méthode inconnue : -32601 ;
- le tampon de chaque trame reçue est mis à zéro après décodage ;
- le dispatcher logue `admin <method> id=<id>` au niveau info, **jamais les paramètres**.

Client (`AdminClient`) :

- `Connect(pipeName, expectedServerPath, timeout)` ouvre le pipe puis vérifie l'identité du serveur **avant toute requête** : `GetNamedPipeServerProcessId` → chemin complet de l'image du processus → comparaison insensible à la casse avec `expectedServerPath` (par défaut `irisd.exe` du dossier de l'exécutable appelant). Échec : `AdminServerIdentityException`, connexion fermée, rien n'est envoyé. La vérification vaut pour tous les appels, puisque `secret.add`, `secret.rotate` et `vault.*` portent des valeurs sensibles ;
- `Call(method, params)` rend le `result` ou lève `AdminRpcException(code, message)` ; réponse plafonnée à 16 Mio.

## 5. Méthodes reprises d'IRIS

Mêmes noms, paramètres et résultats que `AdminProtocol.swift`. `Secret` sérialisé comme en phase 1 (`name`, `allowed_hosts`, `created_at`, `last_used_at`, `usage_count`, `quarantined`), sans valeur ; `MITMRule` : `host`, `origin`, `created_at` ; `Event` : sérialisation JSONL de la phase 1.

| Méthode | Paramètres | Résultat | Coffre requis |
|---|---|---|---|
| `secret.list` | — | `[Secret]` | oui |
| `secret.get` | `name` | `Secret` | oui |
| `secret.add` | `name`, `allowed_hosts`, `value` (base64) | `Secret` | oui |
| `secret.update` | `name`, `allowed_hosts` | `Secret` | oui |
| `secret.rotate` | `name`, `value` (base64) | `Secret` | oui |
| `secret.delete` | `name` | `{deleted: true}` | oui |
| `secret.set_quarantined` | `name`, `quarantined` | `Secret` | oui |
| `rule.add` | `host` | `MITMRule` (idempotent) | non |
| `rule.list` | — | `[MITMRule]` | non |
| `rule.delete` | `host` | `{deleted: true}` | non |
| `config.get` | — | `Config` (JSON de `config.json`) | non |
| `config.path` | — | `{path}` | non |
| `config.set` | `updates: [{key, value}]` (valeurs en chaînes) | `{applied, requires_restart}` | non |
| `config.reload` | — | `{reloaded: true, ignored}` | non |
| `daemon.status` | — | `{pid, uptime_s, version, stats, paused, vault}` | non |
| `daemon.stats` | — | `{req_total, sub_total, exfil_blocked_total, errors_total}` | non |
| `daemon.pause` / `daemon.resume` | — | `{paused}` | non |
| `events.query` | `since?`, `until?`, `limit?`, `kind?` (liste), `host?` | `[Event]` | non |
| `events.clear` | — | `{deleted_count}` | non |
| `ca.export_path` | — | `{path}` (`""` si `ca.pem` absent) | non |
| `ca.fingerprint` | — | `{sha256}` | oui |
| `ca.is_trusted` | — | `{trusted}` (empreinte présente dans `CurrentUser\Root`, lecture seule) | oui |

Précisions :

- `daemon.stats` : compteurs de `EventRing` par kind ; `req_total` est leur somme. `version` = `IrisVersion.Value`. `vault` ∈ `absent | locked | unlocked`.
- `events.query` : filtres appliqués dans l'ordre `since`, `until`, `kind`, `host`, puis conservation des `limit` plus récents ; `limit` absent ou supérieur à 10 000 → 10 000. Ordre chronologique croissant.
- `events.clear` : vide le ring et supprime les fichiers JSONL ; `deleted_count` = events supprimés du journal (le ring en est un sous-ensemble), ou du ring s'il n'y a pas de journal — le plus grand des deux.
- `rule.delete` : hôte `origin: default` → -32010, hôte absent → -32011. `rule.add` d'un hôte invalide → -32602.
- `config.set` : clés acceptées et sémantique de `ConfigStore.applyUpdates` d'IRIS, `broker.admin_socket` remplacé par `broker.admin_pipe`. Clés à chaud (`applied`) : `security.on_exfil_attempt`, `security.max_substitutions_per_minute`, `backups.max_count`. Toutes les clés `broker.*` vont dans `requires_restart`. Clé inconnue ou valeur invalide → -32602, rien n'est écrit (lot atomique). `hosts` ne se modifie que par `rule.*`.
- Méthode marquée « coffre requis » appelée porte fermée → -32020.

Correspondance des erreurs du coffre : `UnknownSecret` -32001, `InvalidName` -32002, `InvalidAllowedHosts` -32003, `Duplicate` -32004, `VaultBusy` -32022, `DataCorruption` -32603. Autres codes repris : -32006 `notFound`, -32012 `configReloadFailed`.

## 6. Méthodes `vault.*` et protections

| Méthode | Paramètres | Résultat | Erreurs |
|---|---|---|---|
| `vault.status` | — | `{state, path}` | — |
| `vault.unlock` | `password` | `{state: "unlocked"}` | -32021 mot de passe refusé, -32023 délai en cours, -32602 vide ; `Absent` → -32006 |
| `vault.create` | `password` | `{state: "unlocked"}` | -32024 coffre existant, -32602 vide |

Codes : -32020 `vaultLocked`, -32021 `badPassword`, -32022 `vaultBusy`, -32023 `rateLimited` (`data: {retry_after_s}`), -32024 `vaultExists`.

- **Pas d'oracle** : `vault.unlock` sur une porte déjà ouverte rend `{state: "unlocked"}` sans examiner le mot de passe et sans toucher au compteur d'échecs.
- **Force brute** : une seule ouverture à la fois (les appels concurrents attendent le verrou). Après le n-ième échec consécutif, toute tentative est refusée pendant `min(2^(n-1), 60)` secondes avec -32023, sans examiner le mot de passe. Un succès remet le compteur à zéro. Horloge injectée pour les tests. Le compteur est commun à la console et au pipe ; la console garde en plus sa limite de trois essais (code 2).
- **Mot de passe** : décodé de la trame directement en `SecureString` ; la `string` JSON intermédiaire est une limite du runtime, déjà acceptée pour les valeurs de secrets (ruling phase 2). Jamais logué, jamais dans un event, jamais dans un message d'erreur.
- **Console et pipe** : si le pipe ouvre la porte pendant l'invite console, l'invite est annulée et le daemon continue (log info).

## 7. Rechargement à chaud

`ConfigStore` gagne, sous un verrou unique (le daemon reste le seul écrivain, backup avant chaque écriture) :

- `ApplyUpdates(updates, now)` → `ConfigSetResult` ;
- `AddHost(host, now)` → `MITMRule` (idempotent), `DeleteHost(host)` → bool, exception typée pour un hôte `default` ;
- `Reload()` → relit `config.json`, le valide, le substitue à `Current` et rend la liste `ignored` des champs `broker.*` modifiés. Fichier illisible ou invalide : exception, `Current` inchangé (-32012). Contrairement au démarrage, pas de re-seed.

Effets, déclenchés par le daemon après chaque mutation réussie :

- `security.*` → `ProxyServer.UpdateSecurity(SecurityConfig)` ; `RequestProcessor` lit déjà politique et seuil par accesseurs ;
- `backups.max_count` → `KeePassVault.MaxBackups` et rotation des backups de config ;
- hôtes (`rule.*`, `config.reload`) → `ProxyServer.UpdateRules`.

## 8. Flux SSE

`EventsServer` : `TcpListener` sur `broker.events_listen`, adresse de bouclage obligatoire (sinon refus au démarrage, code 1). Requête lue par `HttpParser`.

- `GET /events[?query]` → `200`, `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `Connection: close`, corps jusqu'à la fermeture. Autre chemin → `404` ; autre méthode → `405`.
- Ouverture : `: connected\n\n`. Chaque event : `event: <kind>\nid: <uuid>\ndata: <JSON de l'Event>\n\n`. Ping `: ping\n\n` toutes les 15 s (intervalle injectable pour les tests).
- Filtres : `since=<ISO-8601>` rejoue le ring depuis cet instant avant le direct, sans doublon (dédoublonnage par id) ; `kind=a,b` ; `host=<hôte>` en égalité stricte. Paramètre invalide → `400`.
- Contre-pression : file bornée à 1000 events par abonné, alimentée par `EventsBus` sans bloquer `EventPipeline.Emit`. Au débordement : `event: dropped\ndata: {"count":N}\n\n`, puis fermeture.
- Au plus 32 abonnés simultanés ; au-delà, `503`.
- Pas d'authentification : loopback, métadonnées seulement, jamais de valeur (résiduel accepté d'IRIS, SPECS §2 et §14.1).

`EventsClient` : connexion, lecture ligne à ligne, rend des `Event` et signale `dropped` ; utilisé par les tests puis par l'app.

## 9. Daemon `irisd`

`irisd.exe --foreground [--locked] [--data <dossier>] [--in-memory-secrets] [--in-memory-ca] [--log-level <niveau>]`. `--locked` avec `--in-memory-secrets` → code 4 (incompatibles).

Ordre de démarrage : `data\` → config → events et purge → `VaultGate` (état `Absent` ou `Locked`, ou ouverte en `--in-memory-secrets`) → proxy → SSE → pipe admin → log `irisd ready on <proxy>, events <sse>, pipe \\.\pipe\<nom>, coffre <état>` (`verrouillé`, `ouvert` ou `absent`).

Ensuite, en `--foreground` sans `--locked` et porte fermée : invite console comme en phase 2 (création avec confirmation si `Absent`, sinon déverrouillage). Trois échecs → code 2. Ctrl+C pendant l'invite → arrêt propre, code 0. Avec `--locked` : aucune invite, le daemon attend `vault.unlock` ou `vault.create`.

Codes de sortie : 0 arrêt normal ; 1 données, config ou `events_listen` hors bouclage ; 2 coffre ; 3 port proxy occupé, port SSE occupé ou pipe déjà existant (messages distincts) ; 4 argument invalide. `AccessDenied` au bind donne un message dédié (« accès refusé au port N : plage réservée par Windows ou pare-feu ? ») et le code 3.

Arrêt : pipe fermé (connexions en cours abandonnées), SSE fermé (abonnés déconnectés), proxy arrêté avec ses 5 s de grâce, puis libérations de la phase 2.

## 10. Sécurité (invariants testés)

Les invariants de la spec socle §8 restent en vigueur. S'y ajoutent :

1. Aucune valeur de secret ni mot de passe maître dans les logs, events, réponses RPC, messages d'erreur ou flux SSE. Test : scénario `secret.add` + `vault.unlock` + substitution, puis recherche des valeurs dans le log capturé, le ring, le journal, les réponses et le flux.
2. `secret.get` et `secret.list` ne renvoient jamais de valeur.
3. Aucune substitution porte fermée ; un hôte whitelisté porte fermée n'est jamais tunnelé (503).
4. Le client n'envoie rien à un serveur de pipe dont l'image n'est pas l'exécutable attendu.
5. Le serveur refuse de démarrer si le pipe existe déjà.
6. Un échec de `vault.unlock` impose le délai, sans examen du mot de passe pendant ce délai.
7. Le pipe refuse les clients réseau ; le SSE n'écoute que sur une adresse de bouclage.

## 11. Tests

Mêmes règles qu'en phase 2 : tout en process, loopback, port 0, nom de pipe unique par test (`iris-admin-test-<guid>`), coffre réel uniquement sur une base temporaire de `%TEMP%`.

| Domaine | Tests |
|---|---|
| FrameCodec / JsonRpc | aller-retour, trame partielle, longueur > 1 Mio, JSON invalide, ids entier/chaîne/null, enveloppes d'erreur |
| Dispatcher (unitaire) | chaque méthode du §5 avec `InMemorySecretStore` et un faux `IDaemonControl` ; chaque code d'erreur ; -32020 sur chaque méthode « coffre requis » porte fermée ; `config.set` atomique ; `events.query` ring + JSONL ; `events.clear` |
| VaultGate | transitions, échec du CA qui laisse `Locked`, délai exponentiel (horloge injectée), absence d'oracle, compteur partagé |
| Pipe (intégration) | requêtes successives sur une connexion, connexions concurrentes, trame trop grande, second serveur refusé, identité du serveur acceptée et refusée |
| SSE (intégration) | en-têtes, `connected`, events en direct, `since` sans doublon, filtres `kind` et `host`, ping, `dropped` puis fermeture, 404, 405, 400, 503 au-delà de 32 |
| Proxy porte fermée | 503 et event `error` pour un hôte whitelisté, tunnel intact pour un hôte hors whitelist, MITM après ouverture sans redémarrage |
| Rechargement | `config.set` sur `security.*` change le comportement de `RequestProcessor` sans redémarrage ; `rule.add` fait passer un hôte du tunnel au MITM ; `config.reload` sur fichier invalide garde l'état |
| Daemon | `--locked` sur base temporaire : 503 → `vault.unlock` → substitution ; code 3 si pipe existant ; code 4 pour `--locked --in-memory-secrets` |
| Redaction | invariant 1 du §10 |

## 12. Démonstration et critères de la phase

Démontrable ainsi, sur un `build\Iris` propre :

1. `irisd --foreground --locked` : log `irisd ready … coffre verrouillé` ; `curl -x http://127.0.0.1:8888 https://api.anthropic.com/` → 503 `coffre verrouillé` ; `curl -N http://127.0.0.1:8899/events` affiche l'event `error`.
2. `irisd --foreground` : déverrouillage console ; le flux SSE affiche ensuite les events `substituted` du scénario de la phase 2.
3. Un script PowerShell de démonstration (`System.IO.Pipes`, sans secret) appelle `daemon.status` et affiche la réponse, champ `vault` compris.

Le pipe complet (`vault.unlock` compris) est démontré par les tests d'intégration ; la CLI de la phase 5 en sera le client utilisateur.
