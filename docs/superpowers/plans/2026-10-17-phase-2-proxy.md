# Phase 2 — Proxy MITM (HttpParser, tunnel, MITM, placeholders, règles R1–R5, streaming) : plan d'implémentation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `irisd --foreground` écoute sur `127.0.0.1:8888`, tunnelle sans déchiffrer les hôtes hors whitelist, déchiffre les hôtes whitelistés avec une feuille signée par le CA local, substitue `{{kc:NAME}}` selon `allowed_hosts` et les règles R1–R5, relaie la réponse en streaming, émet les events ; le scénario `curl --cacert data\ca.pem -H "x-api-key: {{kc:…}}"` de la spec §1 fonctionne.

**Architecture:** Tout en `async`/`await` sur `TcpListener`/`NetworkStream`/`SslStream` du .NET Framework, une `Task` par connexion cliente. `HttpConnection` (lecteur bufferisé sur un `Stream`, avec restes pour la bascule TLS et délai d'inactivité) et `HttpParser` (têtes HTTP/1.1, corps `Content-Length`/`chunked`, relais par blocs de 16 KiB) sont sans dépendance. `ConnectHandler` aiguille la première requête (`/__iris_ping`, `405`, `400`, whitelist) vers `TunnelHandler` (pompe TCP brute) ou `MITMHandler` (feuille de `LeafCertCache`, `SslStream` serveur, boucle keep-alive : parse → `RequestProcessor` → `UpstreamClient` → relais → `Event`). `RequestProcessor` est pur (sans réseau) : il enchaîne `PlaceholderScanner` → `ExfilRuleEngine` → `PlaceholderEngine` et porte la pause, les drapeaux `bodyTooLarge|nonUtf8|compressedBody|paused` et la politique `on_exfil_attempt`. Les tests d'intégration tournent en process avec `MockUpstream` (TLS avec son propre CA) et `TestProxyClient` (`CONNECT` puis TLS en faisant confiance au CA du proxy).

**Tech Stack:** C# 5, .NET Framework 4.8, `csc.exe` natif ; `System.Net.Sockets`, `System.Net.Security.SslStream` (TLS 1.2, SNI, sans ALPN → HTTP/1.1 des deux côtés), `System.Security.Cryptography.X509Certificates.CertificateRequest` + `X509SignatureGenerator.CreateForECDsa` (feuilles), PFX aller-retour avec `PersistKeySet` (Schannel refuse les clés éphémères), `CngKey.Delete` à l'éviction ; `System.Text.RegularExpressions`.

**Spec:** `docs/superpowers/specs/2026-10-17-socle-design.md` (§1 démonstration, §2 décisions, §5.4 placeholder et exfiltration, §6 proxy, §7 daemon, §8 sécurité, §9 tests, §11 phase 2). Amont : `../Iris/SPECS.md` §7 (syntaxe, scan, streaming, encodage, `Accept-Encoding`), §8 (scoping), §9 (R1–R5), §10 (flux), §11.2 (feuilles) ; `../Iris/Sources/IrisKit/{Placeholder,Proxy,CA/LeafCertCache.swift}` ; `../Iris/Tests/IrisKitTests/{PlaceholderScannerTests,PlaceholderEngineTests,ExfilRuleEngineTests,SlidingMinuteCounterTests,LeafCertCacheTests,Fuzzing/*}.swift` et `../Iris/Tests/IntegrationTests/{MockUpstream,TestProxyClient,ProxyEndToEndTests,ProxyStreamingTests,ProxyExfilBlockTests,PingEndpointTests}.swift`. Contexte : `CLAUDE.md`. Vérification préalable (spike jetable du 2026-10-17, `scratchpad\spike\SslSpike.cs`) : une feuille ECDSA P-256 signée par le CA via `X509SignatureGenerator.CreateForECDsa`, exportée en PFX puis réimportée avec `UserKeySet | PersistKeySet`, est acceptée par `SslStream.AuthenticateAsServer` (TLS 1.2, AES-256) ; un client `SslStream` la valide avec `X509Chain` + `ExtraStore` (CA) + `AllowUnknownCertificateAuthority` et épinglage de l'empreinte racine ; `CngKey.Delete` sur `((ECDsaCng)cert.GetECDsaPrivateKey()).Key` fait disparaître le conteneur (`CngKey.Exists` = false).

## Global Constraints

- **C# 5 strict** (csc `v4.0.30319`) : pas de `$""`, `?.`, `nameof`, `out var`, tuples, fonctions locales, membres expression-bodied, initialiseurs d'auto-propriétés, `catch … when`, `using static`. `async`/`await`, lambdas, `Task.FromResult`, `TaskCompletionSource<T>` sont permis. Pas de paramètre `out` dans une méthode `async` (rendre un petit objet résultat).
- Références : `System.dll, System.Core.dll, System.Web.Extensions.dll, System.Security.dll` et `vendor\KeePass-2.61.1\KeePass.exe`. Aucun NuGet. Flags csc : `-nologo -codepage:65001 -target:exe -optimize+` ; depuis Git Bash, `.bat` par chemin absolu (`cmd //c 'D:\Dev\irispc\test.bat'`).
- **Pas d'I/O bloquante dans le proxy** : tout en asynchrone ; pas de `Thread.Sleep` comme synchronisation (CLAUDE.md). Les tests appellent les méthodes `async` via `.GetAwaiter().GetResult()` (pas de `SynchronizationContext` en console, pas d'interblocage).
- Un fichier par responsabilité, ~300 lignes max ; `// ----` pour sectionner. Textes utilisateur et logs en français, identifiants et protocole en anglais.
- **Comportement identique à IRIS** (SPECS §7–§10) : regex `\{\{kc:([a-zA-Z0-9_-]{1,64})\}\}` ; scan des noms et valeurs d'en-têtes, du chemin, de la query, du corps si ≤ 4 MiB **reçus** et UTF-8 valide ; comparaison d'hôtes minuscules, sans port, exacte ; en-têtes canoniques `authorization`, `x-api-key`, `api-key`, `x-auth-token` ; R1 hostMismatch (high) → R2 nonCanonicalLocation (high ; chemin, query et corps sont toujours non canoniques) → R3 multipleSecrets (medium ; ≥ 2 noms **connus** distincts, nom déclencheur = premier par ordre alphabétique) → R4 suspiciousContentType (medium ; `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data` + chemin contenant `/comments`, `/issues`, `/notes`, `/messages`, `/blob` ; inatteignable derrière R2, conservée) → R5 volumeAnomaly (low ; fenêtre glissante inclusive de 60 s, seuil `max_substitutions_per_minute`, comptée seulement sur substitution effective) ; première règle déclenchée = l'alerte (ordre = sévérité décroissante) ; secrets inconnus laissés tels quels et jamais comptés ; secrets en quarantaine inertes (ni substitués ni évalués) ; toute règle déclenchée = **aucune substitution**, requête transmise intacte ; `Accept-Encoding` et `Proxy-Connection` retirés ; `Content-Length` recalculé ; `path` de l'event = URI **avant** substitution.
- **Divergences assumées par la spec socle** (elle prime) : en pause, l'event est `noMatch` avec le drapeau `paused` (IRIS émet `passThrough`) ; boucle keep-alive sur une connexion déchiffrée (IRIS ferme après une requête) ; une connexion amont par connexion cliente, réutilisée en keep-alive ; l'`Event` porte la clé optionnelle `flags` (tâche 2 de la phase 1).
- Limites et délais (spec §6) : tête ≤ 64 KiB et ≤ 100 en-têtes (sinon `400` et fermeture) ; corps bufferisé ≤ 4 MiB puis relais en streaming avec `bodyTooLarge` (en-têtes et URL quand même scannés) ; connexion amont 10 s ; inactivité 120 s sur une connexion déchiffrée ou un tunnel → fermeture des deux côtés ; arrêt : listener fermé, 5 s aux connexions en cours, puis fermeture forcée, flush de `secrets-meta.json` et du journal, clés CNG des feuilles supprimées.
- Erreurs (spec §6.3) : poignée de main côté agent échouée → event `error` + log `warn` « le client ne fait pas confiance à data\ca.pem » ; DNS/connexion/TLS amont en échec → `502 Bad Gateway` (corps texte court) + event `error` ; tête malformée → `400` ; port occupé → code 3 avec le port.
- Sécurité (spec §8) : aucune valeur de secret dans les logs, events, snippets ; aucune substitution sans `hôte ∈ allowed_hosts` ; les clés des feuilles ne survivent pas à l'éviction (test `CngKey.Exists` = false) ; le daemon n'ouvre de connexion sortante que vers l'hôte du `CONNECT` reçu ; le proxy n'écoute que sur une adresse de bouclage (audit IRIS M-4).
- Tests : `tests\Tests.cs` + fichiers `partial class TestMain` ; **aucun test ne touche le réseau hors bouclage** ; `MockUpstream` et le proxy écoutent sur `127.0.0.1` port 0 ; aucune base KeePass utilisateur.
- Codes de sortie de `irisd` : 0 normal, 1 données ou config, 2 coffre, 3 port occupé, 4 argument invalide.
- Git : branche `feat/phase-2-proxy` (créée), commits conventionnels, PR avec checklist, merge en squash après confirmation explicite de l'utilisateur.
- Mineurs différés de la revue de phase 1 repris quand ils touchent le périmètre : `CACrypto.RandomSerial` utilisé par les feuilles (tâche 4) ; Ctrl+C pendant la saisie du mot de passe (tâche 8) ; purge du journal planifiée à minuit UTC (tâche 8).

## Review Focus

1. **Client qui ne fait pas confiance au CA** (`curl` sans `--cacert`) : poignée de main refusée → event `error` avec l'hôte, log `warn` avec l'indice `ca.pem`, connexion fermée, daemon intact. Test `MITM_ClientRejectsCA_ErrorEvent` (tâche 7).
2. **Corps > 4 MiB** (upload) : relayé intégralement en streaming, en-têtes scannés, event `noMatch` avec `bodyTooLarge`, mémoire bornée. Test `MITM_LargeBody_StreamedWithFlag` (tâche 7).
3. **Amont injoignable** (DNS, port fermé) : `502` au client avec un corps texte, event `error`, connexion fermée proprement, sans trace de pile. Tests `Proxy_Tunnel502` (tâche 5) et `MITM_Upstream502` (tâche 7).
4. **Port 8888 déjà pris** : message avec le port, code 3, aucune autre sortie. Test `Entry_PortInUse_Exit3` (tâche 8).
5. **Deux requêtes sur la même connexion déchiffrée** (keep-alive, cas normal de `curl`/Node) : la seconde est servie, avec sa propre substitution et son propre event ; `Connection: close` ferme. Test `MITM_KeepAlive_TwoRequests` (tâche 7).

---

## Structure des fichiers de la phase 2

| Fichier | Responsabilité |
|---|---|
| `src\IrisKit\Proxy\HttpMessage.cs` | `HttpHeader`, `HttpHeaders` (ordre conservé, noms insensibles à la casse), `HttpRequestHead`, `HttpResponseHead` |
| `src\IrisKit\Proxy\HttpConnection.cs` | lecteur bufferisé sur un `Stream` : lignes, lecture exacte, restes (`TakeBuffered`), délai d'inactivité ; `PrefixedStream` pour réinjecter les restes sous un `SslStream` |
| `src\IrisKit\Proxy\HttpParser.cs` | têtes de requête/réponse, limites, encodage, cadrage du corps (`BodyFraming`), lecture bufferisée (`BufferedBody`), relais streaming, chunked ; `HttpProtocolException` |
| `src\IrisKit\Placeholder\PlaceholderHit.cs` | `HitLocation`, `PlaceholderHit` |
| `src\IrisKit\Placeholder\PlaceholderScanner.cs` | regex, scan des en-têtes/URI/corps, snippets, `FindPlaceholderNames` |
| `src\IrisKit\Placeholder\SlidingMinuteCounter.cs` | fenêtre glissante inclusive de 60 s |
| `src\IrisKit\Placeholder\PlaceholderEngine.cs` | substitution des hits autorisés, `ResolvedPayload`, valeurs non UTF-8 → `Unresolved` |
| `src\IrisKit\Placeholder\ExfilRuleEngine.cs` | `RequestContext`, `ExfilDecision`, R1–R5, quarantaine, compteurs R5 |
| `src\IrisKit\CA\LeafCertCache.cs` | feuilles par hôte (90 jours, CN + SAN, serverAuth), cache mémoire, renouvellement, suppression des clés CNG |
| `src\IrisKit\CA\CACrypto.cs` (modifié) | `CreateLeafCertificate`, `PrivateKeyName`, `DestroyPrivateKey` |
| `src\IrisKit\Proxy\UpstreamTrust.cs` | `IUpstreamTrust`, `SystemTrust` (magasin Windows), `PinnedRootTrust` (tests) |
| `src\IrisKit\Proxy\UpstreamClient.cs` | TCP + `SslStream` client (TLS 1.2, SNI, délai 10 s), `UpstreamConnection`, `UpstreamException` |
| `src\IrisKit\Proxy\ProxyOptions.cs` | options du serveur (écoute, whitelist, sécurité, trust, délais) |
| `src\IrisKit\Proxy\ProxyServer.cs` | listener, acceptation, registre des connexions, pause, `UpdateRules`, arrêt coopératif, `ProxyPortInUseException` |
| `src\IrisKit\Proxy\ConnectHandler.cs` | première requête : ping, `405`, `400`, whitelist → tunnel ou MITM ; `PingResponder` |
| `src\IrisKit\Proxy\TunnelHandler.cs` | passthrough TCP bidirectionnel, `502`, event `passThrough` à la fermeture |
| `src\IrisKit\Proxy\RequestProcessor.cs` | scan → règles → substitution, pause, drapeaux, politique `on_exfil_attempt`, `ProcessedRequest` |
| `src\IrisKit\Proxy\MITMHandler.cs` | `SslStream` serveur, boucle keep-alive, `100 Continue`, relais de la réponse, events, délais |
| `src\IrisKit\Events\PurgeScheduler.cs` | purge du journal à chaque minuit UTC |
| `src\irisd\Daemon.cs` (modifié) | démarre le proxy après le CA, code 3, arrêt en 5 s, Ctrl+C pendant la saisie |
| `src\irisd\IConsoleInput.cs` (modifié) | `ReadPassword(prompt, CancellationToken)` |
| `tests\MockUpstream.cs` | serveur TLS de test (CA propre), enregistre les requêtes, réponses simple / streaming / coupure |
| `tests\TestProxyClient.cs` | client de test : `CONNECT`, TLS en confiance au CA du proxy, requêtes keep-alive, lecture streaming |
| `tests\HttpParserTests.cs`, `PlaceholderTests.cs`, `ExfilTests.cs`, `FuzzTests.cs`, `LeafTests.cs`, `ProxyTests.cs`, `ProcessorTests.cs`, `MITMTests.cs`, `DaemonProxyTests.cs` | `partial class TestMain`, une méthode par test |

Chaque tâche ajoute ses sources à `IRISKIT_SOURCES` / `IRISD_SOURCES` / `TEST_SOURCES` dans `test.bat` **et** `build.bat` ; les listes complètes finales sont dans la tâche 9.

---

### Task 1: HTTP/1.1 — `HttpMessage`, `HttpConnection`, `HttpParser`

**Files:**
- Create: `src\IrisKit\Proxy\HttpMessage.cs`, `src\IrisKit\Proxy\HttpConnection.cs`, `src\IrisKit\Proxy\HttpParser.cs`
- Create: `tests\HttpParserTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `Iris.Tests.Check` (phase 0).
- Produces: `HttpHeader(Name, Value)` ; `HttpHeaders` (`Count`, `Add`, `Contains`, `First(name)` → null si absent, `All(name)`, `Remove(name) : int`, `Set(name, value)`, `Clone()`, énumérable) ; `HttpRequestHead(method, target, version, headers)` (`Method`, `Target`, `Version`, `Headers`) ; `HttpResponseHead(version, status, reason, headers)` (`Version`, `Status : int`, `Reason`, `Headers`) ; `HttpConnection(Stream) : IDisposable` (`Inner`, `ReadTimeout : TimeSpan` (zéro = aucun ; dépassement → `TimeoutException`), `ReadLineAsync(int maxLength, CancellationToken) : Task<string>` (null à EOF), `ReadAsync(byte[], int, int, CancellationToken) : Task<int>`, `ReadExactAsync(byte[], int, int, CancellationToken)` (`EndOfStreamException`), `TakeBuffered() : byte[]`, `WriteAsync(byte[], int, int, CancellationToken)`, `FlushAsync(CancellationToken)`) ; `PrefixedStream(byte[] prefix, Stream inner)` ; `HttpProtocolException(int status, string message)` (`Status`) ; `BodyFramingKind { None, ContentLength, Chunked, UntilClose }`, `BodyFraming` (`Kind`, `Length`, `BodyFraming.None/Chunked/UntilClose`, `BodyFraming.OfLength(long)`) ; `BufferedBody` (`Bytes`, `Complete`, `Remaining`, `ChunkRemaining`) ; `HttpParser` statique : `MaxHeadBytes = 65536`, `MaxHeaders = 100`, `MaxBufferedBody = 4194304`, `RelayBlock = 16384`, `ReadRequestHeadAsync(HttpConnection, CancellationToken) : Task<HttpRequestHead>` (null à EOF propre), `ReadResponseHeadAsync(HttpConnection, CancellationToken) : Task<HttpResponseHead>` (null à EOF), `Encode(HttpRequestHead) : byte[]`, `Encode(HttpResponseHead) : byte[]`, `WriteAsync(HttpConnection, HttpRequestHead, CancellationToken)`, `WriteAsync(HttpConnection, HttpResponseHead, CancellationToken)`, `RequestFraming(HttpHeaders) : BodyFraming`, `ResponseFraming(HttpHeaders, string requestMethod, int status) : BodyFraming`, `WantsClose(string version, HttpHeaders) : bool`, `ExpectsContinue(HttpHeaders) : bool`, `ReadBodyAsync(HttpConnection, BodyFraming, int maxBuffered, CancellationToken) : Task<BufferedBody>`, `RelayBodyAsync(HttpConnection from, HttpConnection to, BodyFraming, CancellationToken) : Task<long>`, `RelayRemainderAsync(HttpConnection from, HttpConnection to, BodyFraming, BufferedBody partial, CancellationToken)`, `WriteChunkAsync(HttpConnection, byte[], int, int, CancellationToken)`, `WriteLastChunkAsync(HttpConnection, CancellationToken)`, `StatusLine(int status) : string` (`"200 OK"`, `"400 Bad Request"`, `"405 Method Not Allowed"`, `"502 Bad Gateway"`, `"100 Continue"`), `Latin1 : Encoding`.

- [ ] **Step 1: Écrire `tests\HttpParserTests.cs` (RED)**

```csharp
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- HTTP/1.1 ---------------------------------------------------

        private static HttpConnection Conn(string text)
        {
            return new HttpConnection(new MemoryStream(HttpParser.Latin1.GetBytes(text)));
        }

        private static void Wait(Task task) { task.GetAwaiter().GetResult(); }

        private static void Http_RequestHead()
        {
            HttpConnection c = Conn("POST /v1/messages?x=1 HTTP/1.1\r\nHost: api.example\r\nX-Api-Key: {{kc:k}}\r\ncontent-length:  7 \r\n\r\nbody...");
            HttpRequestHead h = Wait(HttpParser.ReadRequestHeadAsync(c, CancellationToken.None));
            Check.Eq("POST", h.Method, "méthode");
            Check.Eq("/v1/messages?x=1", h.Target, "cible");
            Check.Eq("HTTP/1.1", h.Version, "version");
            Check.Eq(3, h.Headers.Count, "trois en-têtes");
            Check.Eq("api.example", h.Headers.First("host"), "nom insensible à la casse");
            Check.Eq("7", h.Headers.First("Content-Length"), "valeur sans espaces autour");
            Check.Eq("X-Api-Key", System.Linq.Enumerable.ElementAt(h.Headers, 1).Name, "casse d'origine conservée");
            Check.Eq(7L, HttpParser.RequestFraming(h.Headers).Length, "cadrage Content-Length");
            byte[] rest = new byte[7];
            Wait(c.ReadExactAsync(rest, 0, 7, CancellationToken.None));
            Check.Eq("body...", HttpParser.Latin1.GetString(rest), "le corps suit exactement la tête");
            Check.True(Wait(HttpParser.ReadRequestHeadAsync(Conn(""), CancellationToken.None)) == null, "EOF propre → null");
            HttpRequestHead connect = Wait(HttpParser.ReadRequestHeadAsync(Conn("CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n"), CancellationToken.None));
            Check.Eq("api.example:443", connect.Target, "CONNECT authority");
            Check.Eq(BodyFramingKind.None, HttpParser.RequestFraming(connect.Headers).Kind, "sans corps");
        }

        private static void Http_HeadLimitsAndErrors()
        {
            HttpProtocolException ex = Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET /\r\n\r\n"), CancellationToken.None)); }, "ligne de requête à deux éléments");
            Check.Eq(400, ex.Status, "400");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nNoColon\r\n\r\n"), CancellationToken.None)); }, "en-tête sans deux-points");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nBad Name: x\r\n\r\n"), CancellationToken.None)); }, "espace dans le nom");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nHost: a\r\n"), CancellationToken.None)); }, "tête tronquée");
            StringBuilder many = new StringBuilder("GET / HTTP/1.1\r\n");
            for (int i = 0; i < 101; i++) many.Append("X-").Append(i).Append(": v\r\n");
            many.Append("\r\n");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn(many.ToString()), CancellationToken.None)); }, "plus de 100 en-têtes");
            string big = "GET / HTTP/1.1\r\nX: " + new string('a', 70 * 1024) + "\r\n\r\n";
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn(big), CancellationToken.None)); }, "tête > 64 KiB");
            Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Content-Length: abc")); }, "Content-Length non numérique");
            Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Content-Length: -1")); }, "Content-Length négatif");
        }

        private static HttpHeaders HeadersOf(params string[] lines)
        {
            HttpHeaders h = new HttpHeaders();
            foreach (string line in lines)
            {
                int colon = line.IndexOf(':');
                h.Add(line.Substring(0, colon), line.Substring(colon + 1).Trim());
            }
            return h;
        }

        private static void Http_ResponseHeadAndFraming()
        {
            HttpResponseHead r = Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"), CancellationToken.None));
            Check.Eq(200, r.Status, "statut");
            Check.Eq("OK", r.Reason, "raison");
            Check.Eq(BodyFramingKind.Chunked, HttpParser.ResponseFraming(r.Headers, "GET", 200).Kind, "chunked");
            Check.Eq(BodyFramingKind.None, HttpParser.ResponseFraming(r.Headers, "HEAD", 200).Kind, "HEAD : pas de corps");
            Check.Eq(BodyFramingKind.None, HttpParser.ResponseFraming(HeadersOf("Content-Length: 5"), "GET", 204).Kind, "204 : pas de corps");
            Check.Eq(BodyFramingKind.UntilClose, HttpParser.ResponseFraming(HeadersOf("Content-Type: text/plain"), "GET", 200).Kind, "ni longueur ni chunked → jusqu'à la fermeture");
            Check.Eq(5L, HttpParser.ResponseFraming(HeadersOf("Content-Length: 5"), "GET", 200).Length, "Content-Length");
            HttpResponseHead noReason = Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 502 \r\n\r\n"), CancellationToken.None));
            Check.Eq(502, noReason.Status, "raison vide acceptée");
            Check.Eq("", noReason.Reason, "raison vide");
            HttpProtocolException ex = Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 2x0 OK\r\n\r\n"), CancellationToken.None)); }, "statut invalide");
            Check.Eq(502, ex.Status, "une réponse amont invalide vaut 502 pour le client");
            Check.True(Wait(HttpParser.ReadResponseHeadAsync(Conn(""), CancellationToken.None)) == null, "EOF → null");
            Check.True(HttpParser.WantsClose("HTTP/1.1", HeadersOf("Connection: keep-alive, Close")), "Connection: close (jeton, insensible à la casse)");
            Check.True(!HttpParser.WantsClose("HTTP/1.1", HeadersOf("Connection: keep-alive")), "keep-alive explicite");
            Check.True(HttpParser.WantsClose("HTTP/1.0", new HttpHeaders()), "HTTP/1.0 sans keep-alive ferme");
            Check.True(!HttpParser.WantsClose("HTTP/1.0", HeadersOf("Connection: keep-alive")), "HTTP/1.0 + keep-alive garde");
            Check.True(HttpParser.ExpectsContinue(HeadersOf("Expect: 100-Continue")), "Expect: 100-continue");
        }

        private static void Http_EncodeHeads()
        {
            HttpHeaders h = new HttpHeaders();
            h.Add("Host", "api.example");
            h.Add("X-Api-Key", "sk-é");
            string req = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpRequestHead("POST", "/v1", "HTTP/1.1", h)));
            Check.Eq("POST /v1 HTTP/1.1\r\nHost: api.example\r\nX-Api-Key: sk-é\r\n\r\n", req, "tête de requête (octets Latin-1 transparents)");
            string resp = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpResponseHead("HTTP/1.1", 502, "Bad Gateway", HeadersOf("Content-Length: 0"))));
            Check.Eq("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", resp, "tête de réponse");
            Check.Eq("405 Method Not Allowed", HttpParser.StatusLine(405), "libellé 405");
            Check.Eq("100 Continue", HttpParser.StatusLine(100), "libellé 100");
            HttpHeaders clone = h.Clone();
            clone.Set("host", "other");
            clone.Remove("x-api-key");
            Check.Eq("api.example", h.First("Host"), "Clone est indépendant");
            Check.Eq("other", clone.First("Host"), "Set remplace la valeur en gardant la casse du nom d'origine");
            Check.Eq("Host", System.Linq.Enumerable.First(clone).Name, "nom d'origine conservé par Set");
            Check.Eq(1, clone.Count, "Remove retire toutes les occurrences");
            clone.Add("Via", "a");
            clone.Add("via", "b");
            Check.Eq("a,b", string.Join(",", clone.All("VIA")), "All rend toutes les occurrences dans l'ordre");
            clone.Set("Via", "c");
            Check.Eq(1, clone.All("via").Count, "Set ne laisse qu'une occurrence");
        }

        private static void Http_ReadBodyContentLengthAndChunked()
        {
            BufferedBody b = Wait(HttpParser.ReadBodyAsync(Conn("hello world!"), BodyFraming.OfLength(5), 4096, CancellationToken.None));
            Check.Eq("hello", HttpParser.Latin1.GetString(b.Bytes), "Content-Length : exactement N octets");
            Check.True(b.Complete && b.Remaining == 0, "complet");
            b = Wait(HttpParser.ReadBodyAsync(Conn("0123456789"), BodyFraming.OfLength(10), 4, CancellationToken.None));
            Check.Eq("0123", HttpParser.Latin1.GetString(b.Bytes), "tronqué à la limite");
            Check.True(!b.Complete && b.Remaining == 6, "6 octets restent sur le fil");
            b = Wait(HttpParser.ReadBodyAsync(Conn("4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT"), BodyFraming.Chunked, 4096, CancellationToken.None));
            Check.Eq("Wikipedia", HttpParser.Latin1.GetString(b.Bytes), "chunked décodé, extension ignorée, trailers consommés");
            Check.True(b.Complete, "complet");
            HttpConnection c = Conn("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
            b = Wait(HttpParser.ReadBodyAsync(c, BodyFraming.Chunked, 6, CancellationToken.None));
            Check.Eq("Wikipe", HttpParser.Latin1.GetString(b.Bytes), "arrêt au milieu d'un chunk à la limite");
            Check.True(!b.Complete && b.ChunkRemaining == 3, "3 octets du chunk courant restent");
            MemoryStream outStream = new MemoryStream();
            Wait(HttpParser.RelayRemainderAsync(c, new HttpConnection(outStream), BodyFraming.Chunked, b, CancellationToken.None));
            Check.Eq("3\r\ndia\r\n0\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "le reste est réémis en chunks");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadBodyAsync(Conn("zz\r\n"), BodyFraming.Chunked, 4096, CancellationToken.None)); }, "taille de chunk invalide");
            Check.Throws<EndOfStreamException>(delegate { Wait(HttpParser.ReadBodyAsync(Conn("abc"), BodyFraming.OfLength(5), 4096, CancellationToken.None)); }, "corps tronqué");
            b = Wait(HttpParser.ReadBodyAsync(Conn("x"), BodyFraming.None, 4096, CancellationToken.None));
            Check.Eq(0, b.Bytes.Length, "sans corps → vide");
        }

        private static void Http_RelayBodyStreaming()
        {
            MemoryStream outStream = new MemoryStream();
            HttpConnection to = new HttpConnection(outStream);
            long n = Wait(HttpParser.RelayBodyAsync(Conn("4\r\nWiki\r\n5\r\npedia\r\n0\r\nX: y\r\n\r\n"), to, BodyFraming.Chunked, CancellationToken.None));
            Check.Eq("4\r\nWiki\r\n5\r\npedia\r\n0\r\nX: y\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "chunked relayé octet pour octet, trailers compris");
            Check.Eq(9L, n, "octets utiles comptés");
            outStream = new MemoryStream();
            byte[] big = new byte[40000];
            for (int i = 0; i < big.Length; i++) big[i] = (byte)(i % 251);
            n = Wait(HttpParser.RelayBodyAsync(new HttpConnection(new MemoryStream(big)), new HttpConnection(outStream), BodyFraming.OfLength(40000), CancellationToken.None));
            Check.True(n == 40000 && outStream.Length == 40000, "Content-Length relayé par blocs de 16 KiB");
            Check.Eq(Convert.ToBase64String(big), Convert.ToBase64String(outStream.ToArray()), "octets identiques");
            outStream = new MemoryStream();
            n = Wait(HttpParser.RelayBodyAsync(Conn("until the end"), new HttpConnection(outStream), BodyFraming.UntilClose, CancellationToken.None));
            Check.Eq("until the end", HttpParser.Latin1.GetString(outStream.ToArray()), "jusqu'à EOF");
            outStream = new MemoryStream();
            Wait(HttpParser.WriteChunkAsync(new HttpConnection(outStream), HttpParser.Latin1.GetBytes("abc"), 0, 3, CancellationToken.None));
            Wait(HttpParser.WriteLastChunkAsync(new HttpConnection(outStream), CancellationToken.None));
            Check.Eq("3\r\nabc\r\n0\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "écriture de chunks");
        }

        private static void Http_ConnectionLeftoverAndTimeout()
        {
            HttpConnection c = Conn("CONNECT h:443 HTTP/1.1\r\n\r\n\x16\x03\x01TLS");
            HttpRequestHead h = Wait(HttpParser.ReadRequestHeadAsync(c, CancellationToken.None));
            Check.Eq("CONNECT", h.Method, "CONNECT lu");
            byte[] left = c.TakeBuffered();
            Check.Eq("\x16\x03\x01TLS", HttpParser.Latin1.GetString(left), "les octets TLS arrivés dans le même segment sont rendus");
            Check.Eq(0, c.TakeBuffered().Length, "une seule fois");
            PrefixedStream p = new PrefixedStream(left, new MemoryStream(HttpParser.Latin1.GetBytes("more")));
            byte[] buf = new byte[32];
            int n1 = p.Read(buf, 0, 4);
            int n2 = p.Read(buf, 4, 28);
            Check.Eq(4, n1, "première lecture bornée à count");
            Check.Eq(3, n2, "le reste du préfixe avant le flux interne");
            Check.Eq("TLS", HttpParser.Latin1.GetString(buf, 0, 7), "le préfixe est servi d'abord");
            int n3 = p.Read(buf, 7, 25);
            Check.Eq("TLSmore", HttpParser.Latin1.GetString(buf, 0, 7 + n3), "puis le flux interne");
            HttpConnection slow = new HttpConnection(new BlockingStream());
            slow.ReadTimeout = TimeSpan.FromMilliseconds(200);
            Check.Throws<TimeoutException>(delegate { Wait(slow.ReadLineAsync(100, CancellationToken.None)); }, "inactivité → TimeoutException");
            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();
            Check.Throws<OperationCanceledException>(delegate { Wait(new HttpConnection(new BlockingStream()).ReadLineAsync(100, cts.Token)); }, "annulation → OperationCanceledException");
            Check.Throws<HttpProtocolException>(delegate { Wait(Conn(new string('a', 70000) + "\r\n").ReadLineAsync(65536, CancellationToken.None)); }, "ligne trop longue");
            Check.Eq("ab", Wait(Conn("ab\n").ReadLineAsync(10, CancellationToken.None)), "LF seul toléré");
        }

        /// <summary>Flux dont la lecture ne rend jamais (simule un pair silencieux).</summary>
        private sealed class BlockingStream : Stream
        {
            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                TaskCompletionSource<int> tcs = new TaskCompletionSource<int>();
                cancellationToken.Register(delegate { tcs.TrySetCanceled(); });
                return tcs.Task;
            }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        }
    }
}
```

Dans `tests\Tests.cs`, `Main`, après la ligne `Entry_UnexpectedException_NoStackTrace`, ajouter :

```csharp
            Check.Run("HTTP : tête de requête", Http_RequestHead);
            Check.Run("HTTP : limites et erreurs de tête", Http_HeadLimitsAndErrors);
            Check.Run("HTTP : tête de réponse et cadrage", Http_ResponseHeadAndFraming);
            Check.Run("HTTP : encodage des têtes et HttpHeaders", Http_EncodeHeads);
            Check.Run("HTTP : corps Content-Length et chunked bufferisés", Http_ReadBodyContentLengthAndChunked);
            Check.Run("HTTP : relais streaming", Http_RelayBodyStreaming);
            Check.Run("HTTP : restes, préfixe, délai, annulation", Http_ConnectionLeftoverAndTimeout);
```

`TEST_SOURCES` de `test.bat` : ajouter `"%TESTS%\HttpParserTests.cs"`.

- [ ] **Step 2: Vérifier l'échec**

```bash
cmd //c 'D:\Dev\irispc\test.bat' 2>&1 | grep -E 'error CS' | head -3
```

Attendu : `CS0246 'HttpConnection'` / `'HttpParser'`.

- [ ] **Step 3: Écrire `src\IrisKit\Proxy\HttpMessage.cs`**

```csharp
using System;
using System.Collections;
using System.Collections.Generic;

namespace IrisKit
{
    public sealed class HttpHeader
    {
        public string Name { get; private set; }
        public string Value { get; private set; }

        public HttpHeader(string name, string value)
        {
            if (name == null) throw new ArgumentNullException("name");
            Name = name;
            Value = value ?? "";
        }
    }

    /// <summary>En-têtes dans l'ordre du fil, noms insensibles à la casse (RFC 7230 §3.2), occurrences multiples conservées.</summary>
    public sealed class HttpHeaders : IEnumerable<HttpHeader>
    {
        private readonly List<HttpHeader> list = new List<HttpHeader>();

        public int Count { get { return list.Count; } }

        public void Add(string name, string value) { list.Add(new HttpHeader(name, value)); }

        public bool Contains(string name) { return IndexOf(name) >= 0; }

        /// <summary>Première valeur, ou null si absent.</summary>
        public string First(string name)
        {
            int i = IndexOf(name);
            return i < 0 ? null : list[i].Value;
        }

        public IList<string> All(string name)
        {
            List<string> values = new List<string>();
            foreach (HttpHeader h in list) if (Is(h, name)) values.Add(h.Value);
            return values;
        }

        /// <summary>Retire toutes les occurrences ; rend leur nombre.</summary>
        public int Remove(string name)
        {
            return list.RemoveAll(delegate(HttpHeader h) { return Is(h, name); });
        }

        /// <summary>Remplace la première occurrence (en gardant la casse de son nom), retire les autres, ou ajoute.</summary>
        public void Set(string name, string value)
        {
            int i = IndexOf(name);
            if (i < 0) { Add(name, value); return; }
            list[i] = new HttpHeader(list[i].Name, value);
            for (int j = list.Count - 1; j > i; j--) if (Is(list[j], name)) list.RemoveAt(j);
        }

        public HttpHeaders Clone()
        {
            HttpHeaders copy = new HttpHeaders();
            copy.list.AddRange(list);
            return copy;
        }

        private int IndexOf(string name)
        {
            for (int i = 0; i < list.Count; i++) if (Is(list[i], name)) return i;
            return -1;
        }

        private static bool Is(HttpHeader h, string name)
        {
            return string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase);
        }

        public IEnumerator<HttpHeader> GetEnumerator() { return list.GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return list.GetEnumerator(); }
    }

    public sealed class HttpRequestHead
    {
        public string Method { get; private set; }
        /// <summary>Cible telle que reçue : chemin+query (origin-form) ou `host:port` (CONNECT).</summary>
        public string Target { get; private set; }
        public string Version { get; private set; }
        public HttpHeaders Headers { get; private set; }

        public HttpRequestHead(string method, string target, string version, HttpHeaders headers)
        {
            Method = method; Target = target; Version = version; Headers = headers ?? new HttpHeaders();
        }
    }

    public sealed class HttpResponseHead
    {
        public string Version { get; private set; }
        public int Status { get; private set; }
        public string Reason { get; private set; }
        public HttpHeaders Headers { get; private set; }

        public HttpResponseHead(string version, int status, string reason, HttpHeaders headers)
        {
            Version = version; Status = status; Reason = reason ?? ""; Headers = headers ?? new HttpHeaders();
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\Proxy\HttpConnection.cs`**

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Lecteur bufferisé asynchrone sur un Stream (NetworkStream, SslStream, MemoryStream) : lignes, lecture exacte,
    /// restes non consommés (TakeBuffered, pour la bascule TLS après CONNECT), délai d'inactivité par lecture.
    /// Les écritures passent directement au flux interne.
    /// </summary>
    public sealed class HttpConnection : IDisposable
    {
        private readonly Stream inner;
        private byte[] buffer = new byte[16 * 1024];
        private int start;
        private int end;

        /// <summary>Délai maximal d'attente d'une lecture ; TimeSpan.Zero = illimité. Dépassement → TimeoutException.</summary>
        public TimeSpan ReadTimeout { get; set; }

        public Stream Inner { get { return inner; } }

        public HttpConnection(Stream inner)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            this.inner = inner;
        }

        // ---- Lecture ----------------------------------------------------

        /// <summary>Ligne terminée par LF (CR final retiré), sans le terminateur ; null si EOF sans octet lu.</summary>
        public async Task<string> ReadLineAsync(int maxLength, CancellationToken cancel)
        {
            int scanned = 0;
            while (true)
            {
                for (int i = start + scanned; i < end; i++)
                {
                    if (buffer[i] == (byte)'\n')
                    {
                        int length = i - start;
                        if (length > 0 && buffer[i - 1] == (byte)'\r') length--;
                        string line = HttpParser.Latin1.GetString(buffer, start, length);
                        start = i + 1;
                        return line;
                    }
                }
                scanned = end - start;
                if (scanned > maxLength) throw new HttpProtocolException(400, "ligne HTTP trop longue (plus de " + maxLength + " octets)");
                if (!await FillAsync(cancel).ConfigureAwait(false))
                {
                    if (scanned == 0) return null;
                    throw new HttpProtocolException(400, "ligne HTTP tronquée");
                }
            }
        }

        /// <summary>Au plus count octets, d'abord depuis le tampon ; 0 à EOF.</summary>
        public async Task<int> ReadAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            if (count == 0) return 0;
            if (start == end && !await FillAsync(cancel).ConfigureAwait(false)) return 0;
            int n = Math.Min(count, end - start);
            Buffer.BlockCopy(buffer, start, dst, offset, n);
            start += n;
            return n;
        }

        public async Task ReadExactAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            int done = 0;
            while (done < count)
            {
                int n = await ReadAsync(dst, offset + done, count - done, cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("flux fermé après " + done + " octet(s) sur " + count);
                done += n;
            }
        }

        /// <summary>Rend et vide les octets déjà reçus mais non consommés (ex. ClientHello TLS arrivé avec le CONNECT).</summary>
        public byte[] TakeBuffered()
        {
            byte[] rest = new byte[end - start];
            Buffer.BlockCopy(buffer, start, rest, 0, rest.Length);
            start = end = 0;
            return rest;
        }

        private async Task<bool> FillAsync(CancellationToken cancel)
        {
            if (start > 0)
            {
                Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
                end -= start;
                start = 0;
            }
            if (end == buffer.Length) Array.Resize(ref buffer, buffer.Length * 2);
            int n = await ReadInnerAsync(buffer, end, buffer.Length - end, cancel).ConfigureAwait(false);
            if (n <= 0) return false;
            end += n;
            return true;
        }

        private async Task<int> ReadInnerAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            Task<int> read = inner.ReadAsync(dst, offset, count, cancel);
            if (ReadTimeout <= TimeSpan.Zero) return await read.ConfigureAwait(false);
            using (CancellationTokenSource delayCts = CancellationTokenSource.CreateLinkedTokenSource(cancel))
            {
                Task delay = Task.Delay(ReadTimeout, delayCts.Token);
                Task first = await Task.WhenAny(read, delay).ConfigureAwait(false);
                if (first == delay)
                {
                    cancel.ThrowIfCancellationRequested();
                    Observe(read);
                    throw new TimeoutException("aucune donnée reçue pendant " + (int)ReadTimeout.TotalSeconds + " s");
                }
                delayCts.Cancel();
                return await read.ConfigureAwait(false);
            }
        }

        /// <summary>Une lecture abandonnée (délai dépassé) finira par échouer à la fermeture du flux : on observe son exception.</summary>
        private static void Observe(Task task)
        {
            task.ContinueWith(delegate(Task t) { Exception ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
        }

        // ---- Écriture ---------------------------------------------------

        public Task WriteAsync(byte[] data, int offset, int count, CancellationToken cancel)
        {
            return inner.WriteAsync(data, offset, count, cancel);
        }

        public Task FlushAsync(CancellationToken cancel)
        {
            return inner.FlushAsync(cancel);
        }

        public void Dispose()
        {
            inner.Dispose();
        }
    }

    /// <summary>Flux qui sert d'abord un préfixe (octets déjà lus) puis délègue au flux interne. Sert à poser un SslStream après un CONNECT.</summary>
    public sealed class PrefixedStream : Stream
    {
        private readonly byte[] prefix;
        private int position;
        private readonly Stream inner;

        public PrefixedStream(byte[] prefix, Stream inner)
        {
            this.prefix = prefix ?? new byte[0];
            this.inner = inner;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return inner.CanWrite; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = FromPrefix(buffer, offset, count);
            return n > 0 ? n : inner.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int n = FromPrefix(buffer, offset, count);
            return n > 0 ? Task.FromResult(n) : inner.ReadAsync(buffer, offset, count, cancellationToken);
        }

        private int FromPrefix(byte[] buffer, int offset, int count)
        {
            int n = Math.Min(count, prefix.Length - position);
            if (n <= 0) return 0;
            Buffer.BlockCopy(prefix, position, buffer, offset, n);
            position += n;
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) { return inner.WriteAsync(buffer, offset, count, cancellationToken); }
        public override void Flush() { inner.Flush(); }
        public override Task FlushAsync(CancellationToken cancellationToken) { return inner.FlushAsync(cancellationToken); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Proxy\HttpParser.cs`**

```csharp
using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Tête HTTP malformée ou hors limites. Status = réponse à rendre au client (400 côté requête, 502 côté amont).</summary>
    public sealed class HttpProtocolException : Exception
    {
        public int Status { get; private set; }
        public HttpProtocolException(int status, string message) : base(message) { Status = status; }
    }

    public enum BodyFramingKind { None, ContentLength, Chunked, UntilClose }

    public sealed class BodyFraming
    {
        public BodyFramingKind Kind { get; private set; }
        public long Length { get; private set; }

        private BodyFraming(BodyFramingKind kind, long length) { Kind = kind; Length = length; }

        public static readonly BodyFraming None = new BodyFraming(BodyFramingKind.None, 0);
        public static readonly BodyFraming Chunked = new BodyFraming(BodyFramingKind.Chunked, 0);
        public static readonly BodyFraming UntilClose = new BodyFraming(BodyFramingKind.UntilClose, 0);
        public static BodyFraming OfLength(long length) { return new BodyFraming(BodyFramingKind.ContentLength, length); }
    }

    /// <summary>Corps lu en mémoire jusqu'à une limite. Complete = false : le reste est encore sur le fil (Remaining octets, ou ChunkRemaining dans le chunk courant).</summary>
    public sealed class BufferedBody
    {
        public byte[] Bytes { get; private set; }
        public bool Complete { get; private set; }
        public long Remaining { get; private set; }
        public long ChunkRemaining { get; private set; }

        public BufferedBody(byte[] bytes, bool complete, long remaining, long chunkRemaining)
        {
            Bytes = bytes; Complete = complete; Remaining = remaining; ChunkRemaining = chunkRemaining;
        }
    }

    /// <summary>HTTP/1.1 minimal et strict (spec §6.1) : têtes (≤ 64 KiB, ≤ 100 en-têtes), corps Content-Length ou chunked, relais par blocs.</summary>
    public static class HttpParser
    {
        public const int MaxHeadBytes = 64 * 1024;
        public const int MaxHeaders = 100;
        public const int MaxBufferedBody = 4 * 1024 * 1024;
        public const int RelayBlock = 16 * 1024;

        /// <summary>Les octets d'en-tête sont transportés tels quels (ISO-8859-1 : un octet ↔ un caractère).</summary>
        public static readonly Encoding Latin1 = Encoding.GetEncoding(28591);
        private static readonly byte[] CrLf = { 13, 10 };

        // ---- Têtes ------------------------------------------------------

        public static async Task<HttpRequestHead> ReadRequestHeadAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
            if (line == null) return null;
            if (line.Length == 0) line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false); // RFC 7230 §3.5 : un CRLF de trop toléré
            if (line == null) return null;
            string[] parts = line.Split(' ');
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
                throw new HttpProtocolException(400, "ligne de requête invalide");
            HttpHeaders headers = await ReadHeadersAsync(c, line.Length + 2, 400, cancel).ConfigureAwait(false);
            return new HttpRequestHead(parts[0], parts[1], parts[2], headers);
        }

        public static async Task<HttpResponseHead> ReadResponseHeadAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
            if (line == null) return null;
            int sp1 = line.IndexOf(' ');
            if (sp1 < 0 || !line.StartsWith("HTTP/1.", StringComparison.Ordinal)) throw new HttpProtocolException(502, "ligne de statut amont invalide");
            int sp2 = line.IndexOf(' ', sp1 + 1);
            string code = sp2 < 0 ? line.Substring(sp1 + 1) : line.Substring(sp1 + 1, sp2 - sp1 - 1);
            int status;
            if (code.Length != 3 || !int.TryParse(code, NumberStyles.None, CultureInfo.InvariantCulture, out status))
                throw new HttpProtocolException(502, "statut amont invalide : " + code);
            string reason = sp2 < 0 ? "" : line.Substring(sp2 + 1);
            HttpHeaders headers = await ReadHeadersAsync(c, line.Length + 2, 502, cancel).ConfigureAwait(false);
            return new HttpResponseHead(line.Substring(0, sp1), status, reason, headers);
        }

        private static async Task<HttpHeaders> ReadHeadersAsync(HttpConnection c, int consumed, int errorStatus, CancellationToken cancel)
        {
            HttpHeaders headers = new HttpHeaders();
            while (true)
            {
                string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                if (line == null) throw new HttpProtocolException(errorStatus, "tête HTTP tronquée");
                consumed += line.Length + 2;
                if (consumed > MaxHeadBytes) throw new HttpProtocolException(errorStatus, "tête HTTP trop grande (plus de " + MaxHeadBytes + " octets)");
                if (line.Length == 0) return headers;
                if (headers.Count >= MaxHeaders) throw new HttpProtocolException(errorStatus, "plus de " + MaxHeaders + " en-têtes");
                int colon = line.IndexOf(':');
                if (colon <= 0) throw new HttpProtocolException(errorStatus, "en-tête invalide");
                string name = line.Substring(0, colon);
                if (name.IndexOf(' ') >= 0 || name.IndexOf('\t') >= 0) throw new HttpProtocolException(errorStatus, "nom d'en-tête invalide");
                headers.Add(name, line.Substring(colon + 1).Trim(' ', '\t'));
            }
        }

        public static byte[] Encode(HttpRequestHead head)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(head.Method).Append(' ').Append(head.Target).Append(' ').Append(head.Version).Append("\r\n");
            AppendHeaders(sb, head.Headers);
            return Latin1.GetBytes(sb.ToString());
        }

        public static byte[] Encode(HttpResponseHead head)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(head.Version).Append(' ').Append(head.Status.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(head.Reason).Append("\r\n");
            AppendHeaders(sb, head.Headers);
            return Latin1.GetBytes(sb.ToString());
        }

        private static void AppendHeaders(StringBuilder sb, HttpHeaders headers)
        {
            foreach (HttpHeader h in headers) sb.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
            sb.Append("\r\n");
        }

        public static async Task WriteAsync(HttpConnection c, HttpRequestHead head, CancellationToken cancel)
        {
            byte[] bytes = Encode(head);
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }

        public static async Task WriteAsync(HttpConnection c, HttpResponseHead head, CancellationToken cancel)
        {
            byte[] bytes = Encode(head);
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }

        public static string StatusLine(int status)
        {
            switch (status)
            {
                case 100: return "100 Continue";
                case 200: return "200 OK";
                case 400: return "400 Bad Request";
                case 405: return "405 Method Not Allowed";
                case 502: return "502 Bad Gateway";
                default: return status.ToString(CultureInfo.InvariantCulture) + " Status";
            }
        }

        // ---- Cadrage ----------------------------------------------------

        /// <summary>Requête : chunked prime, puis Content-Length, sinon pas de corps.</summary>
        public static BodyFraming RequestFraming(HttpHeaders headers)
        {
            if (IsChunked(headers)) return BodyFraming.Chunked;
            string cl = headers.First("Content-Length");
            if (cl == null) return BodyFraming.None;
            return BodyFraming.OfLength(ParseLength(cl, 400));
        }

        /// <summary>Réponse : HEAD, 1xx, 204, 304 → aucun corps ; chunked ; Content-Length ; sinon jusqu'à la fermeture.</summary>
        public static BodyFraming ResponseFraming(HttpHeaders headers, string requestMethod, int status)
        {
            if (string.Equals(requestMethod, "HEAD", StringComparison.OrdinalIgnoreCase) || status / 100 == 1 || status == 204 || status == 304) return BodyFraming.None;
            if (IsChunked(headers)) return BodyFraming.Chunked;
            string cl = headers.First("Content-Length");
            if (cl == null) return BodyFraming.UntilClose;
            return BodyFraming.OfLength(ParseLength(cl, 502));
        }

        private static bool IsChunked(HttpHeaders headers)
        {
            string te = headers.First("Transfer-Encoding");
            return te != null && te.Trim().EndsWith("chunked", StringComparison.OrdinalIgnoreCase);
        }

        private static long ParseLength(string text, int errorStatus)
        {
            long length;
            if (!long.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out length) || length < 0)
                throw new HttpProtocolException(errorStatus, "Content-Length invalide : " + text);
            return length;
        }

        /// <summary>`Connection: close` (jeton, insensible à la casse) ou HTTP/1.0 sans `keep-alive`.</summary>
        public static bool WantsClose(string version, HttpHeaders headers)
        {
            bool close = false, keepAlive = false;
            foreach (string value in headers.All("Connection"))
                foreach (string token in value.Split(','))
                {
                    string t = token.Trim();
                    if (string.Equals(t, "close", StringComparison.OrdinalIgnoreCase)) close = true;
                    if (string.Equals(t, "keep-alive", StringComparison.OrdinalIgnoreCase)) keepAlive = true;
                }
            if (close) return true;
            return string.Equals(version, "HTTP/1.0", StringComparison.Ordinal) && !keepAlive;
        }

        public static bool ExpectsContinue(HttpHeaders headers)
        {
            string e = headers.First("Expect");
            return e != null && string.Equals(e.Trim(), "100-continue", StringComparison.OrdinalIgnoreCase);
        }

        // ---- Corps bufferisé ---------------------------------------------

        public static async Task<BufferedBody> ReadBodyAsync(HttpConnection c, BodyFraming framing, int maxBuffered, CancellationToken cancel)
        {
            switch (framing.Kind)
            {
                case BodyFramingKind.ContentLength:
                    {
                        int take = (int)Math.Min(framing.Length, maxBuffered);
                        byte[] bytes = new byte[take];
                        await c.ReadExactAsync(bytes, 0, take, cancel).ConfigureAwait(false);
                        long remaining = framing.Length - take;
                        return new BufferedBody(bytes, remaining == 0, remaining, 0);
                    }
                case BodyFramingKind.Chunked:
                    return await ReadChunkedAsync(c, maxBuffered, cancel).ConfigureAwait(false);
                default:
                    return new BufferedBody(new byte[0], true, 0, 0);
            }
        }

        private static async Task<BufferedBody> ReadChunkedAsync(HttpConnection c, int maxBuffered, CancellationToken cancel)
        {
            MemoryStream ms = new MemoryStream();
            while (true)
            {
                long size = await ReadChunkSizeAsync(c, cancel).ConfigureAwait(false);
                if (size == 0)
                {
                    await SkipTrailersAsync(c, cancel).ConfigureAwait(false);
                    return new BufferedBody(ms.ToArray(), true, 0, 0);
                }
                long room = maxBuffered - ms.Length;
                if (size > room)
                {
                    if (room > 0) await CopyExactAsync(c, ms, room, cancel).ConfigureAwait(false);
                    return new BufferedBody(ms.ToArray(), false, 0, size - room);
                }
                await CopyExactAsync(c, ms, size, cancel).ConfigureAwait(false);
                await ReadChunkEndAsync(c, cancel).ConfigureAwait(false);
            }
        }

        private static async Task<long> ReadChunkSizeAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(1024, cancel).ConfigureAwait(false);
            if (line == null) throw new EndOfStreamException("flux fermé avant la fin du corps chunked");
            int semi = line.IndexOf(';');
            string hex = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
            long size;
            if (hex.Length == 0 || hex.Length > 15 || !long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out size))
                throw new HttpProtocolException(400, "taille de chunk invalide");
            return size;
        }

        private static async Task ReadChunkEndAsync(HttpConnection c, CancellationToken cancel)
        {
            string crlf = await c.ReadLineAsync(16, cancel).ConfigureAwait(false);
            if (crlf == null) throw new EndOfStreamException("flux fermé dans un chunk");
            if (crlf.Length != 0) throw new HttpProtocolException(400, "fin de chunk invalide");
        }

        private static async Task SkipTrailersAsync(HttpConnection c, CancellationToken cancel)
        {
            while (true)
            {
                string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                if (line == null) throw new EndOfStreamException("flux fermé dans les trailers");
                if (line.Length == 0) return;
            }
        }

        private static async Task CopyExactAsync(HttpConnection from, Stream to, long count, CancellationToken cancel)
        {
            byte[] block = new byte[RelayBlock];
            long left = count;
            while (left > 0)
            {
                int n = await from.ReadAsync(block, 0, (int)Math.Min(block.Length, left), cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("flux fermé, " + left + " octet(s) manquant(s)");
                await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                left -= n;
            }
        }

        // ---- Relais streaming ---------------------------------------------

        /// <summary>Relaie un corps entier sans le modifier, flush après chaque bloc ou chunk (SSE). Rend le nombre d'octets utiles.</summary>
        public static async Task<long> RelayBodyAsync(HttpConnection from, HttpConnection to, BodyFraming framing, CancellationToken cancel)
        {
            switch (framing.Kind)
            {
                case BodyFramingKind.ContentLength:
                    return await CopyBlocksAsync(from, to, framing.Length, true, cancel).ConfigureAwait(false);
                case BodyFramingKind.Chunked:
                    return await RelayChunkedVerbatimAsync(from, to, cancel).ConfigureAwait(false);
                case BodyFramingKind.UntilClose:
                    return await CopyBlocksAsync(from, to, long.MaxValue, false, cancel).ConfigureAwait(false);
                default:
                    return 0;
            }
        }

        private static async Task<long> CopyBlocksAsync(HttpConnection from, HttpConnection to, long count, bool exact, CancellationToken cancel)
        {
            byte[] block = new byte[RelayBlock];
            long done = 0;
            while (done < count)
            {
                int n = await from.ReadAsync(block, 0, (int)Math.Min(block.Length, count - done), cancel).ConfigureAwait(false);
                if (n == 0)
                {
                    if (exact) throw new EndOfStreamException("flux fermé après " + done + " octet(s) sur " + count);
                    break;
                }
                await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                await to.FlushAsync(cancel).ConfigureAwait(false);
                done += n;
            }
            return done;
        }

        private static async Task<long> RelayChunkedVerbatimAsync(HttpConnection from, HttpConnection to, CancellationToken cancel)
        {
            long total = 0;
            while (true)
            {
                string line = await from.ReadLineAsync(1024, cancel).ConfigureAwait(false);
                if (line == null) throw new EndOfStreamException("flux fermé avant la fin du corps chunked");
                int semi = line.IndexOf(';');
                string hex = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
                long size;
                if (hex.Length == 0 || hex.Length > 15 || !long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out size))
                    throw new HttpProtocolException(502, "taille de chunk amont invalide");
                await WriteLineAsync(to, line, cancel).ConfigureAwait(false);
                if (size == 0)
                {
                    while (true)
                    {
                        string trailer = await from.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                        if (trailer == null) throw new EndOfStreamException("flux fermé dans les trailers");
                        await WriteLineAsync(to, trailer, cancel).ConfigureAwait(false);
                        if (trailer.Length == 0) break;
                    }
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                    return total;
                }
                total += await CopyBlocksAsync(from, to, size, true, cancel).ConfigureAwait(false);
                string end = await from.ReadLineAsync(16, cancel).ConfigureAwait(false);
                if (end == null) throw new EndOfStreamException("flux fermé dans un chunk");
                if (end.Length != 0) throw new HttpProtocolException(502, "fin de chunk amont invalide");
                await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
                await to.FlushAsync(cancel).ConfigureAwait(false);
            }
        }

        /// <summary>Après un ReadBodyAsync incomplet : relaie le reste (Content-Length brut, ou chunks réémis), sans jamais le bufferiser.</summary>
        public static async Task RelayRemainderAsync(HttpConnection from, HttpConnection to, BodyFraming framing, BufferedBody partial, CancellationToken cancel)
        {
            if (framing.Kind == BodyFramingKind.ContentLength)
            {
                await CopyBlocksAsync(from, to, partial.Remaining, true, cancel).ConfigureAwait(false);
                return;
            }
            if (framing.Kind != BodyFramingKind.Chunked) return;
            long pending = partial.ChunkRemaining;
            while (true)
            {
                if (pending > 0)
                {
                    await WriteLineAsync(to, pending.ToString("x", CultureInfo.InvariantCulture), cancel).ConfigureAwait(false);
                    await CopyBlocksAsync(from, to, pending, true, cancel).ConfigureAwait(false);
                    await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                    await ReadChunkEndAsync(from, cancel).ConfigureAwait(false);
                }
                pending = await ReadChunkSizeAsync(from, cancel).ConfigureAwait(false);
                if (pending == 0)
                {
                    await SkipTrailersAsync(from, cancel).ConfigureAwait(false);
                    await WriteLastChunkAsync(to, cancel).ConfigureAwait(false);
                    return;
                }
            }
        }

        public static async Task WriteChunkAsync(HttpConnection to, byte[] data, int offset, int count, CancellationToken cancel)
        {
            if (count == 0) return;
            await WriteLineAsync(to, count.ToString("x", CultureInfo.InvariantCulture), cancel).ConfigureAwait(false);
            await to.WriteAsync(data, offset, count, cancel).ConfigureAwait(false);
            await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
        }

        public static async Task WriteLastChunkAsync(HttpConnection to, CancellationToken cancel)
        {
            byte[] last = Latin1.GetBytes("0\r\n\r\n");
            await to.WriteAsync(last, 0, last.Length, cancel).ConfigureAwait(false);
            await to.FlushAsync(cancel).ConfigureAwait(false);
        }

        private static async Task WriteLineAsync(HttpConnection to, string line, CancellationToken cancel)
        {
            byte[] bytes = Latin1.GetBytes(line + "\r\n");
            await to.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }
    }
}
```

- [ ] **Step 6: Sources + vert**

`IRISKIT_SOURCES` (les deux `.bat`) : ajouter `"%SRC%\IrisKit\Proxy\HttpMessage.cs" "%SRC%\IrisKit\Proxy\HttpConnection.cs" "%SRC%\IrisKit\Proxy\HttpParser.cs"`.

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
```

Attendu : `73 test(s) réussi(s), 0 échec(s)`. Si le test de délai dépasse 200 ms de beaucoup : `Task.Delay` a une granularité de ~15 ms, normal ; ne pas raccourcir sous 100 ms.

- [ ] **Step 7: Commit**

```bash
git add src/IrisKit/Proxy tests/HttpParserTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): HTTP/1.1 — HttpHeaders, HttpConnection bufferisée, HttpParser (têtes, chunked, relais streaming)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 2: Placeholders — `PlaceholderScanner`, `SlidingMinuteCounter`, `PlaceholderEngine`

**Files:**
- Create: `src\IrisKit\Placeholder\PlaceholderHit.cs`, `src\IrisKit\Placeholder\PlaceholderScanner.cs`, `src\IrisKit\Placeholder\SlidingMinuteCounter.cs`, `src\IrisKit\Placeholder\PlaceholderEngine.cs`
- Create: `tests\PlaceholderTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `HttpHeaders` (tâche 1), `ISecretStore`, `SecretStoreException`, `SecretCache`, `InMemorySecretStore`, `AlertLocation` (phase 1).
- Produces: `HitLocationKind { Header, UrlPath, QueryString, Body }` ; `HitLocation` (`Kind`, `HeaderName` minuscule ou null, `static Header(string)`, `static readonly UrlPath / QueryString / Body`, `ToAlertLocation() : AlertLocation`, `Describe() : string` (`header(x-api-key)`, `path`, `query`, `body`), égalité par valeur) ; `PlaceholderHit(name, location, snippet)` (`Name`, `Location`, `Snippet`) ; `PlaceholderScanner` statique (`PatternText`, `Pattern : Regex`, `SnippetMaxLength = 256`, `SnippetContextChars = 80`, `Scan(HttpHeaders headers, string uri, string body) : IList<PlaceholderHit>` (body null = absent ou non UTF-8), `SplitUri(string uri, out string path, out string query)` (query null sans `?`), `FindPlaceholderNames(string) : IList<string>` (distincts, ordre d'apparition)) ; `SlidingMinuteCounter` (`Record(DateTime)`, `Count(DateTime) : int`, fenêtre inclusive `[now-60 s, now]`) ; `ResolvedPayload` (`Headers : HttpHeaders`, `Uri`, `Body : byte[]`, `Substituted : IList<string>` trié, `Unresolved : IList<string>` trié) ; `PlaceholderEngine(ISecretStore)` avec `SubstituteAsync(HttpHeaders, string uri, byte[] body, IList<PlaceholderHit> resolvable) : Task<ResolvedPayload>`.

- [ ] **Step 1: Écrire `tests\PlaceholderTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Placeholders --------------------------------------------------

        private static HttpHeaders H(params string[] pairs)
        {
            HttpHeaders h = new HttpHeaders();
            for (int i = 0; i + 1 < pairs.Length; i += 2) h.Add(pairs[i], pairs[i + 1]);
            return h;
        }

        private static string Names(IList<PlaceholderHit> hits)
        {
            List<string> names = new List<string>();
            foreach (PlaceholderHit h in hits) names.Add(h.Name);
            return string.Join(",", names);
        }

        private static void Scanner_Locations()
        {
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}"), "/v1/messages", null);
            Check.Eq(1, hits.Count, "un hit");
            Check.Eq("foo", hits[0].Name, "nom");
            Check.True(hits[0].Location.Equals(HitLocation.Header("authorization")), "en-tête, nom en minuscules");
            Check.Eq(AlertLocation.Header, hits[0].Location.ToAlertLocation(), "→ AlertLocation.Header");
            hits = PlaceholderScanner.Scan(H("X-{{kc:foo}}", "bar"), "/", null);
            Check.True(hits.Count == 1 && hits[0].Location.HeaderName.Contains("{{kc:foo}}"), "placeholder dans un nom d'en-tête");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/foo/{{kc:bar}}/baz", null);
            Check.True(hits.Count == 1 && hits[0].Location.Kind == HitLocationKind.UrlPath, "chemin");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/foo?key={{kc:bar}}", null);
            Check.True(hits.Count == 1 && hits[0].Location.Equals(HitLocation.QueryString), "query");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", "{\"key\":\"{{kc:bar}}\"}");
            Check.True(hits.Count == 1 && hits[0].Location.Equals(HitLocation.Body), "corps");
            hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}"), "/foo?x={{kc:foo}}", null);
            Check.Eq("foo,foo", Names(hits), "même secret à deux endroits = deux hits");
            hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}}", "X-Other", "{{kc:bar}}"), "/", null);
            Check.Eq("foo,bar", Names(hits), "deux secrets distincts, ordre des en-têtes");
            hits = PlaceholderScanner.Scan(H("X-API-KEY", "{{kc:foo}}"), "/", null);
            Check.Eq("x-api-key", hits[0].Location.HeaderName, "nom d'en-tête en minuscules dans la localisation");
            Check.Eq("header(x-api-key)", hits[0].Location.Describe(), "Describe");
            string path, query;
            PlaceholderScanner.SplitUri("/a/b?c=1&d=2", out path, out query);
            Check.True(path == "/a/b" && query == "c=1&d=2", "SplitUri");
            PlaceholderScanner.SplitUri("/a", out path, out query);
            Check.True(path == "/a" && query == null, "SplitUri sans query");
            Check.Eq("a,b,c", string.Join(",", PlaceholderScanner.FindPlaceholderNames("{{kc:a}}-{{kc:b}}-{{kc:a}}-{{kc:c}}")), "FindPlaceholderNames : distincts, ordonnés");
            Check.Eq("ok", string.Join(",", PlaceholderScanner.FindPlaceholderNames("{{kc:}}-{{kc:has space}}-{kc:foo}}-{{kc:ok}}")), "malformés ignorés");
        }

        private static void Scanner_InvalidNamesAndSnippets()
        {
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:}}"), "/", null).Count, "nom vide ignoré");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:" + new string('a', 65) + "}}"), "/", null).Count, "nom de 65 caractères ignoré");
            Check.Eq(1, PlaceholderScanner.Scan(H("X", "{{kc:" + new string('a', 64) + "}}"), "/", null).Count, "nom de 64 caractères accepté");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{KC:foo}}"), "/", null).Count, "préfixe sensible à la casse");
            Check.Eq(0, PlaceholderScanner.Scan(H("X", "{{kc:\u0430\u0501\u200Bname}}"), "/", null).Count, "lettres non ASCII refusées");
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(H("Authorization", "Bearer {{kc:foo}} suffix"), "/", null);
            Check.True(hits[0].Snippet.Contains("{{kc:foo}}") && hits[0].Snippet.Length <= 256, "snippet contient le placeholder littéral, ≤ 256");
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", "\u0001\u0007prefix {{kc:foo}} suffix\u007F");
            Check.True(!hits[0].Snippet.Contains("\u0001") && !hits[0].Snippet.Contains("\u0007") && !hits[0].Snippet.Contains("\u007F") && hits[0].Snippet.Contains("?") && hits[0].Snippet.Contains("{{kc:foo}}"), "caractères de contrôle remplacés par ?");
            string longBody = new string('x', 500) + "{{kc:foo}}" + new string('y', 500);
            hits = PlaceholderScanner.Scan(new HttpHeaders(), "/", longBody);
            Check.True(hits[0].Snippet.Length <= 256 && hits[0].Snippet.StartsWith("xxxx") && hits[0].Snippet.Contains("{{kc:foo}}"), "80 caractères de contexte de chaque côté");
            hits = PlaceholderScanner.Scan(H("X", "{{kc:{{kc:foo}}}}"), "/", null);
            Check.Eq("foo", Names(hits), "imbriqué : seul le motif interne valide");
            hits = PlaceholderScanner.Scan(H("X", "{{ {{kc {{kc: kc:x}} }}}} {{"), "/", null);
            Check.Eq(0, hits.Count, "accolades déséquilibrées : rien");
        }

        private static void Counter_SlidingMinute()
        {
            SlidingMinuteCounter c = new SlidingMinuteCounter();
            DateTime t0 = new DateTime(2026, 10, 17, 12, 0, 0, DateTimeKind.Utc);
            Check.Eq(0, c.Count(t0), "vide");
            c.Record(t0);
            Check.Eq(1, c.Count(t0), "un enregistrement");
            Check.Eq(1, c.Count(t0.AddSeconds(59)), "gardé à 59 s");
            Check.Eq(1, c.Count(t0.AddSeconds(60)), "gardé à 60 s (fenêtre inclusive)");
            Check.Eq(0, c.Count(t0.AddMilliseconds(60001)), "retiré juste après");
            c = new SlidingMinuteCounter();
            c.Record(t0); c.Record(t0.AddSeconds(30)); c.Record(t0.AddSeconds(60));
            Check.Eq(3, c.Count(t0.AddSeconds(60)), "trois dans la fenêtre");
            Check.Eq(2, c.Count(t0.AddSeconds(61)), "t0 expiré");
            Check.Eq(1, c.Count(t0.AddSeconds(91)), "t0+30 expiré");
            Check.Eq(0, c.Count(t0.AddSeconds(121)), "tout expiré");
        }

        private static InMemorySecretStore StoreWith(params string[] nameValuePairs)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            for (int i = 0; i + 1 < nameValuePairs.Length; i += 2)
                Wait(store.AddAsync(nameValuePairs[i], Bytes(nameValuePairs[i + 1]), new[] { "example.com" }, T0));
            return store;
        }

        private static PlaceholderHit Hit(string name, HitLocation location) { return new PlaceholderHit(name, location, ""); }

        private static void Engine_SubstitutesOnlyAuthorized()
        {
            PlaceholderEngine engine = new PlaceholderEngine(StoreWith("foo", "VALUE_FOO", "bar", "VALUE_BAR"));
            ResolvedPayload p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:foo}}", "X-Other", "{{kc:bar}}"), "/v1/messages", null,
                new[] { Hit("foo", HitLocation.Header("authorization")) }));
            Check.Eq("foo", string.Join(",", p.Substituted), "seul foo est substitué");
            Check.Eq("Bearer VALUE_FOO", p.Headers.First("Authorization"), "valeur substituée");
            Check.Eq("{{kc:bar}}", p.Headers.First("X-Other"), "bar non autorisé reste littéral");
            Check.True(p.Body == null, "corps absent inchangé");
            p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:foo}}"), "/v1", null, new PlaceholderHit[0]));
            Check.True(p.Substituted.Count == 0 && p.Headers.First("Authorization") == "Bearer {{kc:foo}}", "sans hit autorisé : verbatim");
            p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:k}}", "X-Echo", "{{kc:k}}"), "/x?t={{kc:k}}", Bytes("{\"t\":\"{{kc:k}}\"}"),
                new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.True(p.Substituted.Count == 0 && p.Unresolved.Count == 1 && p.Unresolved[0] == "k", "nom inconnu → Unresolved, rien substitué");
        }

        private static void Engine_AllOccurrencesBodyUriAndCache()
        {
            InMemorySecretStore inner = StoreWith("k", "V");
            SecretCache cached = new SecretCache(inner);
            PlaceholderEngine engine = new PlaceholderEngine(cached);
            ResolvedPayload p = Wait(engine.SubstituteAsync(H("Authorization", "Bearer {{kc:k}}", "X-Echo", "{{kc:k}}"), "/x?t={{kc:k}}", Bytes("{\"t\":\"{{kc:k}}\"}"),
                new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.Eq("k", string.Join(",", p.Substituted), "signalé une fois malgré quatre occurrences");
            Check.Eq("Bearer V", p.Headers.First("Authorization"), "en-tête 1");
            Check.Eq("V", p.Headers.First("X-Echo"), "en-tête 2");
            Check.Eq("/x?t=V", p.Uri, "URI");
            Check.Eq("{\"t\":\"V\"}", Encoding.UTF8.GetString(p.Body), "corps");
            Wait(inner.RotateAsync("k", Bytes("V2")));
            p = Wait(engine.SubstituteAsync(H("Authorization", "{{kc:k}}"), "/", null, new[] { Hit("k", HitLocation.Header("authorization")) }));
            Check.Eq("V", p.Headers.First("Authorization"), "le cache sert la valeur résolue dans le TTL (rotation faite sous le cache)");
            byte[] body = new byte[] { 0x00, 0xff, 0x01 };
            p = Wait(engine.SubstituteAsync(H("x-api-key", "{{kc:k}}"), "/", body, new[] { Hit("k", HitLocation.Header("x-api-key")) }));
            Check.Eq(Convert.ToBase64String(body), Convert.ToBase64String(p.Body), "corps non UTF-8 jamais réécrit");
            Check.Eq("V", p.Headers.First("x-api-key"), "mais l'en-tête est substitué");
            InMemorySecretStore bin = new InMemorySecretStore();
            Wait(bin.AddAsync("binkey", new byte[] { 0xFF, 0xFE, 0xFD, 0xFC }, new[] { "api.x" }, T0));
            p = Wait(new PlaceholderEngine(bin).SubstituteAsync(H("Authorization", "Bearer {{kc:binkey}}"), "/", null, new[] { Hit("binkey", HitLocation.Header("authorization")) }));
            Check.True(p.Substituted.Count == 0 && p.Unresolved.Count == 1 && p.Unresolved[0] == "binkey" && p.Headers.First("Authorization") == "Bearer {{kc:binkey}}", "valeur non UTF-8 → Unresolved, placeholder intact");
            p = Wait(engine.SubstituteAsync(H("Authorization", "é {{kc:k}} ✓"), "/", Bytes("héllo {{kc:k}}"), new[] { Hit("k", HitLocation.Body) }));
            Check.True(p.Headers.First("Authorization") == "é V ✓" && Encoding.UTF8.GetString(p.Body) == "héllo V", "texte non ASCII autour conservé");
        }
    }
}
```

`Main` : `Check.Run("Scanner : emplacements", Scanner_Locations); Check.Run("Scanner : noms invalides et snippets", Scanner_InvalidNamesAndSnippets); Check.Run("Compteur : fenêtre glissante inclusive", Counter_SlidingMinute); Check.Run("Engine : substitue seulement les hits autorisés", Engine_SubstitutesOnlyAuthorized); Check.Run("Engine : toutes les occurrences, corps, URI, cache, non UTF-8", Engine_AllOccurrencesBodyUriAndCache);` — `TEST_SOURCES` : ajouter `"%TESTS%\PlaceholderTests.cs"`.

Note : `Wait<T>`, `Bytes`, `T0` existent déjà (`tests\SecretStoreTests.cs`, `tests\ModelsTests.cs`) ; `Wait(Task)` non générique vient de la tâche 1.

- [ ] **Step 2: Vérifier l'échec** — `cmd //c 'D:\Dev\irispc\test.bat' 2>&1 | grep -E 'error CS' | head -2` → `CS0246 'PlaceholderHit'` / `'PlaceholderScanner'`.

- [ ] **Step 3: Écrire `src\IrisKit\Placeholder\PlaceholderHit.cs`**

```csharp
using System;

namespace IrisKit
{
    public enum HitLocationKind { Header, UrlPath, QueryString, Body }

    /// <summary>Emplacement d'un placeholder dans la requête. Pour un en-tête, le nom est en minuscules (RFC 7230 §3.2).</summary>
    public sealed class HitLocation : IEquatable<HitLocation>
    {
        public HitLocationKind Kind { get; private set; }
        public string HeaderName { get; private set; }

        private HitLocation(HitLocationKind kind, string headerName) { Kind = kind; HeaderName = headerName; }

        public static HitLocation Header(string name) { return new HitLocation(HitLocationKind.Header, (name ?? "").ToLowerInvariant()); }
        public static readonly HitLocation UrlPath = new HitLocation(HitLocationKind.UrlPath, null);
        public static readonly HitLocation QueryString = new HitLocation(HitLocationKind.QueryString, null);
        public static readonly HitLocation Body = new HitLocation(HitLocationKind.Body, null);

        public AlertLocation ToAlertLocation()
        {
            switch (Kind)
            {
                case HitLocationKind.Header: return AlertLocation.Header;
                case HitLocationKind.UrlPath: return AlertLocation.UrlPath;
                case HitLocationKind.QueryString: return AlertLocation.QueryString;
                default: return AlertLocation.Body;
            }
        }

        /// <summary>Libellé sans valeur pour le journal de diagnostic (le nom d'en-tête est une métadonnée, jamais un secret).</summary>
        public string Describe()
        {
            switch (Kind)
            {
                case HitLocationKind.Header: return "header(" + HeaderName + ")";
                case HitLocationKind.UrlPath: return "path";
                case HitLocationKind.QueryString: return "query";
                default: return "body";
            }
        }

        public bool Equals(HitLocation other)
        {
            return other != null && other.Kind == Kind && string.Equals(other.HeaderName, HeaderName, StringComparison.Ordinal);
        }

        public override bool Equals(object obj) { return Equals(obj as HitLocation); }
        public override int GetHashCode() { return ((int)Kind * 397) ^ (HeaderName == null ? 0 : HeaderName.GetHashCode()); }
        public override string ToString() { return Describe(); }
    }

    /// <summary>Un placeholder trouvé : nom, emplacement, extrait de contexte (avant substitution, jamais une valeur).</summary>
    public sealed class PlaceholderHit
    {
        public string Name { get; private set; }
        public HitLocation Location { get; private set; }
        public string Snippet { get; private set; }

        public PlaceholderHit(string name, HitLocation location, string snippet)
        {
            Name = name; Location = location; Snippet = snippet ?? "";
        }
    }
}
```

- [ ] **Step 4: Écrire `src\IrisKit\Placeholder\PlaceholderScanner.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace IrisKit
{
    /// <summary>Scan des placeholders `{{kc:NAME}}` (SPECS §7.1–7.2) dans les noms et valeurs d'en-têtes, le chemin, la query et le corps.</summary>
    public static class PlaceholderScanner
    {
        public const string PatternText = @"\{\{kc:([a-zA-Z0-9_-]{1,64})\}\}";
        public static readonly Regex Pattern = new Regex(PatternText, RegexOptions.CultureInvariant);
        /// <summary>Plafond du snippet ; avec 80 caractères de contexte et un nom ≤ 64 le pire cas fait ≈ 233, le plafond est une défense en profondeur.</summary>
        public const int SnippetMaxLength = 256;
        public const int SnippetContextChars = 80;

        /// <summary>body = null quand le corps est absent, trop grand ou non UTF-8 : le scanner ne décode jamais lui-même.</summary>
        public static IList<PlaceholderHit> Scan(HttpHeaders headers, string uri, string body)
        {
            List<PlaceholderHit> hits = new List<PlaceholderHit>();
            foreach (HttpHeader h in headers)
            {
                HitLocation location = HitLocation.Header(h.Name);
                hits.AddRange(ScanString(h.Name, location));
                hits.AddRange(ScanString(h.Value, location));
            }
            string path, query;
            SplitUri(uri ?? "", out path, out query);
            hits.AddRange(ScanString(path, HitLocation.UrlPath));
            if (query != null) hits.AddRange(ScanString(query, HitLocation.QueryString));
            if (body != null) hits.AddRange(ScanString(body, HitLocation.Body));
            return hits;
        }

        internal static IList<PlaceholderHit> ScanString(string text, HitLocation location)
        {
            List<PlaceholderHit> hits = new List<PlaceholderHit>();
            if (string.IsNullOrEmpty(text)) return hits;
            foreach (Match m in Pattern.Matches(text))
                hits.Add(new PlaceholderHit(m.Groups[1].Value, location, MakeSnippet(text, m.Index, m.Length)));
            return hits;
        }

        public static void SplitUri(string uri, out string path, out string query)
        {
            int q = uri.IndexOf('?');
            if (q < 0) { path = uri; query = null; return; }
            path = uri.Substring(0, q);
            query = uri.Substring(q + 1);
        }

        /// <summary>80 caractères de contexte de chaque côté, caractères de contrôle ASCII → '?', plafond 256 avec '…'.</summary>
        internal static string MakeSnippet(string text, int start, int length)
        {
            int from = Math.Max(0, start - SnippetContextChars);
            int to = Math.Min(text.Length, start + length + SnippetContextChars);
            StringBuilder sb = new StringBuilder(to - from);
            for (int i = from; i < to; i++)
            {
                char c = text[i];
                sb.Append(c < 0x20 || c == 0x7F ? '?' : c);
            }
            if (sb.Length > SnippetMaxLength) return sb.ToString(0, SnippetMaxLength - 1) + "\u2026";
            return sb.ToString();
        }

        /// <summary>Noms distincts dans l'ordre d'apparition (utilisé par le lot CLI / mcp wrap).</summary>
        public static IList<string> FindPlaceholderNames(string text)
        {
            List<string> order = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(text)) return order;
            foreach (Match m in Pattern.Matches(text))
            {
                string name = m.Groups[1].Value;
                if (seen.Add(name)) order.Add(name);
            }
            return order;
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Placeholder\SlidingMinuteCounter.cs`**

```csharp
using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Compteur sur fenêtre glissante inclusive de 60 s (R5). Non thread-safe : l'appelant verrouille.</summary>
    public sealed class SlidingMinuteCounter
    {
        private readonly List<DateTime> stamps = new List<DateTime>();

        public void Record(DateTime now)
        {
            Prune(now);
            stamps.Add(now);
        }

        public int Count(DateTime now)
        {
            Prune(now);
            return stamps.Count;
        }

        /// <summary>Garde les instants t tels que now-60 s ≤ t ≤ now.</summary>
        private void Prune(DateTime now)
        {
            DateTime cutoff = now.AddSeconds(-60);
            stamps.RemoveAll(delegate(DateTime t) { return t < cutoff; });
        }
    }
}
```

- [ ] **Step 6: Écrire `src\IrisKit\Placeholder\PlaceholderEngine.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Résultat d'une substitution : requête réécrite, noms substitués, noms non résolus (inconnus ou valeur non UTF-8).</summary>
    public sealed class ResolvedPayload
    {
        public HttpHeaders Headers { get; private set; }
        public string Uri { get; private set; }
        public byte[] Body { get; private set; }
        public IList<string> Substituted { get; private set; }
        public IList<string> Unresolved { get; private set; }

        public ResolvedPayload(HttpHeaders headers, string uri, byte[] body, IList<string> substituted, IList<string> unresolved)
        {
            Headers = headers; Uri = uri; Body = body; Substituted = substituted; Unresolved = unresolved;
        }
    }

    /// <summary>
    /// Substitution par nom des hits déjà autorisés par ExfilRuleEngine (R1/R2 passés pour chaque nom : toute occurrence
    /// du nom est donc légitime). Octet pour octet sur l'UTF-8 ; un corps non UTF-8 n'est jamais réécrit ; une valeur de
    /// secret non UTF-8 est signalée dans Unresolved (échec visible plutôt que silencieux).
    /// </summary>
    public sealed class PlaceholderEngine
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private readonly ISecretStore secrets;

        public PlaceholderEngine(ISecretStore secrets)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
        }

        public async Task<ResolvedPayload> SubstituteAsync(HttpHeaders headers, string uri, byte[] body, IList<PlaceholderHit> resolvable)
        {
            if (resolvable == null || resolvable.Count == 0)
                return new ResolvedPayload(headers, uri, body, new List<string>(), new List<string>());

            SortedSet<string> names = new SortedSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in resolvable) names.Add(hit.Name);

            Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.Ordinal);
            List<string> unresolved = new List<string>();
            foreach (string name in names)
            {
                byte[] raw;
                try { raw = await secrets.ValueAsync(name).ConfigureAwait(false); }
                catch (SecretStoreException ex)
                {
                    if (ex.Kind != SecretStoreErrorKind.UnknownSecret) throw;
                    unresolved.Add(name);
                    continue;
                }
                try { values[name] = StrictUtf8.GetString(raw); }
                catch (DecoderFallbackException) { unresolved.Add(name); }
                finally { Array.Clear(raw, 0, raw.Length); }
            }

            SortedSet<string> substituted = new SortedSet<string>(StringComparer.Ordinal);
            Func<string, string> mutate = delegate(string input)
            {
                string result = input;
                foreach (KeyValuePair<string, string> kv in values)
                {
                    string needle = "{{kc:" + kv.Key + "}}";
                    if (result.IndexOf(needle, StringComparison.Ordinal) < 0) continue;
                    result = result.Replace(needle, kv.Value);
                    substituted.Add(kv.Key);
                }
                return result;
            };

            HttpHeaders newHeaders = new HttpHeaders();
            foreach (HttpHeader h in headers) newHeaders.Add(mutate(h.Name), mutate(h.Value));
            string newUri = mutate(uri);
            byte[] newBody = body;
            if (body != null)
            {
                string text = null;
                try { text = StrictUtf8.GetString(body); }
                catch (DecoderFallbackException) { }
                if (text != null)
                {
                    string transformed = mutate(text);
                    if (!ReferenceEquals(transformed, text) && transformed != text) newBody = StrictUtf8.GetBytes(transformed);
                }
            }
            return new ResolvedPayload(newHeaders, newUri, newBody, new List<string>(substituted), unresolved);
        }
    }
}
```

- [ ] **Step 7: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Placeholder\PlaceholderHit.cs" "%SRC%\IrisKit\Placeholder\PlaceholderScanner.cs" "%SRC%\IrisKit\Placeholder\SlidingMinuteCounter.cs" "%SRC%\IrisKit\Placeholder\PlaceholderEngine.cs"`. → `78 test(s) réussi(s)`.

- [ ] **Step 8: Commit**

```bash
git add src/IrisKit/Placeholder tests/PlaceholderTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): PlaceholderScanner, SlidingMinuteCounter et PlaceholderEngine (port d'IRIS)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: `ExfilRuleEngine` (R1–R5, quarantaine) et fuzzing du scanner

**Files:**
- Create: `src\IrisKit\Placeholder\ExfilRuleEngine.cs`
- Create: `tests\ExfilTests.cs`, `tests\FuzzTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `PlaceholderHit`, `HitLocation`, `PlaceholderScanner`, `PlaceholderEngine`, `SlidingMinuteCounter` (tâche 2), `ISecretStore`, `Secret`, `Alert`, `Event`, `HostName`, `Log`, `Json` (phase 1).
- Produces: `RequestContext(host, method, path, contentType)` (`Host`, `Method`, `Path`, `ContentType` nullable) ; `ExfilDecision` (`Blocked : bool`, `Alert`, `Resolvable : IList<PlaceholderHit>`, `AllHits : IList<PlaceholderHit>`, `static Allow(resolvable)`, `static Block(alert, allHits)`) ; `ExfilRuleEngine(ISecretStore secrets, Func<int> maxSubstitutionsPerMinute, Func<DateTime> clock)` avec `EvaluateAsync(IList<PlaceholderHit>, RequestContext) : Task<ExfilDecision>`, `RecordSubstitution(IEnumerable<string> names)`, `static readonly string[] CanonicalAuthHeaders`, `SuspiciousContentTypes`, `SuspiciousPathFragments`.

- [ ] **Step 1: Écrire `tests\ExfilTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- ExfilRuleEngine --------------------------------------------------

        private static DateTime exfilNow;

        private static ExfilRuleEngine Evaluator(int maxPerMinute, params string[] nameHostPairs)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            for (int i = 0; i + 1 < nameHostPairs.Length; i += 2)
                Wait(store.AddAsync(nameHostPairs[i], Bytes("v"), nameHostPairs[i + 1].Split('|'), T0));
            exfilNow = T0;
            return new ExfilRuleEngine(store, delegate { return maxPerMinute; }, delegate { return exfilNow; });
        }

        private static RequestContext Ctx(string host, string method, string path, string contentType)
        {
            return new RequestContext(host, method, path, contentType);
        }

        private static RequestContext CtxAnthropic() { return Ctx("api.anthropic.com", "POST", "/v1/messages", "application/json"); }

        private static ExfilDecision Eval(ExfilRuleEngine ev, RequestContext ctx, params PlaceholderHit[] hits)
        {
            return Wait(ev.EvaluateAsync(hits, ctx));
        }

        private static void Exfil_R1_HostMismatch()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com");
            PlaceholderHit hit = new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}");
            ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", "/v1/messages", "application/json"), hit);
            Check.True(d.Blocked, "hôte hors allowed_hosts → bloqué");
            Check.Eq(ExfilRule.HostMismatch, d.Alert.Rule, "R1");
            Check.Eq(AlertSeverity.High, d.Alert.Severity, "high");
            Check.Eq("foo", d.Alert.SecretName, "nom");
            Check.Eq(AlertLocation.Header, d.Alert.DetectedAt, "emplacement");
            Check.Eq("{{kc:foo}}", d.Alert.Snippet, "snippet du hit");
            Check.Eq(1, d.AllHits.Count, "tous les hits rendus");
            d = Eval(ev, CtxAnthropic(), hit);
            Check.True(!d.Blocked && d.Resolvable.Count == 1 && d.Resolvable[0].Name == "foo", "hôte autorisé → résoluble");
            d = Eval(ev, Ctx("api.anthropic.com:443", "POST", "/v1/messages", null), hit);
            Check.True(!d.Blocked, "port retiré avant comparaison");
            d = Eval(ev, Ctx("API.Anthropic.com", "POST", "/v1/messages", null), hit);
            Check.True(!d.Blocked, "comparaison insensible à la casse");
            d = Eval(Evaluator(60), CtxAnthropic(), new PlaceholderHit("ghost", HitLocation.Header("authorization"), "{{kc:ghost}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "secret inconnu : ni bloqué ni résoluble");
            d = Eval(ev, CtxAnthropic());
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "aucun hit → allow vide");
        }

        private static void Exfil_R2_NonCanonicalLocation()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com");
            ExfilDecision d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Header("x-custom"), "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.Severity == AlertSeverity.High, "en-tête non canonique");
            foreach (string header in new[] { "authorization", "x-api-key", "api-key", "x-auth-token", "X-API-Key", "AUTHORIZATION" })
            {
                d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Header(header), "{{kc:foo}}"));
                Check.True(!d.Blocked, header + " est canonique (insensible à la casse)");
            }
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.UrlPath, "/{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.DetectedAt == AlertLocation.UrlPath, "chemin");
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.QueryString, "?x={{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.DetectedAt == AlertLocation.QueryString, "query");
            d = Eval(ev, Ctx("api.anthropic.com", "GET", "/v1/messages", "application/json"), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation, "corps sur GET");
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation, "corps JSON sur POST vers l'hôte autorisé : bloqué (A2)");
        }

        private static void Exfil_R3_MultipleSecrets()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com", "bar", "api.anthropic.com");
            ExfilDecision d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("bar", HitLocation.Header("x-api-key"), "{{kc:bar}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.MultipleSecrets && d.Alert.Severity == AlertSeverity.Medium, "deux secrets connus distincts");
            Check.Eq("bar", d.Alert.SecretName, "nom déclencheur = premier par ordre alphabétique");
            Check.Eq("foo,bar", Names(d.AllHits), "tous les hits dans l'ordre");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("foo", HitLocation.Header("x-api-key"), "{{kc:foo}}"));
            Check.True(!d.Blocked, "même nom deux fois : pas R3");
            ev = Evaluator(60, "foo", "api.anthropic.com");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("ghost", HitLocation.Header("x-api-key"), "{{kc:ghost}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "foo", "un connu + un inconnu : pas R3, seul le connu est résoluble");
        }

        private static void Exfil_R4_BehindR2()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.github.com");
            foreach (string[] c in new[] {
                new[] { "/repos/x/y/issues", "text/plain" }, new[] { "/comments/123", "application/x-www-form-urlencoded" },
                new[] { "/repos/x/y/blob/main", "multipart/form-data" }, new[] { "/issues", "text/plain; charset=utf-8" },
                new[] { "/issues", null }, new[] { "/v1/complete", "text/plain" }, new[] { "/issues", "application/json" } })
            {
                ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", c[0], c[1]), new PlaceholderHit("foo", HitLocation.Body, "{{kc:foo}}"));
                Check.True(d.Blocked && d.Alert.Rule == ExfilRule.NonCanonicalLocation && d.Alert.DetectedAt == AlertLocation.Body, "corps connu → R2 préempte R4 : " + c[0] + " " + c[1]);
            }
            ExfilDecision allow = Eval(ev, Ctx("api.github.com", "POST", "/issues", "text/plain"), new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"));
            Check.True(!allow.Blocked, "sans hit dans le corps, R4 ne tire pas");
            allow = Eval(ev, Ctx("api.github.com", "POST", "/issues", "text/plain"), new PlaceholderHit("ghost", HitLocation.Body, "{{kc:ghost}}"));
            Check.True(!allow.Blocked, "nom inconnu dans un corps suspect : rien (R2 et R4 clés sur les connus)");
        }

        private static void Exfil_R5_VolumeAnomaly()
        {
            ExfilRuleEngine ev = Evaluator(3, "foo", "api.anthropic.com");
            PlaceholderHit hit = new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}");
            for (int i = 0; i < 3; i++)
            {
                Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "substitution " + (i + 1) + " autorisée");
                ev.RecordSubstitution(new[] { "foo" });
            }
            ExfilDecision d = Eval(ev, CtxAnthropic(), hit);
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.VolumeAnomaly && d.Alert.Severity == AlertSeverity.Low && d.Alert.SecretName == "foo", "4e dans la minute → R5");
            exfilNow = T0.AddSeconds(61);
            Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "fenêtre glissée : de nouveau autorisé");
            ev = Evaluator(2, "foo", "api.anthropic.com");
            for (int i = 0; i < 5; i++) Eval(ev, Ctx("api.evil.com", "POST", "/", null), hit);
            Check.True(!Eval(ev, CtxAnthropic(), hit).Blocked, "les blocages R1 n'incrémentent pas R5");
        }

        private static void Exfil_CompositionAndQuarantine()
        {
            ExfilRuleEngine ev = Evaluator(60, "foo", "api.anthropic.com", "bar", "api.anthropic.com");
            ExfilDecision d = Eval(ev, Ctx("api.github.com", "POST", "/v1/messages", "application/json"),
                new PlaceholderHit("foo", HitLocation.Header("authorization"), "{{kc:foo}}"),
                new PlaceholderHit("bar", HitLocation.Header("x-api-key"), "{{kc:bar}}"));
            Check.True(d.Blocked && d.Alert.Rule == ExfilRule.HostMismatch && d.Alert.Severity == AlertSeverity.High && d.AllHits.Count == 2, "R1 gagne sur R3 (ordre = sévérité décroissante)");
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync("active", Bytes("v"), new[] { "api.anthropic.com" }, T0));
            Wait(store.AddAsync("quar", Bytes("v"), new[] { "api.anthropic.com" }, T0));
            Wait(store.SetQuarantinedAsync("quar", true));
            ev = new ExfilRuleEngine(store, delegate { return 60; }, delegate { return T0; });
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "en quarantaine sur hôte autorisé : non résoluble");
            d = Eval(ev, Ctx("api.github.com", "POST", "/", null), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && d.Resolvable.Count == 0, "en quarantaine sur hôte interdit : inerte, pas de R1");
            d = Eval(ev, CtxAnthropic(),
                new PlaceholderHit("active", HitLocation.Header("authorization"), "{{kc:active}}"),
                new PlaceholderHit("quar", HitLocation.Header("x-api-key"), "{{kc:quar}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "active", "quarantaine ne compte pas pour R3");
            Wait(store.SetQuarantinedAsync("quar", false));
            d = Eval(ev, CtxAnthropic(), new PlaceholderHit("quar", HitLocation.Header("authorization"), "{{kc:quar}}"));
            Check.True(!d.Blocked && Names(d.Resolvable) == "quar", "levée de quarantaine : de nouveau résoluble");
        }
    }
}
```

- [ ] **Step 2: Écrire `tests\FuzzTests.cs` (RED, même tâche)**

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>Une requête synthétique pour le pipeline scan → règles → substitution.</summary>
    public sealed class FuzzInput
    {
        public HttpHeaders Headers;
        public string Uri;
        public byte[] Body;
        public string Label;

        public FuzzInput(HttpHeaders headers, string uri, byte[] body, string label)
        {
            Headers = headers; Uri = uri; Body = body; Label = label;
        }
    }

    /// <summary>SplitMix64 : même graine → même corpus, aucun test instable.</summary>
    public sealed class SeededGenerator
    {
        private ulong state;
        public SeededGenerator(ulong seed) { state = seed; }

        public ulong Next()
        {
            state += 0x9E3779B97F4A7C15UL;
            ulong z = state;
            z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9UL;
            z = (z ^ (z >> 27)) * 0x94D049BB133111EBUL;
            return z ^ (z >> 31);
        }

        public int NextInt(int maxExclusive) { return (int)(Next() % (ulong)maxExclusive); }
    }

    /// <summary>Corpus adverse repris de ../Iris/Tests/IrisKitTests/Fuzzing/AdversarialInputGenerator.swift.</summary>
    public static class AdversarialInputGenerator
    {
        public const ulong Seed = 0xD1CE5EED17152026UL;
        public const string KnownSecretName = "leaky";
        public const string Sentinel = "SENTINEL_VALUE_DO_NOT_LEAK_7Q3Z";
        private const string CanonicalHeader = "x-api-key";
        private const string KnownPlaceholder = "{{kc:" + KnownSecretName + "}}";

        private static HttpHeaders Hdr(params string[] pairs)
        {
            HttpHeaders h = new HttpHeaders();
            for (int i = 0; i + 1 < pairs.Length; i += 2) h.Add(pairs[i], pairs[i + 1]);
            return h;
        }

        private static string Repeat(string s, int n) { StringBuilder sb = new StringBuilder(); for (int i = 0; i < n; i++) sb.Append(s); return sb.ToString(); }

        public static IList<FuzzInput> NamedCorpus()
        {
            return new List<FuzzInput> {
                new FuzzInput(Hdr(CanonicalHeader, "Bearer {{kc:" + new string('a', 65) + "}}"), "/v1/messages", null, "name-too-long"),
                new FuzzInput(Hdr(CanonicalHeader, "Bearer {{kc:" + new string('a', 64) + "}}"), "/v1/messages", null, "name-at-limit"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:}}"), "/v1/messages", null, "name-empty"),
                new FuzzInput(Hdr(CanonicalHeader, Repeat(KnownPlaceholder, 5000)), "/v1/messages", null, "thousands-occurrences"),
                new FuzzInput(Hdr(CanonicalHeader, "{{ {{kc {{kc: kc:x}} }}}} {{"), "/v1/messages", null, "unbalanced-braces"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:{{kc:" + KnownSecretName + "}}}}"), "/v1/messages", null, "nested-placeholder"),
                new FuzzInput(Hdr(CanonicalHeader, KnownPlaceholder), "/v1/messages", new byte[] { 0xFF, 0xFE, 0x00, 0x80, 0xC0, 0x01 }, "non-utf8-body"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:\u0000\u0001\u007F}}"), "/v1/\u0000messages", null, "control-chars"),
                new FuzzInput(Hdr(CanonicalHeader, "{{kc:\u0430\u0501\u200Bname}}"), "/v1/messages", null, "unicode-name"),
                new FuzzInput(Hdr("X-API-KEY", KnownPlaceholder, "AUTHORIZATION", KnownPlaceholder), "/v1/messages", null, "mixed-case-headers"),
            };
        }

        private static readonly string[] Fragments = {
            KnownPlaceholder, "{{kc:}}", "{{kc:" + new string('z', 70) + "}}", "{{kc", "kc:}}", "}}{{",
            "{{kc:{{kc:" + KnownSecretName + "}}}}", "{{kc:\u0000}}", "{{kc:\u200B\u0430}}", "{{KC:" + KnownSecretName + "}}",
            "{{kc:a-b_c}}", "  {{kc:" + KnownSecretName + "}}  ",
        };

        public static IList<FuzzInput> Generate(int count)
        {
            SeededGenerator gen = new SeededGenerator(Seed);
            List<FuzzInput> list = new List<FuzzInput>(count);
            for (int i = 0; i < count; i++)
            {
                string payload = Repeat(Fragments[gen.NextInt(Fragments.Length)], 1 + gen.NextInt(4));
                switch (gen.NextInt(5))
                {
                    case 0: list.Add(new FuzzInput(Hdr(CanonicalHeader, payload), "/v1/messages", null, "gen-" + i + "-canonical-header")); break;
                    case 1: list.Add(new FuzzInput(Hdr("x-custom-" + (i % 7), payload), "/v1/messages", null, "gen-" + i + "-random-header")); break;
                    case 2: list.Add(new FuzzInput(Hdr(), "/v1/" + payload + "/messages", null, "gen-" + i + "-url-path")); break;
                    case 3: list.Add(new FuzzInput(Hdr(), "/v1/messages?token=" + payload, null, "gen-" + i + "-query")); break;
                    default: list.Add(new FuzzInput(Hdr("content-type", "application/json"), "/v1/messages", Encoding.UTF8.GetBytes(payload), "gen-" + i + "-body")); break;
                }
            }
            return list;
        }
    }

    public static partial class TestMain
    {
        // ---- Fuzzing (I1 robustesse, I2 aucune valeur dans les events, I3 aucune substitution hors scope) ----

        private const int FuzzIterations = 2000;
        private static readonly UTF8Encoding FuzzUtf8 = new UTF8Encoding(false, true);

        private sealed class PipelineResult { public ExfilDecision Decision; public ResolvedPayload Payload; }

        private static InMemorySecretStore FuzzStore(params string[] allowedHosts)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync(AdversarialInputGenerator.KnownSecretName, Bytes(AdversarialInputGenerator.Sentinel), allowedHosts, T0));
            return store;
        }

        private static string BodyText(byte[] body)
        {
            if (body == null) return null;
            try { return FuzzUtf8.GetString(body); } catch (DecoderFallbackException) { return null; }
        }

        private static IList<FuzzInput> AllFuzzInputs()
        {
            List<FuzzInput> all = new List<FuzzInput>(AdversarialInputGenerator.NamedCorpus());
            all.AddRange(AdversarialInputGenerator.Generate(FuzzIterations));
            return all;
        }

        /// <summary>Le vrai pipeline, comme MITMHandler : scan → EvaluateAsync → SubstituteAsync.</summary>
        private static PipelineResult RunPipeline(FuzzInput input, InMemorySecretStore store, string host)
        {
            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(input.Headers, input.Uri, BodyText(input.Body));
            ExfilRuleEngine engine = new ExfilRuleEngine(store, delegate { return 100000; }, delegate { return T0; });
            string path, query;
            PlaceholderScanner.SplitUri(input.Uri, out path, out query);
            PipelineResult r = new PipelineResult();
            r.Decision = Wait(engine.EvaluateAsync(hits, new RequestContext(host, "POST", path, "application/json")));
            if (!r.Decision.Blocked)
                r.Payload = Wait(new PlaceholderEngine(store).SubstituteAsync(input.Headers, input.Uri, input.Body, r.Decision.Resolvable));
            return r;
        }

        private static void Fuzz_ScanBoundedAndPipelineNeverThrows()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            int n = 0;
            foreach (FuzzInput input in AllFuzzInputs())
            {
                string body = BodyText(input.Body);
                IList<PlaceholderHit> hits = PlaceholderScanner.Scan(input.Headers, input.Uri, body);
                int chars = input.Uri.Length + (body == null ? 0 : body.Length);
                foreach (HttpHeader h in input.Headers) chars += h.Name.Length + h.Value.Length;
                if (hits.Count > chars + 1) Check.True(false, "nombre de hits non borné pour " + input.Label);
                RunPipeline(input, store, "api.anthropic.com");
                n++;
            }
            Check.Eq(FuzzIterations + 10, n, "corpus complet parcouru sans exception");
        }

        private static void Fuzz_SentinelNeverInEncodedEvent()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            foreach (FuzzInput input in AllFuzzInputs())
            {
                PipelineResult r = RunPipeline(input, store, "api.anthropic.com");
                Event e;
                if (r.Decision.Blocked)
                    e = new Event(Guid.NewGuid(), T0, EventKind.ExfilBlocked, "api.anthropic.com", "POST", input.Uri, null, null, new string[0], r.Decision.Alert, null, EventFlags.None);
                else
                    e = new Event(Guid.NewGuid(), T0, r.Payload.Substituted.Count == 0 ? EventKind.NoMatch : EventKind.Substituted, "api.anthropic.com", "POST", input.Uri, null, null, r.Payload.Substituted, null, null, EventFlags.None);
                string json = Json.EmitCompact(e.ToJson());
                if (json.Contains(AdversarialInputGenerator.Sentinel)) Check.True(false, "la valeur sentinelle fuit dans l'event pour " + input.Label);
            }
            Check.True(true, "aucune fuite sur " + (FuzzIterations + 10) + " entrées");
        }

        private static void Fuzz_OutOfScopeNeverSubstituted()
        {
            InMemorySecretStore store = FuzzStore("api.anthropic.com");
            HttpHeaders none = new HttpHeaders();
            HttpHeaders canonical = new HttpHeaders(); canonical.Add("x-api-key", "{{kc:leaky}}");
            HttpHeaders evil = new HttpHeaders(); evil.Add("x-evil-header", "{{kc:leaky}}");
            PipelineResult r = RunPipeline(new FuzzInput(canonical, "/v1/messages", null, "r1-host-mismatch"), store, "evil.example.com");
            Check.True(r.Decision.Blocked && r.Payload == null, "R1 : hôte hors scope → bloqué, rien substitué");
            r = RunPipeline(new FuzzInput(evil, "/v1/messages", null, "r2-non-canonical-header"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : en-tête non canonique → bloqué");
            r = RunPipeline(new FuzzInput(none, "/v1/{{kc:leaky}}/messages", null, "r2-url-path"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : chemin → bloqué");
            r = RunPipeline(new FuzzInput(none, "/v1/messages?token={{kc:leaky}}", null, "r2-query-string"), store, "api.anthropic.com");
            Check.True(r.Decision.Blocked, "R2 : query → bloqué");
            r = RunPipeline(new FuzzInput(canonical, "/v1/messages", null, "in-scope-canonical"), store, "api.anthropic.com");
            Check.True(!r.Decision.Blocked && string.Join(",", r.Payload.Substituted) == AdversarialInputGenerator.KnownSecretName, "dans le scope et canonique → substitué");
            Check.Eq(AdversarialInputGenerator.Sentinel, r.Payload.Headers.First("x-api-key"), "la valeur réelle est dans l'en-tête réécrit (et nulle part ailleurs)");
        }
    }
}
```

`Main` : `Check.Run("Exfil : R1 hostMismatch", Exfil_R1_HostMismatch); Check.Run("Exfil : R2 nonCanonicalLocation", Exfil_R2_NonCanonicalLocation); Check.Run("Exfil : R3 multipleSecrets (connus seulement)", Exfil_R3_MultipleSecrets); Check.Run("Exfil : R4 derrière R2", Exfil_R4_BehindR2); Check.Run("Exfil : R5 volumeAnomaly", Exfil_R5_VolumeAnomaly); Check.Run("Exfil : composition et quarantaine", Exfil_CompositionAndQuarantine); Check.Run("Fuzz : scan borné, pipeline sans exception", Fuzz_ScanBoundedAndPipelineNeverThrows); Check.Run("Fuzz : la valeur sentinelle n'apparaît dans aucun event", Fuzz_SentinelNeverInEncodedEvent); Check.Run("Fuzz : hors scope jamais substitué", Fuzz_OutOfScopeNeverSubstituted);` — `TEST_SOURCES` : ajouter `"%TESTS%\ExfilTests.cs" "%TESTS%\FuzzTests.cs"`.

- [ ] **Step 3: Vérifier l'échec** — `CS0246 'ExfilRuleEngine'` / `'RequestContext'`.

- [ ] **Step 4: Écrire `src\IrisKit\Placeholder\ExfilRuleEngine.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    public sealed class RequestContext
    {
        public string Host { get; private set; }
        public string Method { get; private set; }
        public string Path { get; private set; }
        public string ContentType { get; private set; }

        public RequestContext(string host, string method, string path, string contentType)
        {
            Host = host; Method = method; Path = path; ContentType = contentType;
        }
    }

    public sealed class ExfilDecision
    {
        public bool Blocked { get; private set; }
        public Alert Alert { get; private set; }
        public IList<PlaceholderHit> Resolvable { get; private set; }
        public IList<PlaceholderHit> AllHits { get; private set; }

        private ExfilDecision() { }

        public static ExfilDecision Allow(IList<PlaceholderHit> resolvable)
        {
            ExfilDecision d = new ExfilDecision();
            d.Blocked = false; d.Resolvable = resolvable; d.AllHits = resolvable;
            return d;
        }

        public static ExfilDecision Block(Alert alert, IList<PlaceholderHit> allHits)
        {
            ExfilDecision d = new ExfilDecision();
            d.Blocked = true; d.Alert = alert; d.Resolvable = new PlaceholderHit[0]; d.AllHits = allHits;
            return d;
        }
    }

    /// <summary>
    /// Règles d'exfiltration R1–R5 (SPECS §9), évaluées dans l'ordre = sévérité décroissante ; la première déclenchée fait l'alerte.
    /// Toutes clés sur les secrets connus ; les inconnus ne résolvent jamais ; les secrets en quarantaine sont inertes.
    /// Le journal de diagnostic (debug) ne porte que des noms et des emplacements, jamais une valeur ni un snippet.
    /// </summary>
    public sealed class ExfilRuleEngine
    {
        public static readonly string[] CanonicalAuthHeaders = { "authorization", "x-api-key", "api-key", "x-auth-token" };
        public static readonly string[] SuspiciousContentTypes = { "text/plain", "application/x-www-form-urlencoded", "multipart/form-data" };
        public static readonly string[] SuspiciousPathFragments = { "/comments", "/issues", "/notes", "/messages", "/blob" };

        private readonly ISecretStore secrets;
        private readonly Func<int> maxPerMinute;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private readonly Dictionary<string, SlidingMinuteCounter> counters = new Dictionary<string, SlidingMinuteCounter>(StringComparer.Ordinal);

        /// <summary>maxPerMinute est relu à chaque évaluation : le seuil peut être rechargé à chaud sans recréer le moteur.</summary>
        public ExfilRuleEngine(ISecretStore secrets, Func<int> maxPerMinute, Func<DateTime> clock)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
            this.maxPerMinute = maxPerMinute;
            this.clock = clock;
        }

        /// <summary>À appeler après une substitution effective (jamais sur blocage).</summary>
        public void RecordSubstitution(IEnumerable<string> names)
        {
            DateTime now = clock();
            lock (gate)
            {
                foreach (string name in names)
                {
                    SlidingMinuteCounter c;
                    if (!counters.TryGetValue(name, out c)) { c = new SlidingMinuteCounter(); counters[name] = c; }
                    c.Record(now);
                }
            }
        }

        private bool WouldExceedVolume(string name)
        {
            int limit = maxPerMinute();
            DateTime now = clock();
            lock (gate)
            {
                SlidingMinuteCounter c;
                int current = counters.TryGetValue(name, out c) ? c.Count(now) : 0;
                return current + 1 > limit;
            }
        }

        public async Task<ExfilDecision> EvaluateAsync(IList<PlaceholderHit> hits, RequestContext context)
        {
            if (hits == null || hits.Count == 0) return ExfilDecision.Allow(new PlaceholderHit[0]);
            string host = HostName.Normalize(context.Host);

            Dictionary<string, Secret> known = new Dictionary<string, Secret>(StringComparer.Ordinal);
            HashSet<string> looked = new HashSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in hits)
            {
                if (!looked.Add(hit.Name)) continue;
                try { known[hit.Name] = await secrets.SecretAsync(hit.Name).ConfigureAwait(false); }
                catch (SecretStoreException ex) { if (ex.Kind != SecretStoreErrorKind.UnknownSecret) throw; }
            }

            List<PlaceholderHit> effective = new List<PlaceholderHit>();
            List<PlaceholderHit> knownHits = new List<PlaceholderHit>();
            foreach (PlaceholderHit hit in hits)
            {
                Secret s;
                bool isKnown = known.TryGetValue(hit.Name, out s);
                if (isKnown && s.Quarantined) continue;
                effective.Add(hit);
                if (isKnown) knownHits.Add(hit);
            }

            if (Log.Minimum <= LogLevel.Debug)
            {
                StringBuilder inv = new StringBuilder();
                foreach (PlaceholderHit hit in effective)
                {
                    if (inv.Length > 0) inv.Append(", ");
                    inv.Append(hit.Name).Append('@').Append(hit.Location.Describe()).Append(known.ContainsKey(hit.Name) ? ":known" : ":unknown");
                }
                Log.Debug("exfil", "inventaire " + context.Method + " " + host + " " + context.Path + " : " + inv);
            }

            // R1 — hôte hors allowed_hosts (high)
            foreach (PlaceholderHit hit in knownHits)
            {
                bool allowed = false;
                foreach (string h in known[hit.Name].AllowedHosts) if (HostName.Normalize(h) == host) { allowed = true; break; }
                if (!allowed) return ExfilDecision.Block(new Alert(AlertSeverity.High, ExfilRule.HostMismatch, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);
            }
            // R2 — emplacement non canonique (high) : seuls les en-têtes d'auth canoniques sont admis
            foreach (PlaceholderHit hit in knownHits)
                if (IsNonCanonical(hit.Location))
                    return ExfilDecision.Block(new Alert(AlertSeverity.High, ExfilRule.NonCanonicalLocation, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);
            // R3 — plusieurs secrets connus distincts (medium)
            SortedSet<string> distinct = new SortedSet<string>(StringComparer.Ordinal);
            foreach (PlaceholderHit hit in knownHits) distinct.Add(hit.Name);
            if (distinct.Count >= 2)
            {
                string first = distinct.Min;
                PlaceholderHit trigger = knownHits[0];
                foreach (PlaceholderHit hit in knownHits) if (hit.Name == first) { trigger = hit; break; }
                return ExfilDecision.Block(new Alert(AlertSeverity.Medium, ExfilRule.MultipleSecrets, first, trigger.Location.ToAlertLocation(), trigger.Snippet), effective);
            }
            // R4 — type de contenu suspect (medium) ; inatteignable derrière R2, conservée pour la défense en profondeur
            PlaceholderHit suspicious = SuspiciousContentTypeFires(knownHits, context);
            if (suspicious != null)
                return ExfilDecision.Block(new Alert(AlertSeverity.Medium, ExfilRule.SuspiciousContentType, suspicious.Name, AlertLocation.Body, suspicious.Snippet), effective);
            // R5 — volume (low) : compté sur les substitutions effectives seulement
            foreach (PlaceholderHit hit in knownHits)
                if (WouldExceedVolume(hit.Name))
                    return ExfilDecision.Block(new Alert(AlertSeverity.Low, ExfilRule.VolumeAnomaly, hit.Name, hit.Location.ToAlertLocation(), hit.Snippet), effective);

            return ExfilDecision.Allow(knownHits);
        }

        private static bool IsNonCanonical(HitLocation location)
        {
            if (location.Kind != HitLocationKind.Header) return true;
            foreach (string c in CanonicalAuthHeaders) if (c == location.HeaderName) return false;
            return true;
        }

        private static PlaceholderHit SuspiciousContentTypeFires(IList<PlaceholderHit> hits, RequestContext context)
        {
            PlaceholderHit bodyHit = null;
            foreach (PlaceholderHit hit in hits) if (hit.Location.Kind == HitLocationKind.Body) { bodyHit = hit; break; }
            if (bodyHit == null || context.ContentType == null) return null;
            string baseType = context.ContentType.Split(';')[0].Trim().ToLowerInvariant();
            if (Array.IndexOf(SuspiciousContentTypes, baseType) < 0) return null;
            string path = (context.Path ?? "").ToLowerInvariant();
            foreach (string fragment in SuspiciousPathFragments) if (path.Contains(fragment)) return bodyHit;
            return null;
        }
    }
}
```

- [ ] **Step 5: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Placeholder\ExfilRuleEngine.cs"`. → `87 test(s) réussi(s)`. Les trois tests de fuzzing font 2 010 entrées chacun : compter quelques secondes, pas plus ; si `thousands-occurrences` (5 000 placeholders dans un en-tête) prend plus d'une seconde, c'est `MakeSnippet` qui recopie 160 caractères par hit, acceptable.

- [ ] **Step 6: Commit**

```bash
git add src/IrisKit/Placeholder/ExfilRuleEngine.cs tests/ExfilTests.cs tests/FuzzTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): ExfilRuleEngine R1–R5 avec quarantaine, corpus de fuzzing du scanner (I1, I2, I3)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 4: Feuilles par hôte — `CACrypto.CreateLeafCertificate`, `LeafCertCache`, `IUpstreamTrust`

**Files:**
- Modify: `src\IrisKit\CA\CACrypto.cs` (ajouts en fin de classe)
- Create: `src\IrisKit\CA\LeafCertCache.cs`, `src\IrisKit\Proxy\UpstreamTrust.cs`
- Create: `tests\LeafTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `CAManager` (`Certificate`, `SigningKey`, `EnsureCA`), `CACrypto.RandomSerial`, `InMemoryCAKeyStore`, `Log` (phase 1).
- Produces: `CACrypto.LeafValidityDays = 90`, `CACrypto.CreateLeafCertificate(string host, X509Certificate2 caCertificate, ECDsa caKey, DateTime now, int validityDays) : X509Certificate2` (avec clé privée persistée dans le KSP), `CACrypto.PrivateKeyName(X509Certificate2) : string`, `CACrypto.DestroyPrivateKey(X509Certificate2)` ; `LeafCertCache(CAManager ca, Func<DateTime> clock) : IDisposable` (`Get(string host) : X509Certificate2`, `Evict(string host) : bool`, `Count`, `static readonly TimeSpan RenewBefore = 1 jour`) ; `IUpstreamTrust { bool Validate(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors); string Describe(); }`, `SystemTrust`, `PinnedRootTrust(X509Certificate2 root)`, `UpstreamTrustAdapter.Callback(IUpstreamTrust) : RemoteCertificateValidationCallback`.

- [ ] **Step 1: Écrire `tests\LeafTests.cs` (RED)**

```csharp
using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Feuilles et confiance amont ---------------------------------------

        private static CAManager FreshCA()
        {
            CAManager ca = new CAManager(new InMemoryCAKeyStore(), null, delegate { return DateTime.UtcNow; });
            ca.EnsureCA();
            return ca;
        }

        private static bool ChainsTo(X509Certificate2 leaf, X509Certificate2 root)
        {
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            bool built = chain.Build(leaf);
            return built && chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint == root.Thumbprint;
        }

        private static void Leaf_SignedByCA_SanValidity()
        {
            using (CAManager ca = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; }))
            {
                X509Certificate2 leaf = cache.Get("Example.COM");
                Check.Eq("CN=example.com", leaf.Subject, "CN = hôte normalisé");
                Check.Eq(ca.Certificate.Subject, leaf.Issuer, "émetteur = CA");
                Check.True(leaf.HasPrivateKey, "clé privée attachée");
                Check.True(ChainsTo(leaf, ca.Certificate), "signature vérifiable par X509Chain avec le CA");
                bool san = false, serverAuth = false, notCa = false;
                foreach (X509Extension ext in leaf.Extensions)
                {
                    if (ext.Oid.Value == "2.5.29.17") san = ext.Format(false).ToLowerInvariant().Contains("example.com");
                    X509EnhancedKeyUsageExtension eku = ext as X509EnhancedKeyUsageExtension;
                    if (eku != null) foreach (Oid o in eku.EnhancedKeyUsages) if (o.Value == "1.3.6.1.5.5.7.3.1") serverAuth = true;
                    X509BasicConstraintsExtension bc = ext as X509BasicConstraintsExtension;
                    if (bc != null) notCa = !bc.CertificateAuthority;
                }
                Check.True(san, "SAN DNS = hôte");
                Check.True(serverAuth, "EKU serverAuth");
                Check.True(notCa, "basicConstraints CA:FALSE");
                double days = (leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime()).TotalDays;
                Check.True(days > 89.9 && days < 90.2, "validité ≈ 90 jours (notBefore antidaté d'une heure)");
                Check.True(leaf.NotBefore.ToUniversalTime() < DateTime.UtcNow, "déjà valide");
                Check.True(leaf.SerialNumber.Length >= 16, "série aléatoire de 16 octets (RandomSerial)");
            }
        }

        private static void Leaf_CacheEvictAndDispose_DeleteCngKeys()
        {
            string nameA, nameB;
            using (CAManager ca = FreshCA())
            {
                LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; });
                X509Certificate2 a1 = cache.Get("alpha.example");
                X509Certificate2 a2 = cache.Get("ALPHA.example");
                X509Certificate2 b = cache.Get("beta.example");
                Check.Eq(a1.Thumbprint, a2.Thumbprint, "même hôte (insensible à la casse) = même feuille");
                Check.True(a1.Thumbprint != b.Thumbprint, "hôtes différents = feuilles différentes");
                Check.Eq(2, cache.Count, "deux entrées");
                nameA = CACrypto.PrivateKeyName(a1);
                nameB = CACrypto.PrivateKeyName(b);
                Check.True(nameA != null && CngKey.Exists(nameA), "la clé de la feuille est un conteneur CNG persistant");
                Check.True(cache.Evict("alpha.example"), "éviction");
                Check.True(!CngKey.Exists(nameA), "le conteneur CNG n'existe plus après Evict (spec §8.4)");
                Check.True(!cache.Evict("alpha.example"), "éviction d'un absent = false");
                Check.Eq(1, cache.Count, "une entrée");
                cache.Dispose();
                Check.True(!CngKey.Exists(nameB), "Dispose supprime les clés restantes");
                Check.Eq(0, cache.Count, "vide après Dispose");
            }
        }

        private static void Leaf_RenewalNearExpiry()
        {
            DateTime now = DateTime.UtcNow;
            DateTime clock = now;
            using (CAManager ca = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return clock; }))
            {
                X509Certificate2 first = cache.Get("renew.example");
                string firstKey = CACrypto.PrivateKeyName(first);
                clock = now.AddDays(10);
                Check.Eq(first.Thumbprint, cache.Get("renew.example").Thumbprint, "dix jours plus tard : même feuille");
                clock = now.AddDays(90).AddHours(-12);
                X509Certificate2 renewed = cache.Get("renew.example");
                Check.True(renewed.Thumbprint != first.Thumbprint, "moins d'un jour avant expiration : renouvelée");
                Check.True(!CngKey.Exists(firstKey), "la clé de l'ancienne feuille est supprimée au renouvellement");
                Check.Eq(1, cache.Count, "toujours une entrée");
            }
        }

        private static void Leaf_SchannelHandshake_PinnedTrust()
        {
            using (CAManager ca = FreshCA())
            using (CAManager other = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; }))
            {
                X509Certificate2 leaf = cache.Get("localhost");
                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = Task.Run(async delegate
                {
                    for (int i = 0; i < 3; i++)
                    {
                        using (TcpClient c = await listener.AcceptTcpClientAsync())
                        using (SslStream ssl = new SslStream(c.GetStream(), false))
                        {
                            try
                            {
                                await ssl.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false);
                                byte[] buf = new byte[16];
                                int n = await ssl.ReadAsync(buf, 0, buf.Length);
                                byte[] reply = Encoding.ASCII.GetBytes("pong:" + Encoding.ASCII.GetString(buf, 0, n));
                                await ssl.WriteAsync(reply, 0, reply.Length);
                            }
                            catch (IOException) { }
                            catch (AuthenticationException) { }
                        }
                    }
                });
                try
                {
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(ca.Certificate))))
                    {
                        ssl.AuthenticateAsClient("localhost", null, SslProtocols.Tls12, false);
                        Check.Eq(SslProtocols.Tls12, ssl.SslProtocol, "TLS 1.2 négocié avec la feuille ECDSA persistée (Schannel)");
                        ssl.Write(Encoding.ASCII.GetBytes("ping"));
                        byte[] buf = new byte[16];
                        int n = ssl.Read(buf, 0, buf.Length);
                        Check.Eq("pong:ping", Encoding.ASCII.GetString(buf, 0, n), "échange chiffré");
                    }
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(other.Certificate))))
                        Check.Throws<AuthenticationException>(delegate { ssl.AuthenticateAsClient("localhost", null, SslProtocols.Tls12, false); }, "autre racine épinglée → refus");
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(ca.Certificate))))
                        Check.Throws<AuthenticationException>(delegate { ssl.AuthenticateAsClient("other.example", null, SslProtocols.Tls12, false); }, "nom d'hôte différent du SAN → refus");
                }
                finally
                {
                    listener.Stop();
                    try { server.Wait(2000); } catch (AggregateException) { }
                }
            }
        }

        private static void UpstreamTrust_System()
        {
            SystemTrust trust = new SystemTrust();
            using (CAManager ca = FreshCA())
            {
                Check.True(trust.Validate(ca.Certificate, null, SslPolicyErrors.None), "aucune erreur → accepté");
                Check.True(!trust.Validate(ca.Certificate, null, SslPolicyErrors.RemoteCertificateChainErrors), "chaîne non fiable → refusé");
                Check.True(!trust.Validate(ca.Certificate, null, SslPolicyErrors.RemoteCertificateNameMismatch), "nom → refusé");
                Check.True(trust.Describe().Length > 0 && new PinnedRootTrust(ca.Certificate).Describe().Contains(ca.Certificate.Thumbprint.Substring(0, 8).ToLowerInvariant()), "Describe");
            }
        }
    }
}
```

`Main` : `Check.Run("Feuilles : signée par le CA, SAN, validité", Leaf_SignedByCA_SanValidity); Check.Run("Feuilles : cache, éviction et Dispose suppriment les clés CNG", Leaf_CacheEvictAndDispose_DeleteCngKeys); Check.Run("Feuilles : renouvellement avant expiration", Leaf_RenewalNearExpiry); Check.Run("Feuilles : poignée de main Schannel et racine épinglée", Leaf_SchannelHandshake_PinnedTrust); Check.Run("Confiance amont : magasin système", UpstreamTrust_System);` — `TEST_SOURCES` : ajouter `"%TESTS%\LeafTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'LeafCertCache'` / `CS0117 'CACrypto' ne contient pas 'PrivateKeyName'`.

- [ ] **Step 3: Compléter `src\IrisKit\CA\CACrypto.cs`**

Ajouter `using System.Security.Cryptography.X509Certificates;` (déjà présent) et, avant la dernière accolade de la classe `CACrypto` :

```csharp
        // ---- Feuilles (SPECS §11.2) -------------------------------------------

        public const int LeafValidityDays = 90;

        /// <summary>
        /// Feuille pour `host` : CN et SAN DNS = hôte, serverAuth, digitalSignature+keyEncipherment, CA:FALSE, série aléatoire,
        /// signée par la clé du CA (jamais exportée ici). La clé privée de la feuille est persistée dans le KSP par un aller-retour PFX
        /// (`PersistKeySet`) parce que Schannel refuse une clé éphémère ; l'appelant la supprime avec DestroyPrivateKey.
        /// </summary>
        public static X509Certificate2 CreateLeafCertificate(string host, X509Certificate2 caCertificate, ECDsa caKey, DateTime now, int validityDays)
        {
            using (ECDsaCng leafKey = new ECDsaCng(ECCurve.NamedCurves.nistP256))
            {
                CertificateRequest req = new CertificateRequest("CN=" + host, leafKey, HashAlgorithmName.SHA256);
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(host);
                req.CertificateExtensions.Add(san.Build());
                DateTimeOffset notBefore = new DateTimeOffset(now.ToUniversalTime()).AddHours(-1);
                X509SignatureGenerator generator = X509SignatureGenerator.CreateForECDsa(caKey);
                using (X509Certificate2 publicOnly = req.Create(caCertificate.SubjectName, generator, notBefore, notBefore.AddDays(validityDays).AddHours(1), RandomSerial()))
                using (X509Certificate2 withKey = publicOnly.CopyWithPrivateKey(leafKey))
                {
                    byte[] pfx = withKey.Export(X509ContentType.Pfx, "iris");
                    try { return new X509Certificate2(pfx, "iris", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet); }
                    finally { Array.Clear(pfx, 0, pfx.Length); }
                }
            }
        }

        /// <summary>Nom du conteneur CNG de la clé privée (null si absente ou non CNG).</summary>
        public static string PrivateKeyName(X509Certificate2 certificate)
        {
            using (ECDsaCng key = certificate.GetECDsaPrivateKey() as ECDsaCng)
            {
                return key == null ? null : key.Key.KeyName;
            }
        }

        /// <summary>Supprime le conteneur CNG de la clé privée (spec §8.4 : une feuille évincée ne survit pas) et libère le certificat.</summary>
        public static void DestroyPrivateKey(X509Certificate2 certificate)
        {
            try
            {
                using (ECDsaCng key = certificate.GetECDsaPrivateKey() as ECDsaCng)
                {
                    if (key != null) key.Key.Delete();
                }
            }
            catch (CryptographicException ex) { Log.Warn("ca", "suppression de la clé d'une feuille impossible : " + ex.Message); }
            certificate.Reset();
        }
```

- [ ] **Step 4: Écrire `src\IrisKit\CA\LeafCertCache.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace IrisKit
{
    /// <summary>
    /// Feuilles par hôte signées par le CA (spec §6.1) : cache mémoire, jamais sur disque ; renouvelée moins d'un jour avant
    /// expiration ; la clé CNG est supprimée à l'éviction, au renouvellement et au Dispose.
    /// </summary>
    public sealed class LeafCertCache : IDisposable
    {
        public static readonly TimeSpan RenewBefore = TimeSpan.FromDays(1);

        private readonly CAManager ca;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private readonly Dictionary<string, X509Certificate2> cache = new Dictionary<string, X509Certificate2>(StringComparer.Ordinal);

        public LeafCertCache(CAManager ca, Func<DateTime> clock)
        {
            if (ca == null) throw new ArgumentNullException("ca");
            this.ca = ca;
            this.clock = clock;
        }

        public int Count { get { lock (gate) { return cache.Count; } } }

        /// <summary>Feuille valide pour l'hôte (normalisé en minuscules, sans port), frappée au premier usage.</summary>
        public X509Certificate2 Get(string host)
        {
            string key = HostName.Normalize(host);
            DateTime now = clock();
            lock (gate)
            {
                X509Certificate2 existing;
                if (cache.TryGetValue(key, out existing))
                {
                    if (existing.NotAfter.ToUniversalTime() - now > RenewBefore) return existing;
                    cache.Remove(key);
                    CACrypto.DestroyPrivateKey(existing);
                    Log.Info("ca", "feuille renouvelée pour " + key);
                }
                X509Certificate2 leaf = CACrypto.CreateLeafCertificate(key, ca.Certificate, ca.SigningKey, now, CACrypto.LeafValidityDays);
                cache[key] = leaf;
                Log.Debug("ca", "feuille émise pour " + key + ", empreinte " + leaf.Thumbprint.ToLowerInvariant());
                return leaf;
            }
        }

        public bool Evict(string host)
        {
            string key = HostName.Normalize(host);
            lock (gate)
            {
                X509Certificate2 existing;
                if (!cache.TryGetValue(key, out existing)) return false;
                cache.Remove(key);
                CACrypto.DestroyPrivateKey(existing);
                return true;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                foreach (X509Certificate2 leaf in cache.Values) CACrypto.DestroyPrivateKey(leaf);
                cache.Clear();
            }
        }
    }
}
```

- [ ] **Step 5: Écrire `src\IrisKit\Proxy\UpstreamTrust.cs`**

```csharp
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace IrisKit
{
    /// <summary>Validation du certificat amont (spec §6.1 : validation standard via le magasin Windows ; épinglage pour les tests).</summary>
    public interface IUpstreamTrust
    {
        bool Validate(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors);
        string Describe();
    }

    /// <summary>Magasin de certificats Windows : seule une chaîne sans erreur est acceptée.</summary>
    public sealed class SystemTrust : IUpstreamTrust
    {
        public bool Validate(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors) { return errors == SslPolicyErrors.None; }
        public string Describe() { return "magasin Windows"; }
    }

    /// <summary>Racine épinglée (tests et MockUpstream) : la chaîne doit se construire jusqu'à cette racine et le nom doit correspondre.</summary>
    public sealed class PinnedRootTrust : IUpstreamTrust
    {
        private readonly X509Certificate2 root;

        public PinnedRootTrust(X509Certificate2 root)
        {
            if (root == null) throw new ArgumentNullException("root");
            this.root = root;
        }

        public bool Validate(X509Certificate2 certificate, X509Chain ignored, SslPolicyErrors errors)
        {
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(certificate)) return false;
            return chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint == root.Thumbprint;
        }

        public string Describe() { return "racine épinglée " + root.Thumbprint.ToLowerInvariant(); }
    }

    public static class UpstreamTrustAdapter
    {
        public static RemoteCertificateValidationCallback Callback(IUpstreamTrust trust)
        {
            return delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            {
                if (certificate == null) return false;
                return trust.Validate(new X509Certificate2(certificate), chain, errors);
            };
        }
    }
}
```

- [ ] **Step 6: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\CA\LeafCertCache.cs" "%SRC%\IrisKit\Proxy\UpstreamTrust.cs"`. → `92 test(s) réussi(s)`. Si `Leaf_SchannelHandshake_PinnedTrust` échoue à `AuthenticateAsServer` avec « Le fichier de données de clé est introuvable » : la clé n'a pas été persistée, vérifier `X509KeyStorageFlags.PersistKeySet` ; si le client refuse avec `RemoteCertificateNameMismatch` sur `localhost` : le SAN n'est pas construit (`SubjectAlternativeNameBuilder.Build()` doit être ajouté **après** les autres extensions, c'est le cas).

- [ ] **Step 7: Commit**

```bash
git add src/IrisKit/CA/CACrypto.cs src/IrisKit/CA/LeafCertCache.cs src/IrisKit/Proxy/UpstreamTrust.cs tests/LeafTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): feuilles par hôte signées par le CA (LeafCertCache, clés CNG détruites à l'éviction) et confiance amont

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 5: `ProxyServer`, `ConnectHandler`, `TunnelHandler`, `UpstreamClient` et le harnais d'intégration

**Files:**
- Create: `src\IrisKit\Proxy\ProxyOptions.cs`, `src\IrisKit\Proxy\UpstreamClient.cs`, `src\IrisKit\Proxy\ProxyServer.cs`, `src\IrisKit\Proxy\ConnectHandler.cs`, `src\IrisKit\Proxy\TunnelHandler.cs`
- Create: `tests\MockUpstream.cs`, `tests\TestProxyClient.cs`, `tests\ProxyTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `HttpConnection`, `HttpParser`, `HttpHeaders`, `PrefixedStream` (tâche 1), `LeafCertCache`, `IUpstreamTrust`, `PinnedRootTrust`, `UpstreamTrustAdapter` (tâche 4), `CAManager`, `EventPipeline`, `Event`, `EventKind`, `MITMRule`, `HostName`, `SecurityConfig`, `Config`, `ISecretStore`, `Log` (phase 1).
- Produces: `ProxyOptions` (`ListenHost`, `ListenPort`, `AllowedHosts : ISet<string>`, `Security : SecurityConfig`, `UpstreamTrust`, `IdleTimeout` 120 s, `ConnectTimeout` 10 s, `ShutdownGrace` 5 s, `static FromConfig(Config)`, `Validate()`) ; `ProxyException`, `ProxyPortInUseException(int port)` (`Port`) ; `UpstreamException(message, inner)` ; `UpstreamClient(IUpstreamTrust, TimeSpan connectTimeout)` (`static ConnectTcpAsync(string host, int port, TimeSpan timeout, CancellationToken) : Task<TcpClient>`, `ConnectTlsAsync(string host, int port, CancellationToken) : Task<UpstreamConnection>`) ; `UpstreamConnection : IDisposable` (`Http : HttpConnection`, `Host`, `Port`) ; `ProxyServer(ProxyOptions, ISecretStore, CAManager, EventPipeline, Func<DateTime> clock) : IDisposable` (`Options`, `ListenEndPoint`, `Start() : IPEndPoint`, `StopAsync() : Task`, `Paused`, `SetPaused(bool)`, `AllowedHosts`, `UpdateRules(IList<MITMRule>)`, `IsAllowed(string host)`, `ActiveConnections`, `Leaves : LeafCertCache`, `Events : EventPipeline`, `Secrets : ISecretStore`, `Upstream : UpstreamClient`, `Clock`, `Processor : RequestProcessor` (posé par la tâche 6, `null` jusque-là), `Register/Unregister(ClientConnection)`) ; `ClientConnection : IDisposable` (`Client : TcpClient`, `Http : HttpConnection`, `Remote`, `Close()`) ; `ConnectHandler.HandleAsync(ProxyServer, ClientConnection, CancellationToken)`, `ConnectHandler.ParseAuthority(string, out string host, out int port) : bool`, `ConnectHandler.WriteSimpleResponseAsync(HttpConnection, int status, string body, CancellationToken)` ; `PingResponder.Matches(HttpRequestHead)`, `PingResponder.RespondAsync(HttpConnection, CancellationToken)` ; `TunnelHandler.RunAsync(ProxyServer, ClientConnection, string host, int port, CancellationToken)` ; `MITMHandler.RunAsync(ProxyServer, ClientConnection, string host, int port, CancellationToken)` est **déclarée dans cette tâche comme un bouchon** (répond `502` « MITM non disponible ») que la tâche 7 remplace. Côté tests : `MockUpstream` (`Start(string host) : MockUpstream`, `Port`, `CACertificate`, `Received : IList<ReceivedRequest>`, `WaitForRequestAsync(TimeSpan) : Task<ReceivedRequest>`, `Streaming : StreamingPlan`, `Connections`, `Stop()`), `ReceivedRequest` (`Head`, `Body`), `StreamingPlan` (`FirstChunk`, `RemainingChunks`, `ReleaseRest : TaskCompletionSource<bool>`, `DropAfterFirstChunk`) ; `TestProxyClient` (`ConnectAsync(int proxyPort)`, `ConnectTunnelAsync(host, port) : Task<int>`, `StartTlsAsync(host, X509Certificate2 root)`, `SendAsync(method, path, HttpHeaders, byte[] body)`, `ReadResponseAsync() : Task<ProxyClientResponse>`, `ReadResponseHeadAsync()`, `ReadChunkAsync() : Task<byte[]>` (null au dernier chunk), `Http`, `Dispose()`, `static RequestAsync(proxyPort, host, port, root, method, path, headers, body)`, `static RawAsync(proxyPort, string request) : Task<string>`) ; `ProxyClientResponse` (`Status`, `Headers`, `Body`) ; `TestMain.NewProxy(ProxyOptions, ISecretStore, CAManager) : ProxyServer` et `TestMain.FreePort() : int`.

- [ ] **Step 1: Écrire `tests\MockUpstream.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>
    /// Serveur HTTPS de test en process (cf. ../Iris/Tests/IntegrationTests/MockUpstream.swift) : son propre CA, une feuille
    /// pour `host`, enregistre chaque requête complète, répond `200 OK` (corps `OK`) ou suit un plan de streaming.
    /// </summary>
    public sealed class MockUpstream : IDisposable
    {
        public sealed class ReceivedRequest { public HttpRequestHead Head; public byte[] Body; }

        public sealed class StreamingPlan
        {
            public byte[] FirstChunk;
            public IList<byte[]> RemainingChunks = new List<byte[]>();
            public TaskCompletionSource<bool> ReleaseRest = new TaskCompletionSource<bool>();
            public bool DropAfterFirstChunk;
        }

        public int Port { get; private set; }
        public X509Certificate2 CACertificate { get { return ca.Certificate; } }
        public StreamingPlan Streaming;
        public int Connections;

        private readonly CAManager ca;
        private readonly LeafCertCache leaves;
        private readonly X509Certificate2 leaf;
        private readonly TcpListener listener;
        private readonly List<ReceivedRequest> received = new List<ReceivedRequest>();
        private readonly SemaphoreSlim arrived = new SemaphoreSlim(0);
        private readonly CancellationTokenSource stopping = new CancellationTokenSource();

        private MockUpstream(string host)
        {
            ca = new CAManager(new InMemoryCAKeyStore(), null, delegate { return DateTime.UtcNow; });
            ca.EnsureCA();
            leaves = new LeafCertCache(ca, delegate { return DateTime.UtcNow; });
            leaf = leaves.Get(host);
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        public static MockUpstream Start(string host)
        {
            MockUpstream mock = new MockUpstream(host);
            Task.Run(new Func<Task>(mock.AcceptLoopAsync));
            return mock;
        }

        public IList<ReceivedRequest> Received { get { lock (received) { return new List<ReceivedRequest>(received); } } }

        public async Task<ReceivedRequest> WaitForRequestAsync(TimeSpan timeout)
        {
            if (!await arrived.WaitAsync(timeout)) throw new TimeoutException("aucune requête reçue par MockUpstream en " + timeout.TotalSeconds + " s");
            lock (received) { return received[received.Count - 1]; }
        }

        private async Task AcceptLoopAsync()
        {
            while (!stopping.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { return; }
                Interlocked.Increment(ref Connections);
                Task ignored = ServeAsync(client);
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            using (SslStream ssl = new SslStream(client.GetStream(), false))
            {
                try
                {
                    await ssl.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false);
                    HttpConnection http = new HttpConnection(ssl);
                    while (true)
                    {
                        HttpRequestHead head = await HttpParser.ReadRequestHeadAsync(http, stopping.Token);
                        if (head == null) return;
                        BufferedBody body = await HttpParser.ReadBodyAsync(http, HttpParser.RequestFraming(head.Headers), 64 * 1024 * 1024, stopping.Token);
                        ReceivedRequest r = new ReceivedRequest();
                        r.Head = head;
                        r.Body = body.Bytes;
                        lock (received) received.Add(r);
                        arrived.Release();
                        StreamingPlan plan = Streaming;
                        if (plan != null) { await StreamAsync(http, plan); return; }
                        byte[] reply = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK");
                        await http.WriteAsync(reply, 0, reply.Length, stopping.Token);
                        await http.FlushAsync(stopping.Token);
                        if (HttpParser.WantsClose(head.Version, head.Headers)) return;
                    }
                }
                catch (IOException) { }
                catch (AuthenticationException) { }
                catch (HttpProtocolException) { }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
            }
        }

        private async Task StreamAsync(HttpConnection http, StreamingPlan plan)
        {
            byte[] head = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
            await http.WriteAsync(head, 0, head.Length, stopping.Token);
            await HttpParser.WriteChunkAsync(http, plan.FirstChunk, 0, plan.FirstChunk.Length, stopping.Token);
            await http.FlushAsync(stopping.Token);
            if (plan.DropAfterFirstChunk) return; // fermeture sans dernier chunk : amont coupé en plein flux
            await plan.ReleaseRest.Task;
            foreach (byte[] chunk in plan.RemainingChunks) await HttpParser.WriteChunkAsync(http, chunk, 0, chunk.Length, stopping.Token);
            await HttpParser.WriteLastChunkAsync(http, stopping.Token);
        }

        public void Stop()
        {
            stopping.Cancel();
            listener.Stop();
            leaves.Dispose();
            ca.Dispose();
        }

        public void Dispose() { Stop(); }
    }
}
```

- [ ] **Step 2: Écrire `tests\TestProxyClient.cs`**

```csharp
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public sealed class ProxyClientResponse
    {
        public int Status;
        public HttpHeaders Headers;
        public byte[] Body;
        public string Text { get { return Encoding.UTF8.GetString(Body ?? new byte[0]); } }
    }

    /// <summary>Client HTTP/1.1 manuel à travers le proxy (cf. ../Iris/Tests/IntegrationTests/TestProxyClient.swift) : TCP → CONNECT → TLS → requêtes.</summary>
    public sealed class TestProxyClient : IDisposable
    {
        private TcpClient tcp;
        private HttpConnection plain;
        private SslStream tls;
        public HttpConnection Http { get; private set; }

        public static async Task<TestProxyClient> ConnectAsync(int proxyPort)
        {
            TestProxyClient c = new TestProxyClient();
            c.tcp = new TcpClient();
            await c.tcp.ConnectAsync("127.0.0.1", proxyPort);
            c.plain = new HttpConnection(c.tcp.GetStream());
            c.plain.ReadTimeout = TimeSpan.FromSeconds(10);
            c.Http = c.plain;
            return c;
        }

        /// <summary>Envoie CONNECT host:port et rend le statut de la réponse du proxy.</summary>
        public async Task<int> ConnectTunnelAsync(string host, int port)
        {
            byte[] req = HttpParser.Latin1.GetBytes("CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n\r\n");
            await plain.WriteAsync(req, 0, req.Length, CancellationToken.None);
            await plain.FlushAsync(CancellationToken.None);
            HttpResponseHead head = await HttpParser.ReadResponseHeadAsync(plain, CancellationToken.None);
            if (head == null) throw new IOException("le proxy a fermé la connexion sans répondre au CONNECT");
            if (head.Status != 200)
            {
                BufferedBody body = await HttpParser.ReadBodyAsync(plain, HttpParser.ResponseFraming(head.Headers, "CONNECT", head.Status), 65536, CancellationToken.None);
                LastErrorBody = HttpParser.Latin1.GetString(body.Bytes);
            }
            return head.Status;
        }

        public string LastErrorBody { get; private set; }

        /// <summary>TLS dans le tunnel, en ne faisant confiance qu'à `root` (le CA du proxy pour le MITM, celui du mock pour un tunnel brut).</summary>
        public async Task StartTlsAsync(string host, X509Certificate2 root)
        {
            Stream inner = new PrefixedStream(plain.TakeBuffered(), tcp.GetStream());
            tls = new SslStream(inner, false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(root)));
            await tls.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false);
            Http = new HttpConnection(tls);
            Http.ReadTimeout = TimeSpan.FromSeconds(10);
        }

        public async Task SendAsync(string method, string path, HttpHeaders headers, byte[] body)
        {
            HttpHeaders h = headers == null ? new HttpHeaders() : headers.Clone();
            if (body != null && !h.Contains("Content-Length") && !h.Contains("Transfer-Encoding")) h.Add("Content-Length", body.Length.ToString());
            await HttpParser.WriteAsync(Http, new HttpRequestHead(method, path, "HTTP/1.1", h), CancellationToken.None);
            if (body != null) await Http.WriteAsync(body, 0, body.Length, CancellationToken.None);
            await Http.FlushAsync(CancellationToken.None);
        }

        public Task<HttpResponseHead> ReadResponseHeadAsync() { return HttpParser.ReadResponseHeadAsync(Http, CancellationToken.None); }

        public async Task<ProxyClientResponse> ReadResponseAsync()
        {
            HttpResponseHead head = await ReadResponseHeadAsync();
            if (head == null) throw new IOException("connexion fermée avant la réponse");
            BufferedBody body = await HttpParser.ReadBodyAsync(Http, HttpParser.ResponseFraming(head.Headers, "GET", head.Status), 64 * 1024 * 1024, CancellationToken.None);
            ProxyClientResponse r = new ProxyClientResponse();
            r.Status = head.Status; r.Headers = head.Headers; r.Body = body.Bytes;
            return r;
        }

        /// <summary>Un chunk d'une réponse chunked ; null au dernier chunk (trailers consommés) ou si le pair ferme.</summary>
        public async Task<byte[]> ReadChunkAsync()
        {
            string line = await Http.ReadLineAsync(1024, CancellationToken.None);
            if (line == null) return null;
            int size = Convert.ToInt32(line.Split(';')[0].Trim(), 16);
            if (size == 0)
            {
                while (true) { string t = await Http.ReadLineAsync(65536, CancellationToken.None); if (t == null || t.Length == 0) break; }
                return null;
            }
            byte[] data = new byte[size];
            await Http.ReadExactAsync(data, 0, size, CancellationToken.None);
            await Http.ReadLineAsync(16, CancellationToken.None);
            return data;
        }

        public void Dispose()
        {
            if (tls != null) { try { tls.Dispose(); } catch (IOException) { } }
            if (tcp != null) tcp.Close();
        }

        /// <summary>CONNECT + TLS (racine `root`) + une requête ; lève si le CONNECT n'est pas accepté.</summary>
        public static async Task<ProxyClientResponse> RequestAsync(int proxyPort, string host, int port, X509Certificate2 root, string method, string path, HttpHeaders headers, byte[] body)
        {
            using (TestProxyClient c = await ConnectAsync(proxyPort))
            {
                int status = await c.ConnectTunnelAsync(host, port);
                if (status != 200) throw new InvalidOperationException("CONNECT refusé : " + status + " " + c.LastErrorBody);
                await c.StartTlsAsync(host, root);
                await c.SendAsync(method, path, headers, body);
                return await c.ReadResponseAsync();
            }
        }

        /// <summary>Envoie des octets bruts au proxy et rend tout ce qu'il répond jusqu'à la fermeture (ping, 405, 400).</summary>
        public static async Task<string> RawAsync(int proxyPort, string request)
        {
            using (TcpClient tcp = new TcpClient())
            {
                await tcp.ConnectAsync("127.0.0.1", proxyPort);
                NetworkStream s = tcp.GetStream();
                byte[] bytes = HttpParser.Latin1.GetBytes(request);
                await s.WriteAsync(bytes, 0, bytes.Length);
                MemoryStream all = new MemoryStream();
                byte[] buf = new byte[4096];
                Task<int> read;
                while (true)
                {
                    read = s.ReadAsync(buf, 0, buf.Length);
                    if (await Task.WhenAny(read, Task.Delay(5000)) != read) throw new TimeoutException("le proxy n'a pas fermé la connexion");
                    int n = await read;
                    if (n == 0) break;
                    all.Write(buf, 0, n);
                }
                return HttpParser.Latin1.GetString(all.ToArray());
            }
        }
    }
}
```

- [ ] **Step 3: Écrire `tests\ProxyTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- ProxyServer : écoute, ping, CONNECT, tunnel ------------------------

        private static int FreePort()
        {
            TcpListener l = new TcpListener(IPAddress.Loopback, 0);
            l.Start();
            int port = ((IPEndPoint)l.LocalEndpoint).Port;
            l.Stop();
            return port;
        }

        private static ProxyOptions TestOptions(params string[] allowedHosts)
        {
            ProxyOptions o = new ProxyOptions();
            o.ListenPort = 0;
            foreach (string h in allowedHosts) o.AllowedHosts.Add(h);
            o.Security = new SecurityConfig(ExfilPolicy.BlockOnly, 60);
            return o;
        }

        private static ProxyServer NewProxy(ProxyOptions options, ISecretStore secrets, CAManager ca)
        {
            EventPipeline events = new EventPipeline(new EventRing(1000), null, new EventsBus());
            return new ProxyServer(options, secrets, ca, events, delegate { return DateTime.UtcNow; });
        }

        private static Event FirstEvent(ProxyServer proxy, EventKind kind)
        {
            foreach (Event e in proxy.Events.Ring.All) if (e.Kind == kind) return e;
            return null;
        }

        private static void Proxy_StartStopAndLoopbackOnly()
        {
            using (CAManager ca = FreshCA())
            {
                ProxyOptions bad = TestOptions();
                bad.ListenHost = "0.0.0.0";
                using (ProxyServer p = NewProxy(bad, new InMemorySecretStore(), ca))
                    Check.Throws<ProxyException>(delegate { p.Start(); }, "adresse hors bouclage refusée (audit IRIS M-4)");
                int port = FreePort();
                ProxyOptions a = TestOptions(); a.ListenPort = port;
                using (ProxyServer first = NewProxy(a, new InMemorySecretStore(), ca))
                {
                    IPEndPoint ep = first.Start();
                    Check.Eq(port, ep.Port, "port demandé");
                    Check.Eq(port, first.ListenEndPoint.Port, "ListenEndPoint");
                    ProxyOptions b = TestOptions(); b.ListenPort = port;
                    using (ProxyServer second = NewProxy(b, new InMemorySecretStore(), ca))
                    {
                        ProxyPortInUseException ex = Check.Throws<ProxyPortInUseException>(delegate { second.Start(); }, "port occupé");
                        Check.Eq(port, ex.Port, "le port est dans l'exception");
                        Check.True(ex.Message.Contains(port.ToString()), "et dans le message");
                    }
                    Wait(first.StopAsync());
                    Check.Eq(0, first.ActiveConnections, "aucune connexion après arrêt");
                }
                using (ProxyServer again = NewProxy(a, new InMemorySecretStore(), ca))
                {
                    again.Start();
                    Wait(again.StopAsync());
                    Check.True(true, "le port est libéré après StopAsync");
                }
            }
        }

        private static void Proxy_Ping()
        {
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions(), new InMemorySecretStore(), ca))
            {
                int port = p.Start().Port;
                string reply = Wait(TestProxyClient.RawAsync(port, "GET /__iris_ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
                Check.True(reply.StartsWith("HTTP/1.1 200 OK\r\n"), "200");
                Check.True(reply.Contains("Cache-Control: no-store\r\n") && reply.Contains("Content-Length: 3\r\n"), "en-têtes");
                Check.True(reply.EndsWith("\r\n\r\nok\n"), "corps ok\\n puis fermeture");
                Check.Eq(0, p.Events.Ring.All.Count, "le ping n'émet aucun event");
                Wait(p.StopAsync());
            }
        }

        private static void Proxy_NonConnect405_BadAuthority400()
        {
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions("localhost"), new InMemorySecretStore(), ca))
            {
                int port = p.Start().Port;
                Check.True(Wait(TestProxyClient.RawAsync(port, "POST / HTTP/1.1\r\nHost: x\r\n\r\n")).StartsWith("HTTP/1.1 405 Method Not Allowed\r\n"), "non-CONNECT → 405");
                Check.True(Wait(TestProxyClient.RawAsync(port, "CONNECT nope HTTP/1.1\r\n\r\n")).StartsWith("HTTP/1.1 400 Bad Request\r\n"), "autorité sans port → 400");
                Check.True(Wait(TestProxyClient.RawAsync(port, "CONNECT h:99999 HTTP/1.1\r\n\r\n")).StartsWith("HTTP/1.1 400 "), "port hors plage → 400");
                Check.True(Wait(TestProxyClient.RawAsync(port, "GARBAGE\r\n\r\n")).StartsWith("HTTP/1.1 400 "), "ligne de requête invalide → 400");
                Check.True(Wait(TestProxyClient.RawAsync(port, "GET / HTTP/1.1\r\n" + new string('x', 70000) + ": y\r\n\r\n")).StartsWith("HTTP/1.1 400 "), "tête trop grande → 400");
                string host; int portOut;
                Check.True(ConnectHandler.ParseAuthority("api.example:443", out host, out portOut) && host == "api.example" && portOut == 443, "ParseAuthority");
                Check.True(!ConnectHandler.ParseAuthority(":443", out host, out portOut), "hôte vide refusé");
                Check.True(!ConnectHandler.ParseAuthority("h:0", out host, out portOut), "port 0 refusé");
                Check.Eq(0, p.Events.Ring.All.Count, "aucun event pour ces refus");
                Wait(p.StopAsync());
            }
        }

        private static void Proxy_TunnelPassthrough()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync("test_anthropic_key", Bytes("sk-ant-should-not-leak"), new[] { "localhost" }, T0));
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions("api.anthropic.com"), store, ca)) // localhost n'est PAS whitelisté → tunnel
            {
                int port = p.Start().Port;
                ProxyClientResponse r;
                using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                {
                    Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "200 Connection Established");
                    Wait(c.StartTlsAsync("localhost", mock.CACertificate)); // le client voit le VRAI certificat du mock : pas de MITM
                    HttpHeaders h = new HttpHeaders();
                    h.Add("Host", "localhost");
                    h.Add("x-api-key", "{{kc:test_anthropic_key}}");
                    Wait(c.SendAsync("POST", "/v1/messages", h, Bytes("{\"prompt\":\"hi\"}")));
                    r = Wait(c.ReadResponseAsync());
                }
                Check.True(r.Status == 200 && r.Text == "OK", "réponse du mock à travers le tunnel");
                MockUpstream.ReceivedRequest received = Wait(mock.WaitForRequestAsync(TimeSpan.FromSeconds(5)));
                Check.Eq("{{kc:test_anthropic_key}}", received.Head.Headers.First("x-api-key"), "le placeholder traverse chiffré, jamais substitué");
                Event e = null;
                for (int i = 0; i < 50 && (e = FirstEvent(p, EventKind.PassThrough)) == null; i++) Wait(Task.Delay(20));
                Check.True(e != null, "event passThrough à la fermeture du tunnel");
                Check.True(e.Host == "localhost" && e.Method == "CONNECT" && e.Path == "localhost:" + mock.Port && e.DurationMs.HasValue && e.SubstitutedSecrets.Count == 0, "contenu de l'event");
                Check.True(!Json.EmitCompact(e.ToJson()).Contains("sk-ant"), "aucune valeur dans l'event");
                Wait(p.StopAsync());
            }
        }

        private static void Proxy_Tunnel502()
        {
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions(), new InMemorySecretStore(), ca))
            {
                int port = p.Start().Port;
                int closed = FreePort();
                using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                {
                    Check.Eq(502, Wait(c.ConnectTunnelAsync("127.0.0.1", closed)), "amont injoignable → 502");
                    Check.True(c.LastErrorBody.Length > 0, "corps texte court");
                }
                Event e = FirstEvent(p, EventKind.Error);
                Check.True(e != null && e.Host == "127.0.0.1" && e.Method == "CONNECT", "event error");
                Wait(p.StopAsync());
            }
        }

        private static void Proxy_UpdateRulesPauseAndOptions()
        {
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions("api.anthropic.com"), new InMemorySecretStore(), ca))
            {
                Check.True(p.IsAllowed("API.Anthropic.com:443") && !p.IsAllowed("localhost"), "IsAllowed normalise");
                p.UpdateRules(new[] { new MITMRule("Localhost", T0, RuleOrigin.User) });
                Check.True(p.IsAllowed("localhost") && !p.IsAllowed("api.anthropic.com"), "UpdateRules remplace la whitelist à chaud");
                Check.True(!p.Paused, "non en pause au départ");
                p.SetPaused(true);
                Check.True(p.Paused, "SetPaused");
                ProxyOptions fromConfig = ProxyOptions.FromConfig(Config.Default(T0));
                Check.True(fromConfig.ListenHost == "127.0.0.1" && fromConfig.ListenPort == 8888 && fromConfig.AllowedHosts.Contains("api.anthropic.com") && fromConfig.Security.MaxSubstitutionsPerMinute == 60, "FromConfig");
                Check.True(fromConfig.IdleTimeout == TimeSpan.FromSeconds(120) && fromConfig.ConnectTimeout == TimeSpan.FromSeconds(10) && fromConfig.ShutdownGrace == TimeSpan.FromSeconds(5), "délais de la spec §6.3");
                Check.True(fromConfig.UpstreamTrust is SystemTrust, "confiance amont = magasin Windows par défaut");
            }
        }

        private static void Proxy_StopClosesConnections_AndIdleTimeout()
        {
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions();
                o.ShutdownGrace = TimeSpan.FromMilliseconds(300);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "tunnel ouvert");
                        for (int i = 0; i < 50 && p.ActiveConnections == 0; i++) Wait(Task.Delay(20));
                        Check.Eq(1, p.ActiveConnections, "une connexion active");
                        DateTime t = DateTime.UtcNow;
                        Wait(p.StopAsync());
                        Check.True((DateTime.UtcNow - t) < TimeSpan.FromSeconds(3), "StopAsync rend en moins de 3 s avec une connexion ouverte");
                        Check.Eq(0, p.ActiveConnections, "connexion fermée de force après le délai de grâce");
                        byte[] buf = new byte[8];
                        int n;
                        try { n = Wait(c.Http.ReadAsync(buf, 0, 8, CancellationToken.None)); } catch (System.IO.IOException) { n = 0; }
                        Check.Eq(0, n, "le client voit la fermeture");
                    }
                }
                ProxyOptions idle = TestOptions();
                idle.IdleTimeout = TimeSpan.FromMilliseconds(300);
                using (ProxyServer p = NewProxy(idle, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "tunnel ouvert");
                        byte[] buf = new byte[8];
                        DateTime t = DateTime.UtcNow;
                        int n;
                        try { n = Wait(c.Http.ReadAsync(buf, 0, 8, CancellationToken.None)); } catch (System.IO.IOException) { n = 0; }
                        Check.True(n == 0 && (DateTime.UtcNow - t) < TimeSpan.FromSeconds(3), "tunnel inactif fermé après le délai d'inactivité");
                    }
                    Wait(p.StopAsync());
                }
            }
        }
    }
}
```

`Main` : `Check.Run("Proxy : démarrage, arrêt, port occupé, bouclage seul", Proxy_StartStopAndLoopbackOnly); Check.Run("Proxy : /__iris_ping", Proxy_Ping); Check.Run("Proxy : 405 et 400", Proxy_NonConnect405_BadAuthority400); Check.Run("Proxy : tunnel hors whitelist, certificat amont préservé", Proxy_TunnelPassthrough); Check.Run("Proxy : amont injoignable → 502", Proxy_Tunnel502); Check.Run("Proxy : UpdateRules, pause, options", Proxy_UpdateRulesPauseAndOptions); Check.Run("Proxy : arrêt forcé et délai d'inactivité", Proxy_StopClosesConnections_AndIdleTimeout);` — `TEST_SOURCES` : ajouter `"%TESTS%\MockUpstream.cs" "%TESTS%\TestProxyClient.cs" "%TESTS%\ProxyTests.cs"`.

- [ ] **Step 4: Vérifier l'échec** — `CS0246 'ProxyServer'` / `'ProxyOptions'`.

- [ ] **Step 5: Écrire `src\IrisKit\Proxy\ProxyOptions.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;

namespace IrisKit
{
    public class ProxyException : Exception
    {
        public ProxyException(string message) : base(message) { }
        public ProxyException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>Port d'écoute déjà pris : irisd sort avec le code 3 (spec §7).</summary>
    public sealed class ProxyPortInUseException : ProxyException
    {
        public int Port { get; private set; }
        public ProxyPortInUseException(int port, Exception inner)
            : base("le port " + port.ToString(CultureInfo.InvariantCulture) + " est déjà utilisé : un autre irisd tourne, ou un autre programme écoute dessus", inner)
        {
            Port = port;
        }
    }

    /// <summary>Options du proxy (spec §6) ; `FromConfig` lit `broker.listen`, `hosts` et `security`.</summary>
    public sealed class ProxyOptions
    {
        public string ListenHost = "127.0.0.1";
        public int ListenPort = 8888;
        public ISet<string> AllowedHosts = new HashSet<string>(StringComparer.Ordinal);
        public SecurityConfig Security = new SecurityConfig(ExfilPolicy.BlockAndNotify, 60);
        public IUpstreamTrust UpstreamTrust = new SystemTrust();
        public TimeSpan IdleTimeout = TimeSpan.FromSeconds(120);
        public TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
        public TimeSpan ShutdownGrace = TimeSpan.FromSeconds(5);

        public static ProxyOptions FromConfig(Config config)
        {
            ProxyOptions o = new ProxyOptions();
            string[] parts = config.Broker.Listen.Split(':');
            o.ListenHost = parts[0];
            o.ListenPort = int.Parse(parts[1], CultureInfo.InvariantCulture);
            foreach (string h in config.AllowedHosts) o.AllowedHosts.Add(HostName.Normalize(h));
            o.Security = config.Security;
            return o;
        }

        public void Validate()
        {
            IPAddress ip;
            if (!IPAddress.TryParse(ListenHost, out ip) || !IPAddress.IsLoopback(ip))
                throw new ProxyException("le proxy n'écoute que sur une adresse de bouclage (127.0.0.1 ou ::1), pas sur " + ListenHost + " : il injecterait les secrets de l'utilisateur pour tout le réseau");
            if (ListenPort < 0 || ListenPort > 65535) throw new ProxyException("port d'écoute invalide : " + ListenPort);
            if (Security == null) throw new ProxyException("Security manquant");
            if (UpstreamTrust == null) throw new ProxyException("UpstreamTrust manquant");
        }
    }
}
```

- [ ] **Step 6: Écrire `src\IrisKit\Proxy\UpstreamClient.cs`**

```csharp
using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Connexion amont impossible (DNS, TCP, délai, TLS). Message sans valeur de secret.</summary>
    public sealed class UpstreamException : Exception
    {
        public UpstreamException(string message, Exception inner) : base(message, inner) { }
    }

    public sealed class UpstreamConnection : IDisposable
    {
        private readonly TcpClient client;
        private readonly SslStream tls;
        public HttpConnection Http { get; private set; }
        public string Host { get; private set; }
        public int Port { get; private set; }

        internal UpstreamConnection(TcpClient client, SslStream tls, string host, int port)
        {
            this.client = client; this.tls = tls; Host = host; Port = port;
            Http = new HttpConnection(tls);
        }

        public void Dispose()
        {
            try { tls.Dispose(); } catch (IOException) { }
            client.Close();
        }
    }

    /// <summary>TCP avec délai de connexion puis SslStream client : TLS 1.2 minimum, SNI = hôte, validation par IUpstreamTrust (spec §6.1).</summary>
    public sealed class UpstreamClient
    {
        private readonly IUpstreamTrust trust;
        private readonly TimeSpan connectTimeout;

        public UpstreamClient(IUpstreamTrust trust, TimeSpan connectTimeout)
        {
            if (trust == null) throw new ArgumentNullException("trust");
            this.trust = trust;
            this.connectTimeout = connectTimeout;
        }

        /// <summary>Connexion TCP bornée dans le temps ; lève UpstreamException (SocketException ou délai).</summary>
        public static async Task<TcpClient> ConnectTcpAsync(string host, int port, TimeSpan timeout, CancellationToken cancel)
        {
            TcpClient client = new TcpClient();
            try
            {
                Task connect = client.ConnectAsync(host, port);
                using (CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancel))
                {
                    Task delay = Task.Delay(timeout, cts.Token);
                    Task first = await Task.WhenAny(connect, delay).ConfigureAwait(false);
                    if (first == delay)
                    {
                        connect.ContinueWith(delegate(Task t) { Exception ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                        cancel.ThrowIfCancellationRequested();
                        throw new UpstreamException("connexion à " + host + ":" + port + " sans réponse après " + (int)timeout.TotalSeconds + " s", null);
                    }
                    cts.Cancel();
                    await connect.ConfigureAwait(false);
                }
                client.NoDelay = true;
                return client;
            }
            catch (SocketException ex)
            {
                client.Close();
                throw new UpstreamException("connexion à " + host + ":" + port + " impossible : " + ex.Message, ex);
            }
            catch (Exception)
            {
                client.Close();
                throw;
            }
        }

        public async Task<UpstreamConnection> ConnectTlsAsync(string host, int port, CancellationToken cancel)
        {
            TcpClient client = await ConnectTcpAsync(host, port, connectTimeout, cancel).ConfigureAwait(false);
            SslStream tls = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(trust));
            try
            {
                await tls.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false).ConfigureAwait(false);
                return new UpstreamConnection(client, tls, host, port);
            }
            catch (AuthenticationException ex)
            {
                tls.Dispose(); client.Close();
                throw new UpstreamException("TLS vers " + host + ":" + port + " refusé (" + trust.Describe() + ") : " + ex.Message, ex);
            }
            catch (IOException ex)
            {
                tls.Dispose(); client.Close();
                throw new UpstreamException("TLS vers " + host + ":" + port + " interrompu : " + ex.Message, ex);
            }
        }
    }
}
```

- [ ] **Step 7: Écrire `src\IrisKit\Proxy\ProxyServer.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Une connexion cliente acceptée : socket, lecteur HTTP, fermeture forcée possible à l'arrêt.</summary>
    public sealed class ClientConnection : IDisposable
    {
        public TcpClient Client { get; private set; }
        public HttpConnection Http { get; private set; }
        public string Remote { get; private set; }

        public ClientConnection(TcpClient client)
        {
            Client = client;
            Remote = client.Client.RemoteEndPoint == null ? "?" : client.Client.RemoteEndPoint.ToString();
            Http = new HttpConnection(client.GetStream());
        }

        public void Close()
        {
            try { Client.Close(); } catch (ObjectDisposedException) { }
        }

        public void Dispose() { Close(); }
    }

    /// <summary>
    /// Proxy HTTPS local (spec §6) : TcpListener sur broker.listen (bouclage seul), une Task par connexion, whitelist MITM à chaud,
    /// pause, arrêt coopératif (listener fermé, délai de grâce, fermeture forcée, feuilles détruites).
    /// </summary>
    public sealed class ProxyServer : IDisposable
    {
        public ProxyOptions Options { get; private set; }
        public IPEndPoint ListenEndPoint { get; private set; }
        public LeafCertCache Leaves { get; private set; }
        public EventPipeline Events { get; private set; }
        public ISecretStore Secrets { get; private set; }
        public UpstreamClient Upstream { get; private set; }
        public Func<DateTime> Clock { get; private set; }
        /// <summary>Posé par la tâche 6 (RequestProcessor) ; null tant que le MITM n'est pas branché.</summary>
        public RequestProcessor Processor { get; set; }

        private readonly object gate = new object();
        private readonly HashSet<ClientConnection> connections = new HashSet<ClientConnection>();
        private readonly List<Task> tasks = new List<Task>();
        private HashSet<string> allowed;
        private volatile bool paused;
        private TcpListener listener;
        private CancellationTokenSource stopping;
        private Task acceptLoop;

        public ProxyServer(ProxyOptions options, ISecretStore secrets, CAManager ca, EventPipeline events, Func<DateTime> clock)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (secrets == null) throw new ArgumentNullException("secrets");
            if (ca == null) throw new ArgumentNullException("ca");
            if (events == null) throw new ArgumentNullException("events");
            Options = options;
            Secrets = secrets;
            Events = events;
            Clock = clock;
            Leaves = new LeafCertCache(ca, clock);
            Upstream = new UpstreamClient(options.UpstreamTrust, options.ConnectTimeout);
            allowed = new HashSet<string>(StringComparer.Ordinal);
            foreach (string h in options.AllowedHosts) allowed.Add(HostName.Normalize(h));
        }

        // ---- Whitelist et pause ----------------------------------------------

        public bool Paused { get { return paused; } }
        public void SetPaused(bool value) { paused = value; Log.Warn("proxy", value ? "daemon en pause : plus aucune substitution" : "daemon repris"); }

        public ISet<string> AllowedHosts { get { lock (gate) { return new HashSet<string>(allowed, StringComparer.Ordinal); } } }

        public bool IsAllowed(string host)
        {
            string key = HostName.Normalize(host);
            lock (gate) { return allowed.Contains(key); }
        }

        /// <summary>Remplace la whitelist MITM ; vaut pour toute nouvelle connexion.</summary>
        public void UpdateRules(IList<MITMRule> rules)
        {
            HashSet<string> next = new HashSet<string>(StringComparer.Ordinal);
            foreach (MITMRule r in rules) next.Add(HostName.Normalize(r.Host));
            lock (gate) { allowed = next; }
            Log.Info("proxy", "whitelist MITM mise à jour : " + next.Count + " hôte(s)");
        }

        // ---- Cycle de vie -------------------------------------------------------

        public IPEndPoint Start()
        {
            Options.Validate();
            if (listener != null) throw new ProxyException("proxy déjà démarré");
            TcpListener l = new TcpListener(IPAddress.Parse(Options.ListenHost), Options.ListenPort);
            try { l.Start(64); }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.AddressAlreadyInUse || ex.SocketErrorCode == SocketError.AccessDenied)
                    throw new ProxyPortInUseException(Options.ListenPort, ex);
                throw new ProxyException("écoute sur " + Options.ListenHost + ":" + Options.ListenPort + " impossible : " + ex.Message, ex);
            }
            listener = l;
            ListenEndPoint = (IPEndPoint)l.LocalEndpoint;
            stopping = new CancellationTokenSource();
            acceptLoop = AcceptLoopAsync(stopping.Token);
            Log.Info("proxy", "écoute sur " + ListenEndPoint + ", whitelist MITM : " + string.Join(", ", AllowedHosts));
            return ListenEndPoint;
        }

        private async Task AcceptLoopAsync(CancellationToken cancel)
        {
            while (!cancel.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { if (cancel.IsCancellationRequested) return; continue; }
                catch (InvalidOperationException) { return; }
                client.NoDelay = true;
                ClientConnection conn = new ClientConnection(client);
                Task t = ServeAsync(conn, cancel);
                lock (gate) { tasks.Add(t); tasks.RemoveAll(delegate(Task x) { return x.IsCompleted; }); }
            }
        }

        private async Task ServeAsync(ClientConnection conn, CancellationToken cancel)
        {
            Register(conn);
            try { await ConnectHandler.HandleAsync(this, conn, cancel).ConfigureAwait(false); }
            catch (Exception ex)
            {
                if (!(ex is OperationCanceledException)) Log.Debug("proxy", "connexion " + conn.Remote + " terminée sur " + ex.GetType().Name + " : " + ex.Message);
            }
            finally
            {
                Unregister(conn);
                conn.Dispose();
            }
        }

        public void Register(ClientConnection conn) { lock (gate) { connections.Add(conn); } }
        public void Unregister(ClientConnection conn) { lock (gate) { connections.Remove(conn); } }

        public int ActiveConnections { get { lock (gate) { return connections.Count; } } }

        /// <summary>Ferme le listener, laisse ShutdownGrace aux connexions, puis les ferme de force ; détruit les feuilles.</summary>
        public async Task StopAsync()
        {
            if (listener == null) return;
            stopping.Cancel();
            try { listener.Stop(); } catch (SocketException) { }
            List<Task> pending;
            lock (gate) { pending = new List<Task>(tasks); }
            Task all = Task.WhenAll(pending);
            Task done = await Task.WhenAny(all, Task.Delay(Options.ShutdownGrace)).ConfigureAwait(false);
            if (done != all)
            {
                List<ClientConnection> open;
                lock (gate) { open = new List<ClientConnection>(connections); }
                Log.Warn("proxy", open.Count + " connexion(s) encore ouverte(s) après " + (int)Options.ShutdownGrace.TotalSeconds + " s : fermeture forcée");
                foreach (ClientConnection c in open) c.Close();
                try { await Task.WhenAny(all, Task.Delay(TimeSpan.FromSeconds(2))).ConfigureAwait(false); } catch (Exception) { }
            }
            try { await acceptLoop.ConfigureAwait(false); } catch (Exception) { }
            lock (gate) { tasks.Clear(); connections.Clear(); }
            listener = null;
            Leaves.Dispose();
            Log.Info("proxy", "arrêté");
        }

        public void Dispose()
        {
            if (listener != null) StopAsync().GetAwaiter().GetResult();
            else Leaves.Dispose();
        }
    }
}
```

- [ ] **Step 8: Écrire `src\IrisKit\Proxy\ConnectHandler.cs`**

```csharp
using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`GET /__iris_ping` → `200 ok\n` sans event ni substitution (utilisé par `iris doctor`).</summary>
    public static class PingResponder
    {
        public static bool Matches(HttpRequestHead head)
        {
            return head.Method == "GET" && head.Target == "/__iris_ping";
        }

        public static async Task RespondAsync(HttpConnection c, CancellationToken cancel)
        {
            byte[] bytes = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nCache-Control: no-store\r\n\r\nok\n");
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
            await c.FlushAsync(cancel).ConfigureAwait(false);
        }
    }

    /// <summary>Première requête d'une connexion (spec §6.1) : ping, non-CONNECT → 405, autorité illisible → 400, whitelist → MITM, sinon tunnel.</summary>
    public static class ConnectHandler
    {
        public static async Task HandleAsync(ProxyServer server, ClientConnection conn, CancellationToken cancel)
        {
            HttpConnection http = conn.Http;
            http.ReadTimeout = server.Options.IdleTimeout;
            HttpRequestHead head;
            try { head = await HttpParser.ReadRequestHeadAsync(http, cancel).ConfigureAwait(false); }
            catch (HttpProtocolException ex)
            {
                Log.Debug("proxy", conn.Remote + " : " + ex.Message);
                await WriteSimpleResponseAsync(http, 400, ex.Message, cancel).ConfigureAwait(false);
                return;
            }
            catch (TimeoutException) { return; }
            catch (IOException) { return; }
            if (head == null) return;

            if (PingResponder.Matches(head))
            {
                await PingResponder.RespondAsync(http, cancel).ConfigureAwait(false);
                return;
            }
            if (head.Method != "CONNECT")
            {
                Log.Warn("proxy", "requête " + head.Method + " reçue hors tunnel depuis " + conn.Remote + " : le proxy n'accepte que CONNECT (HTTPS_PROXY)");
                await WriteSimpleResponseAsync(http, 405, "irispc n'accepte que CONNECT (configurez HTTPS_PROXY)", cancel).ConfigureAwait(false);
                return;
            }
            string host; int port;
            if (!ParseAuthority(head.Target, out host, out port))
            {
                await WriteSimpleResponseAsync(http, 400, "autorité CONNECT invalide", cancel).ConfigureAwait(false);
                return;
            }
            if (server.IsAllowed(host)) await MITMHandler.RunAsync(server, conn, host, port, cancel).ConfigureAwait(false);
            else await TunnelHandler.RunAsync(server, conn, host, port, cancel).ConfigureAwait(false);
        }

        /// <summary>`host:port`, hôte non vide, port 1–65535.</summary>
        public static bool ParseAuthority(string target, out string host, out int port)
        {
            host = null; port = 0;
            if (string.IsNullOrEmpty(target)) return false;
            int colon = target.LastIndexOf(':');
            if (colon <= 0 || colon == target.Length - 1) return false;
            if (!int.TryParse(target.Substring(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535) return false;
            host = target.Substring(0, colon);
            return host.Length > 0 && host.IndexOf('/') < 0 && host.IndexOf(' ') < 0;
        }

        /// <summary>Réponse courte en texte (400, 405, 502) puis Connection: close ; l'appelant ferme.</summary>
        public static async Task WriteSimpleResponseAsync(HttpConnection c, int status, string body, CancellationToken cancel)
        {
            byte[] text = System.Text.Encoding.UTF8.GetBytes((body ?? "") + "\n");
            HttpHeaders h = new HttpHeaders();
            h.Add("Content-Type", "text/plain; charset=utf-8");
            h.Add("Content-Length", text.Length.ToString(CultureInfo.InvariantCulture));
            h.Add("Connection", "close");
            string line = HttpParser.StatusLine(status);
            int sp = line.IndexOf(' ');
            try
            {
                await HttpParser.WriteAsync(c, new HttpResponseHead("HTTP/1.1", status, line.Substring(sp + 1), h), cancel).ConfigureAwait(false);
                await c.WriteAsync(text, 0, text.Length, cancel).ConfigureAwait(false);
                await c.FlushAsync(cancel).ConfigureAwait(false);
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }
    }

    /// <summary>Bouchon remplacé par la tâche 7 : un hôte whitelisté reçoit 502 tant que le MITM n'existe pas.</summary>
    public static class MITMHandler
    {
        public static Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            return ConnectHandler.WriteSimpleResponseAsync(conn.Http, 502, "MITM non disponible (phase 2, tâche 7)", cancel);
        }
    }
}
```

- [ ] **Step 9: Écrire `src\IrisKit\Proxy\TunnelHandler.cs`**

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Hôte hors whitelist (SPECS §8.3) : TCP vers l'autorité du CONNECT, 200, pompe bidirectionnelle, event passThrough à la fermeture.</summary>
    public static class TunnelHandler
    {
        public static async Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            DateTime started = server.Clock();
            Stopwatch watch = Stopwatch.StartNew();
            string path = host + ":" + port;
            TcpClient upstream;
            try { upstream = await UpstreamClient.ConnectTcpAsync(host, port, server.Options.ConnectTimeout, cancel).ConfigureAwait(false); }
            catch (UpstreamException ex)
            {
                Log.Warn("proxy", "tunnel vers " + path + " impossible : " + ex.Message);
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", path, 502, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                await ConnectHandler.WriteSimpleResponseAsync(conn.Http, 502, "amont injoignable : " + ex.Message, cancel).ConfigureAwait(false);
                return;
            }
            using (upstream)
            {
                HttpConnection up = new HttpConnection(upstream.GetStream());
                up.ReadTimeout = server.Options.IdleTimeout;
                HttpConnection client = conn.Http;
                try
                {
                    byte[] ok = HttpParser.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await client.WriteAsync(ok, 0, ok.Length, cancel).ConfigureAwait(false);
                    await client.FlushAsync(cancel).ConfigureAwait(false);
                    byte[] early = client.TakeBuffered();
                    if (early.Length > 0) await up.WriteAsync(early, 0, early.Length, cancel).ConfigureAwait(false);
                    Log.Debug("proxy", "tunnel " + conn.Remote + " → " + path);
                    Task a = PumpAsync(client, up, cancel);
                    Task b = PumpAsync(up, client, cancel);
                    await Task.WhenAny(a, b).ConfigureAwait(false);
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                finally
                {
                    conn.Close();
                    upstream.Close();
                }
            }
            server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.PassThrough, host, "CONNECT", path, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
            Log.Info("proxy", "tunnel fermé " + path + " (" + watch.ElapsedMilliseconds + " ms)");
        }

        /// <summary>Copie jusqu'à EOF, erreur, annulation ou inactivité ; l'appelant ferme les deux côtés.</summary>
        private static async Task PumpAsync(HttpConnection from, HttpConnection to, CancellationToken cancel)
        {
            byte[] block = new byte[HttpParser.RelayBlock];
            try
            {
                while (true)
                {
                    int n = await from.ReadAsync(block, 0, block.Length, cancel).ConfigureAwait(false);
                    if (n == 0) return;
                    await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (TimeoutException) { }
            catch (OperationCanceledException) { }
        }
    }
}
```

- [ ] **Step 10: Sources + vert**

`IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Proxy\ProxyOptions.cs" "%SRC%\IrisKit\Proxy\UpstreamClient.cs" "%SRC%\IrisKit\Proxy\ProxyServer.cs" "%SRC%\IrisKit\Proxy\ConnectHandler.cs" "%SRC%\IrisKit\Proxy\TunnelHandler.cs"`. `ProxyServer.Processor` est de type `RequestProcessor`, qui n'existe qu'à la tâche 6 : **dans cette tâche**, déclarer la propriété comme `public object Processor { get; set; }` et la retyper à la tâche 6 (une ligne).

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
```

Attendu : `99 test(s) réussi(s)`. Si `Proxy_TunnelPassthrough` échoue sur la poignée de main client (« nom d'hôte ») : le mock émet une feuille pour `localhost`, le client authentifie `localhost`, le port du CONNECT est celui du mock — vérifier que `TunnelHandler` honore le port du CONNECT et non 443. Si `Proxy_StopClosesConnections_AndIdleTimeout` dépasse 3 s : `StopAsync` doit fermer les sockets (`Close()`) et non seulement annuler le jeton, car `NetworkStream.ReadAsync` ignore le jeton en .NET Framework.

- [ ] **Step 11: Commit**

```bash
git add src/IrisKit/Proxy tests/MockUpstream.cs tests/TestProxyClient.cs tests/ProxyTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): ProxyServer (bouclage, arrêt coopératif), ConnectHandler (ping, 405, 400), TunnelHandler, UpstreamClient et harnais MockUpstream/TestProxyClient

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 6: `RequestProcessor` — scan → règles → substitution, pause, drapeaux, politique

**Files:**
- Create: `src\IrisKit\Proxy\RequestProcessor.cs`
- Modify: `src\IrisKit\Proxy\ProxyServer.cs` (type de `Processor`, construction)
- Create: `tests\ProcessorTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `PlaceholderScanner`, `PlaceholderEngine`, `ExfilRuleEngine`, `RequestContext`, `ExfilDecision` (tâches 2–3), `HttpRequestHead`, `HttpHeaders` (tâche 1), `ProxyServer` (tâche 5), `ISecretStore`, `Alert`, `EventKind`, `EventFlags`, `ExfilPolicy`, `HostName`, `Log` (phase 1).
- Produces: `RequestOutcome { Bypassed, Substituted, NoMatch, Blocked }` ; `ProcessedRequest` (`Head : HttpRequestHead` (version `HTTP/1.1`, en-têtes préparés), `Body : byte[]`, `Outcome`, `Substituted : IList<string>`, `Unresolved : IList<string>`, `Alert`, `Flags : EventFlags`, `EventKind : EventKind`) ; `RequestProcessor(ISecretStore secrets, Func<int> maxPerMinute, Func<ExfilPolicy> policy, Action pause, Func<DateTime> clock)` (`ProcessAsync(HttpRequestHead head, byte[] body, bool bodyTooLarge, string host, bool paused) : Task<ProcessedRequest>`, `Rules : ExfilRuleEngine`, `Engine : PlaceholderEngine`, `LastUsageRecording : Task`) ; `ProxyServer.Processor : RequestProcessor` construit dans le constructeur du serveur (politique et seuil lus dans `Options.Security`, `pause` = `SetPaused(true)`).

- [ ] **Step 1: Écrire `tests\ProcessorTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- RequestProcessor (sans réseau) ------------------------------------------

        private static int pauseCalls;

        private static RequestProcessor Processor(ISecretStore store, int maxPerMinute, ExfilPolicy policy)
        {
            pauseCalls = 0;
            return new RequestProcessor(store, delegate { return maxPerMinute; }, delegate { return policy; }, delegate { pauseCalls++; }, delegate { return T0; });
        }

        private static HttpRequestHead Req(string method, string target, params string[] pairs)
        {
            return new HttpRequestHead(method, target, "HTTP/1.1", H(pairs));
        }

        private static void Processor_SubstitutesStripsHopHeadersRecordsUsage()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 1, ExfilPolicy.BlockAndNotify);
            byte[] body = Bytes("{\"t\":1}");
            HttpRequestHead head = Req("POST", "/v1/messages?x=1", "Host", "example.com", "x-api-key", "{{kc:k}}", "Accept-Encoding", "gzip, br", "Proxy-Connection", "keep-alive", "Expect", "100-continue", "Content-Length", "7");
            ProcessedRequest r = Wait(p.ProcessAsync(head, body, false, "EXAMPLE.com:443", false));
            Check.Eq(RequestOutcome.Substituted, r.Outcome, "substitué");
            Check.Eq(EventKind.Substituted, r.EventKind, "event substituted");
            Check.Eq("VALUE_K", r.Head.Headers.First("x-api-key"), "valeur réelle dans l'en-tête sortant");
            Check.True(!r.Head.Headers.Contains("Accept-Encoding") && !r.Head.Headers.Contains("Proxy-Connection") && !r.Head.Headers.Contains("Expect"), "Accept-Encoding, Proxy-Connection et Expect retirés");
            Check.Eq("example.com", r.Head.Headers.First("Host"), "les autres en-têtes restent");
            Check.Eq("HTTP/1.1", r.Head.Version, "version forcée");
            Check.Eq("/v1/messages?x=1", r.Head.Target, "cible inchangée");
            Check.True(ReferenceEquals(r.Body, body), "corps inchangé (même tableau)");
            Check.Eq("7", r.Head.Headers.First("Content-Length"), "Content-Length inchangé quand le corps ne change pas");
            Check.Eq(EventFlags.None, r.Flags, "aucun drapeau");
            Check.Eq("k", string.Join(",", r.Substituted), "noms substitués");
            Wait(p.LastUsageRecording);
            Check.Eq(1L, Wait(store.SecretAsync("k")).UsageCount, "usage enregistré (détaché)");
            r = Wait(p.ProcessAsync(head, body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.Alert.Rule == ExfilRule.VolumeAnomaly, "R5 compte la substitution précédente (seuil 1)");
            Check.Eq("{{kc:k}}", r.Head.Headers.First("x-api-key"), "bloqué = littéral transmis");
        }

        private static void Processor_BlockedAppliesPolicy()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            HttpRequestHead head = Req("POST", "/v1/messages", "Authorization", "Bearer {{kc:k}}");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            ProcessedRequest r = Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.EventKind == EventKind.ExfilBlocked, "R1 → exfilBlocked");
            Check.True(r.Alert.Rule == ExfilRule.HostMismatch && r.Alert.Severity == AlertSeverity.High && r.Alert.SecretName == "k" && r.Alert.Snippet.Contains("{{kc:k}}"), "alerte R1 avec snippet");
            Check.Eq("Bearer {{kc:k}}", r.Head.Headers.First("Authorization"), "placeholder littéral conservé");
            Check.Eq(0, r.Substituted.Count, "rien substitué");
            Check.Eq(0, pauseCalls, "block_only : pas de pause");
            p = Processor(store, 60, ExfilPolicy.BlockNotifyPause);
            r = Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && pauseCalls == 1, "block_notify_pause : pause demandée");
            p = Processor(store, 60, ExfilPolicy.BlockAndNotify);
            Wait(p.ProcessAsync(head, null, false, "evil.example", false));
            Check.Eq(0, pauseCalls, "block_and_notify : pas de pause (notification = lot app)");
        }

        private static void Processor_PausedBypasses()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 1, ExfilPolicy.BlockOnly);
            HttpRequestHead head = Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Accept-Encoding", "gzip");
            ProcessedRequest r = Wait(p.ProcessAsync(head, null, false, "example.com", true));
            Check.Eq(RequestOutcome.Bypassed, r.Outcome, "en pause : contourné");
            Check.Eq(EventKind.NoMatch, r.EventKind, "spec socle : noMatch avec drapeau paused");
            Check.Eq(EventFlags.Paused, r.Flags, "drapeau paused");
            Check.Eq("{{kc:k}}", r.Head.Headers.First("x-api-key"), "placeholder intact");
            Check.True(!r.Head.Headers.Contains("Accept-Encoding"), "Accept-Encoding retiré même en pause");
            r = Wait(p.ProcessAsync(head, null, false, "example.com", false));
            Check.Eq(RequestOutcome.Substituted, r.Outcome, "hors pause, la pause n'a pas consommé le quota R5");
        }

        private static void Processor_FlagsBodyTooLargeNonUtf8Compressed()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_K");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            byte[] partial = Bytes("{{kc:k}} dans un corps trop grand");
            ProcessedRequest r = Wait(p.ProcessAsync(Req("POST", "/up", "x-api-key", "{{kc:k}}", "Content-Length", "99999999"), partial, true, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && r.Flags == EventFlags.BodyTooLarge, "corps trop grand : en-têtes scannés, drapeau bodyTooLarge");
            Check.True(ReferenceEquals(r.Body, partial) && r.Head.Headers.First("Content-Length") == "99999999", "corps et Content-Length intacts (relais streaming par l'appelant)");
            Check.Eq("VALUE_K", r.Head.Headers.First("x-api-key"), "en-tête substitué malgré le corps trop grand");
            byte[] binary = new byte[] { 0xFF, 0xFE, 0x7B, 0x7B, 0x6B, 0x63, 0x3A, 0x6B, 0x7D, 0x7D }; // 0xFF 0xFE puis "{{kc:k}}"
            r = Wait(p.ProcessAsync(Req("POST", "/up", "x-api-key", "{{kc:k}}", "Content-Length", "10"), binary, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && r.Flags == EventFlags.NonUtf8, "corps non UTF-8 : non scanné (pas de R2), drapeau nonUtf8");
            Check.True(ReferenceEquals(r.Body, binary), "corps binaire inchangé");
            byte[] gz = Bytes("{{kc:k}}");
            r = Wait(p.ProcessAsync(Req("POST", "/up", "Content-Encoding", "gzip", "Content-Length", "8"), gz, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && r.Flags == EventFlags.CompressedBody, "corps compressé : non scanné, drapeau compressedBody, noMatch");
            Check.True(ReferenceEquals(r.Body, gz), "corps compressé inchangé");
            r = Wait(p.ProcessAsync(Req("POST", "/up", "Content-Length", "8"), gz, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked && r.Alert.Rule == ExfilRule.NonCanonicalLocation, "le même corps non compressé est scanné : R2");
        }

        private static void Processor_NoMatchUnknownAndContentLength()
        {
            InMemorySecretStore store = StoreWith("k", "VALUE_LONGER_THAN_PLACEHOLDER");
            RequestProcessor p = Processor(store, 60, ExfilPolicy.BlockOnly);
            ProcessedRequest r = Wait(p.ProcessAsync(Req("GET", "/plain", "Host", "example.com"), null, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && r.EventKind == EventKind.NoMatch && r.Flags == EventFlags.None && r.Substituted.Count == 0, "sans placeholder : noMatch");
            r = Wait(p.ProcessAsync(Req("GET", "/plain", "x-api-key", "{{kc:ghost}}"), null, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.NoMatch && string.Join(",", r.Unresolved) == "ghost" && r.Head.Headers.First("x-api-key") == "{{kc:ghost}}", "nom inconnu : noMatch, Unresolved, littéral");
            byte[] body = Bytes("{\"k\":\"{{kc:k}}\"}");
            r = Wait(p.ProcessAsync(Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Content-Length", body.Length.ToString()), body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Blocked, "corps connu → R2 (le corps n'est jamais substitué)");
            body = Bytes("{\"k\":\"{{kc:ghost}}\"}");
            r = Wait(p.ProcessAsync(Req("POST", "/v1", "x-api-key", "{{kc:k}}", "Content-Length", body.Length.ToString()), body, false, "example.com", false));
            Check.True(r.Outcome == RequestOutcome.Substituted && ReferenceEquals(r.Body, body), "inconnu dans le corps : ignoré, corps inchangé");
            Check.Eq(body.Length.ToString(), r.Head.Headers.First("Content-Length"), "Content-Length inchangé");
        }
    }
}
```

`Main` : `Check.Run("Processor : substitution, en-têtes de saut, usage", Processor_SubstitutesStripsHopHeadersRecordsUsage); Check.Run("Processor : blocage et politique on_exfil_attempt", Processor_BlockedAppliesPolicy); Check.Run("Processor : pause = contournement avec drapeau", Processor_PausedBypasses); Check.Run("Processor : drapeaux bodyTooLarge, nonUtf8, compressedBody", Processor_FlagsBodyTooLargeNonUtf8Compressed); Check.Run("Processor : noMatch, inconnu, Content-Length", Processor_NoMatchUnknownAndContentLength);` — `TEST_SOURCES` : ajouter `"%TESTS%\ProcessorTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — `CS0246 'RequestProcessor'`.

- [ ] **Step 3: Écrire `src\IrisKit\Proxy\RequestProcessor.cs`**

```csharp
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;

namespace IrisKit
{
    public enum RequestOutcome { Bypassed, Substituted, NoMatch, Blocked }

    /// <summary>Requête prête à partir vers l'amont et ce qu'il faut en consigner. Ne contient jamais une valeur de secret hors Head/Body.</summary>
    public sealed class ProcessedRequest
    {
        public HttpRequestHead Head { get; private set; }
        public byte[] Body { get; private set; }
        public RequestOutcome Outcome { get; private set; }
        public IList<string> Substituted { get; private set; }
        public IList<string> Unresolved { get; private set; }
        public Alert Alert { get; private set; }
        public EventFlags Flags { get; private set; }

        public ProcessedRequest(HttpRequestHead head, byte[] body, RequestOutcome outcome, IList<string> substituted, IList<string> unresolved, Alert alert, EventFlags flags)
        {
            Head = head; Body = body; Outcome = outcome;
            Substituted = substituted ?? new string[0];
            Unresolved = unresolved ?? new string[0];
            Alert = alert; Flags = flags;
        }

        /// <summary>Spec socle §6.2 : en pause, noMatch + drapeau paused (IRIS émet passThrough).</summary>
        public EventKind EventKind
        {
            get
            {
                switch (Outcome)
                {
                    case RequestOutcome.Substituted: return EventKind.Substituted;
                    case RequestOutcome.Blocked: return EventKind.ExfilBlocked;
                    default: return EventKind.NoMatch;
                }
            }
        }
    }

    /// <summary>
    /// Étape pure du MITM (spec §6.2 étapes 2–4 et 7) : retire Accept-Encoding / Proxy-Connection / Expect, pose les drapeaux
    /// bodyTooLarge / nonUtf8 / compressedBody, scanne (en-têtes et URL toujours, corps seulement s'il est bufferisé, UTF-8 et
    /// non compressé), évalue R1–R5, substitue, compte R5, enregistre l'usage en tâche détachée, applique on_exfil_attempt.
    /// </summary>
    public sealed class RequestProcessor
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        private readonly ISecretStore secrets;
        private readonly Func<ExfilPolicy> policy;
        private readonly Action pause;
        private readonly Func<DateTime> clock;

        public ExfilRuleEngine Rules { get; private set; }
        public PlaceholderEngine Engine { get; private set; }
        /// <summary>Dernier enregistrement d'usage détaché (les tests l'attendent) ; jamais sur le chemin de la requête.</summary>
        public Task LastUsageRecording { get; private set; }

        public RequestProcessor(ISecretStore secrets, Func<int> maxPerMinute, Func<ExfilPolicy> policy, Action pause, Func<DateTime> clock)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            this.secrets = secrets;
            this.policy = policy;
            this.pause = pause;
            this.clock = clock;
            Rules = new ExfilRuleEngine(secrets, maxPerMinute, clock);
            Engine = new PlaceholderEngine(secrets);
            LastUsageRecording = Task.FromResult(0);
        }

        public async Task<ProcessedRequest> ProcessAsync(HttpRequestHead head, byte[] body, bool bodyTooLarge, string host, bool paused)
        {
            HttpHeaders prepared = head.Headers.Clone();
            prepared.Remove("Accept-Encoding");   // SPECS §7.5 : on ne décompresse jamais les réponses
            prepared.Remove("Proxy-Connection");
            prepared.Remove("Expect");            // le 100 Continue a déjà été rendu au client
            HttpRequestHead preparedHead = new HttpRequestHead(head.Method, head.Target, "HTTP/1.1", prepared);
            string normalizedHost = HostName.Normalize(host);

            EventFlags flags = EventFlags.None;
            if (bodyTooLarge) flags |= EventFlags.BodyTooLarge;
            if (paused)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.Bypassed, null, null, null, flags | EventFlags.Paused);

            string bodyText = null;
            if (bodyTooLarge)
            {
                Log.Warn("proxy", "corps de plus de " + HttpParser.MaxBufferedBody / (1024 * 1024) + " MiB vers " + normalizedHost + " : relayé sans scan du corps");
            }
            else if (prepared.Contains("Content-Encoding"))
            {
                flags |= EventFlags.CompressedBody;
                if (body != null && body.Length > 0) Log.Warn("proxy", "corps compressé (" + prepared.First("Content-Encoding") + ") vers " + normalizedHost + " : pas de substitution dans le corps");
            }
            else if (body != null && body.Length > 0)
            {
                try { bodyText = StrictUtf8.GetString(body); }
                catch (DecoderFallbackException)
                {
                    flags |= EventFlags.NonUtf8;
                    Log.Debug("proxy", "corps non UTF-8 vers " + normalizedHost + " : non scanné");
                }
            }

            IList<PlaceholderHit> hits = PlaceholderScanner.Scan(prepared, head.Target, bodyText);
            if (hits.Count == 0) return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, null, null, flags);

            string path, query;
            PlaceholderScanner.SplitUri(head.Target, out path, out query);
            string contentType = prepared.First("Content-Type");
            RequestContext context = new RequestContext(normalizedHost, head.Method, path, contentType == null ? null : contentType.ToLowerInvariant());
            ExfilDecision decision = await Rules.EvaluateAsync(hits, context).ConfigureAwait(false);
            if (decision.Blocked)
            {
                ApplyPolicy(decision.Alert, normalizedHost);
                return new ProcessedRequest(preparedHead, body, RequestOutcome.Blocked, null, null, decision.Alert, flags);
            }
            if (decision.Resolvable.Count == 0)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, DistinctNames(hits), null, flags);

            ResolvedPayload payload = await Engine.SubstituteAsync(prepared, head.Target, bodyText == null ? null : body, decision.Resolvable).ConfigureAwait(false);
            if (payload.Substituted.Count == 0)
                return new ProcessedRequest(preparedHead, body, RequestOutcome.NoMatch, null, payload.Unresolved, null, flags);

            byte[] newBody = body;
            HttpHeaders newHeaders = payload.Headers;
            if (bodyText != null && payload.Body != null && !ReferenceEquals(payload.Body, body))
            {
                newBody = payload.Body;
                if (newHeaders.Contains("Content-Length")) newHeaders.Set("Content-Length", newBody.Length.ToString(CultureInfo.InvariantCulture));
            }
            Rules.RecordSubstitution(payload.Substituted);
            LastUsageRecording = RecordUsageAsync(payload.Substituted, clock());
            Log.Info("proxy", "substitution de " + string.Join(", ", payload.Substituted) + " pour " + head.Method + " " + normalizedHost + " " + path);
            return new ProcessedRequest(new HttpRequestHead(head.Method, payload.Uri, "HTTP/1.1", newHeaders), newBody, RequestOutcome.Substituted, payload.Substituted, payload.Unresolved, null, flags);
        }

        private void ApplyPolicy(Alert alert, string host)
        {
            Log.Warn("proxy", "tentative d'exfiltration bloquée : " + AlertWire.RuleToWire(alert.Rule) + " (" + AlertWire.SeverityToWire(alert.Severity) + ") secret " + alert.SecretName + " vers " + host + ", requête transmise intacte");
            switch (policy())
            {
                case ExfilPolicy.BlockAndNotify:
                    Log.Warn("proxy", "notification demandée (prise en charge par l'app, lot ultérieur)");
                    break;
                case ExfilPolicy.BlockNotifyPause:
                    Log.Warn("proxy", "politique block_notify_pause : mise en pause du daemon");
                    if (pause != null) pause();
                    break;
            }
        }

        /// <summary>Usage par secret, détaché et jamais fatal (nom seul dans le journal, jamais la valeur).</summary>
        private async Task RecordUsageAsync(IList<string> names, DateTime at)
        {
            foreach (string name in names)
            {
                try { await secrets.RecordUsageAsync(name, at).ConfigureAwait(false); }
                catch (SecretStoreException ex) { Log.Warn("proxy", "usage de " + name + " non enregistré : " + ex.Message); }
                catch (Exception ex) { Log.Warn("proxy", "usage de " + name + " non enregistré : " + ex.GetType().Name); }
            }
        }

        private static IList<string> DistinctNames(IList<PlaceholderHit> hits)
        {
            List<string> names = new List<string>();
            foreach (PlaceholderHit h in hits) if (!names.Contains(h.Name)) names.Add(h.Name);
            return names;
        }
    }
}
```

- [ ] **Step 4: Brancher le processeur dans `ProxyServer`**

Dans `src\IrisKit\Proxy\ProxyServer.cs`, remplacer `public object Processor { get; set; }` (et son commentaire) par `public RequestProcessor Processor { get; private set; }`, et ajouter en fin de constructeur :

```csharp
            ProxyServer self = this;
            Processor = new RequestProcessor(secrets,
                delegate { return self.Options.Security.MaxSubstitutionsPerMinute; },
                delegate { return self.Options.Security.OnExfilAttempt; },
                delegate { self.SetPaused(true); },
                clock);
```

- [ ] **Step 5: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Proxy\RequestProcessor.cs"`. → `104 test(s) réussi(s)`.

- [ ] **Step 6: Commit**

```bash
git add src/IrisKit/Proxy/RequestProcessor.cs src/IrisKit/Proxy/ProxyServer.cs tests/ProcessorTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): RequestProcessor — scan, règles, substitution, pause, drapeaux et politique on_exfil_attempt

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: `MITMHandler` — TLS côté agent, boucle keep-alive, relais streaming, events ; tests d'intégration

**Files:**
- Create: `src\IrisKit\Proxy\MITMHandler.cs`
- Modify: `src\IrisKit\Proxy\ConnectHandler.cs` (retirer le bouchon `MITMHandler`)
- Create: `tests\MITMTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: tout ce qui précède ; `ProxyServer.Leaves/Upstream/Processor/Events/Paused/Options/Clock`, `ClientConnection`, `ConnectHandler.WriteSimpleResponseAsync`, `PingResponder`, `HttpParser.*`, `UpstreamClient.ConnectTlsAsync`, `UpstreamConnection`.
- Produces: `MITMHandler.RunAsync(ProxyServer, ClientConnection, string host, int port, CancellationToken)` (remplace le bouchon).

- [ ] **Step 1: Écrire `tests\MITMTests.cs` (RED)**

```csharp
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Authentication;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- MITM (intégration en process) -------------------------------------------

        private static readonly TimeSpan MockWait = TimeSpan.FromSeconds(5);

        private static InMemorySecretStore StoreFor(string name, string value, params string[] hosts)
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync(name, Bytes(value), hosts, T0));
            return store;
        }

        private static Event WaitEvent(ProxyServer proxy, EventKind kind, int atLeast)
        {
            for (int i = 0; i < 100; i++)
            {
                int n = 0; Event last = null;
                foreach (Event e in proxy.Events.Ring.All) if (e.Kind == kind) { n++; last = e; }
                if (n >= atLeast) return last;
                Wait(Task.Delay(20));
            }
            return null;
        }

        private static string RingJson(ProxyServer proxy)
        {
            StringBuilder sb = new StringBuilder();
            foreach (Event e in proxy.Events.Ring.All) sb.Append(Json.EmitCompact(e.ToJson())).Append('\n');
            return sb.ToString();
        }

        private static void MITM_SubstitutedValueReachesUpstream()
        {
            const string value = "sk-ant-real-XYZ-2026";
            InMemorySecretStore store = StoreFor("test_anthropic_key", value, "localhost");
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log;
            try
            {
                using (MockUpstream mock = MockUpstream.Start("localhost"))
                using (CAManager ca = FreshCA())
                {
                    ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                    using (ProxyServer p = NewProxy(o, store, ca))
                    {
                        int port = p.Start().Port;
                        HttpHeaders h = H("Host", "localhost", "x-api-key", "{{kc:test_anthropic_key}}", "Content-Type", "application/json", "Accept-Encoding", "gzip");
                        ProxyClientResponse r = Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/v1/messages", h, Bytes("{\"prompt\":\"hi\"}")));
                        Check.True(r.Status == 200 && r.Text == "OK", "réponse de l'amont relayée");
                        MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                        Check.True(got.Head.Method == "POST" && got.Head.Target == "/v1/messages", "ligne de requête");
                        Check.Eq(value, got.Head.Headers.First("x-api-key"), "la valeur réelle atteint l'amont");
                        Check.True(!got.Head.Headers.Contains("Accept-Encoding"), "Accept-Encoding retiré");
                        Check.Eq("{\"prompt\":\"hi\"}", Encoding.UTF8.GetString(got.Body), "corps intact");
                        Check.Eq("14", got.Head.Headers.First("Content-Length"), "Content-Length normalisé");
                        Event e = WaitEvent(p, EventKind.Substituted, 1);
                        Check.True(e != null && e.Host == "localhost" && e.Method == "POST" && e.Path == "/v1/messages" && e.StatusCode == 200 && e.DurationMs.HasValue && string.Join(",", e.SubstitutedSecrets) == "test_anthropic_key" && e.Alert == null, "event substituted complet");
                        Wait(p.Processor.LastUsageRecording);
                        Check.Eq(1L, Wait(store.SecretAsync("test_anthropic_key")).UsageCount, "usage enregistré");
                        Wait(p.StopAsync());
                    }
                }
                Check.True(log.ToString().Contains("test_anthropic_key") && !log.ToString().Contains(value), "le journal cite le nom, jamais la valeur");
            }
            finally { Log.Reset(); }
        }

        private static void MITM_HostMismatch_BlockedForwardedLiteral()
        {
            const string value = "sk-real-XYZ-DO-NOT-LEAK";
            InMemorySecretStore store = StoreFor("test_anthropic_key", value, "api.anthropic.com"); // pas localhost → R1
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    ProxyClientResponse r = Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/v1/messages", H("Host", "localhost", "Authorization", "Bearer {{kc:test_anthropic_key}}"), null));
                    Check.Eq(200, r.Status, "la requête est transmise (l'amont décide)");
                    MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                    Check.Eq("Bearer {{kc:test_anthropic_key}}", got.Head.Headers.First("Authorization"), "placeholder littéral transmis");
                    Event e = WaitEvent(p, EventKind.ExfilBlocked, 1);
                    Check.True(e != null && e.Alert.Rule == ExfilRule.HostMismatch && e.Alert.Severity == AlertSeverity.High && e.Alert.SecretName == "test_anthropic_key" && e.SubstitutedSecrets.Count == 0 && e.StatusCode == 200, "event exfilBlocked R1");
                    Check.True(e.Alert.Snippet.Contains("{{kc:test_anthropic_key}}"), "snippet = placeholder, pas la valeur");
                    Check.True(!RingJson(p).Contains(value), "aucune valeur dans le ring");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_KeepAlive_TwoRequests()
        {
            InMemorySecretStore store = StoreFor("k", "V-ONE", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "CONNECT");
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        Wait(c.SendAsync("GET", "/first", H("Host", "localhost", "x-api-key", "{{kc:k}}"), null));
                        ProxyClientResponse r1 = Wait(c.ReadResponseAsync());
                        Wait(c.SendAsync("GET", "/second", H("Host", "localhost", "x-api-key", "{{kc:k}}", "Connection", "close"), null));
                        ProxyClientResponse r2 = Wait(c.ReadResponseAsync());
                        Check.True(r1.Status == 200 && r2.Status == 200, "deux réponses sur la même connexion déchiffrée");
                        byte[] buf = new byte[4];
                        int n; try { n = Wait(c.Http.ReadAsync(buf, 0, 4, CancellationToken.None)); } catch (IOException) { n = 0; }
                        Check.Eq(0, n, "Connection: close → le proxy ferme après la seconde réponse");
                    }
                    Wait(mock.WaitForRequestAsync(MockWait)); Wait(mock.WaitForRequestAsync(MockWait));
                    IList<MockUpstream.ReceivedRequest> got = mock.Received;
                    Check.True(got.Count == 2 && got[0].Head.Target == "/first" && got[1].Head.Target == "/second", "les deux requêtes atteignent l'amont dans l'ordre");
                    Check.True(got[0].Head.Headers.First("x-api-key") == "V-ONE" && got[1].Head.Headers.First("x-api-key") == "V-ONE", "chacune substituée");
                    Check.Eq(1, mock.Connections, "une seule connexion amont réutilisée en keep-alive");
                    Check.True(WaitEvent(p, EventKind.Substituted, 2) != null, "deux events substituted");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_StreamingChunksArriveIncrementally()
        {
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                MockUpstream.StreamingPlan plan = new MockUpstream.StreamingPlan();
                plan.FirstChunk = Bytes("data: first\n\n");
                plan.RemainingChunks.Add(Bytes("data: second\n\n"));
                plan.RemainingChunks.Add(Bytes("data: third\n\n"));
                mock.Streaming = plan;
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Wait(c.ConnectTunnelAsync("localhost", mock.Port));
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        Wait(c.SendAsync("GET", "/events", H("Host", "localhost"), null));
                        HttpResponseHead head = Wait(c.ReadResponseHeadAsync());
                        Check.True(head.Status == 200 && head.Headers.First("Transfer-Encoding") == "chunked", "tête streamée relayée");
                        byte[] first = Wait(c.ReadChunkAsync());
                        Check.Eq("data: first\n\n", Encoding.UTF8.GetString(first), "premier chunk reçu AVANT que l'amont n'envoie la suite (pas de bufferisation)");
                        Check.True(WaitEvent(p, EventKind.NoMatch, 1) == null, "aucun event tant que la réponse n'est pas finie");
                        plan.ReleaseRest.SetResult(true);
                        Check.Eq("data: second\n\n", Encoding.UTF8.GetString(Wait(c.ReadChunkAsync())), "deuxième chunk");
                        Check.Eq("data: third\n\n", Encoding.UTF8.GetString(Wait(c.ReadChunkAsync())), "troisième chunk");
                        Check.True(Wait(c.ReadChunkAsync()) == null, "dernier chunk");
                    }
                    Event e = WaitEvent(p, EventKind.NoMatch, 1);
                    Check.True(e != null && e.StatusCode == 200 && e.Path == "/events", "event noMatch à la fin du flux");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_UpstreamDropMidStream_TruncatesClient()
        {
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                MockUpstream.StreamingPlan plan = new MockUpstream.StreamingPlan();
                plan.FirstChunk = Bytes("partial");
                plan.DropAfterFirstChunk = true;
                mock.Streaming = plan;
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Wait(c.ConnectTunnelAsync("localhost", mock.Port));
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        Wait(c.SendAsync("GET", "/events", H("Host", "localhost"), null));
                        HttpResponseHead head = Wait(c.ReadResponseHeadAsync());
                        Check.Eq(200, head.Status, "tête relayée");
                        Check.Eq("partial", Encoding.UTF8.GetString(Wait(c.ReadChunkAsync())), "premier chunk relayé");
                        byte[] next = null; bool closed = false;
                        try { next = Wait(c.ReadChunkAsync()); } catch (IOException) { closed = true; } catch (HttpProtocolException) { closed = true; }
                        Check.True(closed || next == null, "coupure amont → le proxy ferme le client (réponse tronquée, pas de faux dernier chunk)");
                    }
                    Event e = WaitEvent(p, EventKind.Error, 1);
                    Check.True(e != null && e.Path == "/events" && e.StatusCode == 200, "event error avec le statut déjà relayé");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_LargeBody_StreamedWithFlag()
        {
            InMemorySecretStore store = StoreFor("k", "V-BIG", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    byte[] big = new byte[HttpParser.MaxBufferedBody + 4096];
                    for (int i = 0; i < big.Length; i++) big[i] = (byte)('a' + (i % 26));
                    byte[] marker = Bytes("{{kc:k}}");
                    Buffer.BlockCopy(marker, 0, big, big.Length - 100, marker.Length); // placeholder dans la partie non bufferisée : jamais scanné
                    ProxyClientResponse r = Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/upload", H("Host", "localhost", "x-api-key", "{{kc:k}}", "Content-Type", "application/octet-stream"), big));
                    Check.Eq(200, r.Status, "réponse");
                    MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                    Check.Eq(big.Length, got.Body.Length, "corps intégralement relayé");
                    Check.Eq(Convert.ToBase64String(big), Convert.ToBase64String(got.Body), "octets identiques (placeholder du corps intact)");
                    Check.Eq("V-BIG", got.Head.Headers.First("x-api-key"), "en-tête scanné et substitué malgré le corps trop grand");
                    Event e = WaitEvent(p, EventKind.Substituted, 1);
                    Check.True(e != null && (e.Flags & EventFlags.BodyTooLarge) != 0, "drapeau bodyTooLarge sur l'event");
                    Check.True(Json.EmitCompact(e.ToJson()).Contains("\"flags\":[\"bodyTooLarge\"]"), "drapeau sur le fil");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_NonUtf8AndCompressedBody_Flags()
        {
            InMemorySecretStore store = StoreFor("k", "V", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    byte[] binary = { 0xFF, 0xFE, 0x7B, 0x7B, 0x6B, 0x63, 0x3A, 0x6B, 0x7D, 0x7D, 0x00 };
                    Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/bin", H("Host", "localhost"), binary));
                    MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                    Check.Eq(Convert.ToBase64String(binary), Convert.ToBase64String(got.Body), "corps binaire relayé tel quel");
                    Event e = WaitEvent(p, EventKind.NoMatch, 1);
                    Check.True(e != null && (e.Flags & EventFlags.NonUtf8) != 0, "drapeau nonUtf8");
                    Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/gz", H("Host", "localhost", "Content-Encoding", "gzip"), Bytes("{{kc:k}}")));
                    Wait(mock.WaitForRequestAsync(MockWait));
                    e = WaitEvent(p, EventKind.NoMatch, 2);
                    Check.True(e != null && (e.Flags & EventFlags.CompressedBody) != 0, "drapeau compressedBody, corps non scanné");
                    Check.Eq("{{kc:k}}", Encoding.UTF8.GetString(mock.Received[1].Body), "corps compressé transmis intact");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_Upstream502()
        {
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions("localhost"), new InMemorySecretStore(), ca))
            {
                int port = p.Start().Port;
                int closed = FreePort();
                using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                {
                    Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", closed)), "CONNECT accepté (hôte whitelisté)");
                    Wait(c.StartTlsAsync("localhost", ca.Certificate));
                    Wait(c.SendAsync("GET", "/x", H("Host", "localhost"), null));
                    ProxyClientResponse r = Wait(c.ReadResponseAsync());
                    Check.Eq(502, r.Status, "amont injoignable → 502 au client déchiffré");
                    Check.True(r.Text.Contains("amont injoignable"), "corps texte court en français");
                }
                Event e = WaitEvent(p, EventKind.Error, 1);
                Check.True(e != null && e.Host == "localhost" && e.Method == "GET" && e.Path == "/x" && e.StatusCode == 502, "event error");
                Wait(p.StopAsync());
            }
        }

        private static void MITM_ClientRejectsCA_ErrorEvent()
        {
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log;
            try
            {
                using (CAManager ca = FreshCA())
                using (CAManager other = FreshCA())
                using (ProxyServer p = NewProxy(TestOptions("localhost"), new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", 443)), "CONNECT accepté");
                        Check.Throws<AuthenticationException>(delegate { Wait(c.StartTlsAsync("localhost", other.Certificate)); }, "le client refuse la feuille signée par un CA qu'il ne connaît pas");
                    }
                    Event e = WaitEvent(p, EventKind.Error, 1);
                    Check.True(e != null && e.Host == "localhost" && e.Method == "CONNECT", "event error côté proxy");
                    Check.True(log.ToString().Contains("ca.pem"), "le journal donne l'indice ca.pem");
                    Check.Eq(0, p.Events.Ring.Count(EventKind.Substituted), "rien d'autre");
                    Wait(p.StopAsync());
                }
            }
            finally { Log.Reset(); }
        }

        private static void MITM_PausePolicyAndResume()
        {
            InMemorySecretStore store = StoreFor("k", "V", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost");
                o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                o.Security = new SecurityConfig(ExfilPolicy.BlockNotifyPause, 60);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "GET", "/a", H("Host", "localhost", "x-custom", "{{kc:k}}"), null)); // R2
                    Wait(mock.WaitForRequestAsync(MockWait));
                    Check.True(WaitEvent(p, EventKind.ExfilBlocked, 1) != null, "R2 bloqué");
                    Check.True(p.Paused, "block_notify_pause : daemon en pause");
                    Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "GET", "/b", H("Host", "localhost", "x-api-key", "{{kc:k}}"), null));
                    Wait(mock.WaitForRequestAsync(MockWait));
                    Check.Eq("{{kc:k}}", mock.Received[1].Head.Headers.First("x-api-key"), "en pause : placeholder transmis intact");
                    Event e = WaitEvent(p, EventKind.NoMatch, 1);
                    Check.True(e != null && e.Path == "/b" && (e.Flags & EventFlags.Paused) != 0, "event noMatch avec drapeau paused");
                    p.SetPaused(false);
                    Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "GET", "/c", H("Host", "localhost", "x-api-key", "{{kc:k}}"), null));
                    Wait(mock.WaitForRequestAsync(MockWait));
                    Check.Eq("V", mock.Received[2].Head.Headers.First("x-api-key"), "repris : substitution de nouveau");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_VolumeAnomaly_R5()
        {
            InMemorySecretStore store = StoreFor("test_key", "sk-XYZ", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost");
                o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                o.Security = new SecurityConfig(ExfilPolicy.BlockOnly, 2);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    for (int i = 0; i < 3; i++)
                    {
                        Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/v1/messages", H("Host", "localhost", "Authorization", "Bearer {{kc:test_key}}"), null));
                        Wait(mock.WaitForRequestAsync(MockWait));
                    }
                    Event blocked = WaitEvent(p, EventKind.ExfilBlocked, 1);
                    Check.True(blocked != null && blocked.Alert.Rule == ExfilRule.VolumeAnomaly && blocked.Alert.Severity == AlertSeverity.Low && blocked.Alert.SecretName == "test_key", "3e requête bloquée par R5");
                    Check.Eq(2L, p.Events.Ring.Count(EventKind.Substituted), "deux substitutions avant le seuil");
                    Check.True(!RingJson(p).Contains("sk-XYZ"), "aucune valeur dans les events");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void MITM_Expect100ContinueAndPing()
        {
            InMemorySecretStore store = StoreFor("k", "V", "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, store, ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Wait(c.ConnectTunnelAsync("localhost", mock.Port));
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        byte[] body = Bytes("payload");
                        Wait(HttpParser.WriteAsync(c.Http, new HttpRequestHead("POST", "/up", "HTTP/1.1", H("Host", "localhost", "Expect", "100-continue", "Content-Length", "7", "x-api-key", "{{kc:k}}")), CancellationToken.None));
                        Wait(c.Http.FlushAsync(CancellationToken.None));
                        HttpResponseHead interim = Wait(c.ReadResponseHeadAsync());
                        Check.Eq(100, interim.Status, "100 Continue avant l'envoi du corps");
                        Wait(c.Http.WriteAsync(body, 0, body.Length, CancellationToken.None));
                        Wait(c.Http.FlushAsync(CancellationToken.None));
                        ProxyClientResponse r = Wait(c.ReadResponseAsync());
                        Check.Eq(200, r.Status, "réponse finale");
                        MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                        Check.True(got.Head.Headers.Contains("Expect") == false && Encoding.UTF8.GetString(got.Body) == "payload" && got.Head.Headers.First("x-api-key") == "V", "Expect retiré, corps et substitution transmis");
                        Wait(c.SendAsync("GET", "/__iris_ping", H("Host", "localhost"), null));
                        ProxyClientResponse ping = Wait(c.ReadResponseAsync());
                        Check.True(ping.Status == 200 && ping.Text == "ok\n", "ping aussi dans le tunnel déchiffré, sans fermer");
                        Check.Eq(1, mock.Received.Count, "le ping n'atteint pas l'amont");
                    }
                    Check.Eq(1L, p.Events.Ring.Count(EventKind.Substituted), "un seul event (pas pour le ping)");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void Security_NoSecretValueInProxyDumps()
        {
            const string value = "sk-live-9f8e7d6c-NEVER-SEEN";
            InMemorySecretStore store = StoreFor("prod_key", value, "localhost");
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Trace;
            try
            {
                using (MockUpstream mock = MockUpstream.Start("localhost"))
                using (CAManager ca = FreshCA())
                {
                    ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                    using (ProxyServer p = NewProxy(o, store, ca))
                    {
                        int port = p.Start().Port;
                        Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/v1/{{kc:prod_key}}?t={{kc:prod_key}}", H("Host", "localhost", "x-api-key", "{{kc:prod_key}}"), null)); // R2 (chemin)
                        Wait(mock.WaitForRequestAsync(MockWait));
                        Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "POST", "/v1/messages", H("Host", "localhost", "x-api-key", "{{kc:prod_key}}"), null)); // substitué
                        Wait(mock.WaitForRequestAsync(MockWait));
                        WaitEvent(p, EventKind.Substituted, 1);
                        string dump = RingJson(p) + log;
                        Check.True(dump.Contains("prod_key"), "le dump cite le nom");
                        Check.True(!dump.Contains(value), "le dump ne contient jamais la valeur (events, alertes, snippets, journal en trace)");
                        Check.Eq(value, mock.Received[1].Head.Headers.First("x-api-key"), "seule la requête amont porte la valeur");
                        Wait(p.StopAsync());
                    }
                }
            }
            finally { Log.Reset(); }
        }
    }
}
```

`Main` : `Check.Run("MITM : la valeur substituée atteint l'amont", MITM_SubstitutedValueReachesUpstream); Check.Run("MITM : R1 bloqué, littéral transmis, event", MITM_HostMismatch_BlockedForwardedLiteral); Check.Run("MITM : keep-alive, deux requêtes, amont réutilisé", MITM_KeepAlive_TwoRequests); Check.Run("MITM : streaming chunk par chunk", MITM_StreamingChunksArriveIncrementally); Check.Run("MITM : coupure amont en plein flux", MITM_UpstreamDropMidStream_TruncatesClient); Check.Run("MITM : corps > 4 MiB relayé avec bodyTooLarge", MITM_LargeBody_StreamedWithFlag); Check.Run("MITM : corps non UTF-8 et compressé", MITM_NonUtf8AndCompressedBody_Flags); Check.Run("MITM : amont injoignable → 502", MITM_Upstream502); Check.Run("MITM : client qui refuse le CA → event error", MITM_ClientRejectsCA_ErrorEvent); Check.Run("MITM : pause automatique et reprise", MITM_PausePolicyAndResume); Check.Run("MITM : R5 après le seuil", MITM_VolumeAnomaly_R5); Check.Run("MITM : Expect 100-continue et ping", MITM_Expect100ContinueAndPing); Check.Run("Sécurité : aucune valeur dans les dumps du proxy", Security_NoSecretValueInProxyDumps);` — `TEST_SOURCES` : ajouter `"%TESTS%\MITMTests.cs"`.

- [ ] **Step 2: Vérifier l'échec** — compilation OK (le bouchon existe) mais `MITM_SubstitutedValueReachesUpstream` échoue : `CONNECT refusé : 502 MITM non disponible`. Attendu : `13 échec(s)` au plus (les tests MITM).

- [ ] **Step 3: Retirer le bouchon de `ConnectHandler.cs`** — supprimer la classe `MITMHandler` (les 8 dernières lignes de `src\IrisKit\Proxy\ConnectHandler.cs`, du commentaire « Bouchon remplacé » à son accolade fermante).

- [ ] **Step 4: Écrire `src\IrisKit\Proxy\MITMHandler.cs`**

```csharp
using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Hôte whitelisté (spec §6.1–6.3) : 200, SslStream serveur avec la feuille de l'hôte, puis boucle keep-alive :
    /// tête → 100 Continue → corps (≤ 4 MiB, sinon streaming) → RequestProcessor → amont (connexion réutilisée) →
    /// relais de la réponse par blocs avec flush → Event. 502 si l'amont ne répond pas avant la tête ; fermeture si après.
    /// </summary>
    public static class MITMHandler
    {
        public static async Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            DateTime started = server.Clock();
            Stopwatch watch = Stopwatch.StartNew();
            HttpConnection plain = conn.Http;
            byte[] ok = HttpParser.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await plain.WriteAsync(ok, 0, ok.Length, cancel).ConfigureAwait(false);
            await plain.FlushAsync(cancel).ConfigureAwait(false);

            X509Certificate2 leaf;
            try { leaf = server.Leaves.Get(host); }
            catch (CryptographicException ex)
            {
                Log.Error("proxy", "feuille impossible pour " + host + " : " + ex.Message);
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", host + ":" + port, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                return;
            }

            SslStream tls = new SslStream(new PrefixedStream(plain.TakeBuffered(), conn.Client.GetStream()), false);
            try { await tls.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false).ConfigureAwait(false); }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is AuthenticationException || ex is ObjectDisposedException)) throw;
                Log.Warn("proxy", "poignée de main TLS refusée par le client pour " + host + " : le client ne fait pas confiance à data\\ca.pem ? (" + ex.Message + ")");
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", host + ":" + port, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                tls.Dispose();
                return;
            }
            using (tls)
            {
                HttpConnection http = new HttpConnection(tls);
                http.ReadTimeout = server.Options.IdleTimeout;
                await ServeAsync(server, http, host, port, cancel).ConfigureAwait(false);
            }
        }

        private static async Task ServeAsync(ProxyServer server, HttpConnection http, string host, int port, CancellationToken cancel)
        {
            UpstreamConnection upstream = null;
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    HttpRequestHead head;
                    try { head = await HttpParser.ReadRequestHeadAsync(http, cancel).ConfigureAwait(false); }
                    catch (HttpProtocolException ex)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, ex.Message, cancel).ConfigureAwait(false);
                        return;
                    }
                    if (head == null) return;
                    if (PingResponder.Matches(head))
                    {
                        await PingResponder.RespondAsync(http, cancel).ConfigureAwait(false);
                        continue;
                    }

                    DateTime started = server.Clock();
                    Stopwatch watch = Stopwatch.StartNew();
                    string originalTarget = head.Target;
                    string method = head.Method;
                    bool clientWantsClose = HttpParser.WantsClose(head.Version, head.Headers);
                    BodyFraming framing;
                    try { framing = HttpParser.RequestFraming(head.Headers); }
                    catch (HttpProtocolException ex)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, ex.Message, cancel).ConfigureAwait(false);
                        return;
                    }
                    if (HttpParser.ExpectsContinue(head.Headers) && framing.Kind != BodyFramingKind.None)
                    {
                        byte[] cont = HttpParser.Latin1.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                        await http.WriteAsync(cont, 0, cont.Length, cancel).ConfigureAwait(false);
                        await http.FlushAsync(cancel).ConfigureAwait(false);
                    }
                    BufferedBody body;
                    try { body = await HttpParser.ReadBodyAsync(http, framing, HttpParser.MaxBufferedBody, cancel).ConfigureAwait(false); }
                    catch (HttpProtocolException ex)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, ex.Message, cancel).ConfigureAwait(false);
                        return;
                    }

                    ProcessedRequest processed = await server.Processor.ProcessAsync(head, body.Bytes, !body.Complete, host, server.Paused).ConfigureAwait(false);
                    HttpHeaders outHeaders = processed.Head.Headers;
                    if (body.Complete && framing.Kind != BodyFramingKind.None)
                    {
                        // Corps entièrement bufferisé : toujours renvoyé en Content-Length (chunked décodé, substitution comprise).
                        outHeaders.Remove("Transfer-Encoding");
                        outHeaders.Set("Content-Length", processed.Body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    }

                    HttpResponseHead response;
                    try
                    {
                        if (upstream == null)
                        {
                            upstream = await server.Upstream.ConnectTlsAsync(host, port, cancel).ConfigureAwait(false);
                            upstream.Http.ReadTimeout = server.Options.IdleTimeout;
                        }
                        HttpConnection up = upstream.Http;
                        await HttpParser.WriteAsync(up, new HttpRequestHead(method, processed.Head.Target, "HTTP/1.1", outHeaders), cancel).ConfigureAwait(false);
                        if (body.Complete)
                        {
                            if (processed.Body.Length > 0) await up.WriteAsync(processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                        }
                        else
                        {
                            if (framing.Kind == BodyFramingKind.Chunked) await HttpParser.WriteChunkAsync(up, processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                            else await up.WriteAsync(processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                            await up.FlushAsync(cancel).ConfigureAwait(false);
                            await HttpParser.RelayRemainderAsync(http, up, framing, body, cancel).ConfigureAwait(false);
                        }
                        await up.FlushAsync(cancel).ConfigureAwait(false);
                        response = await HttpParser.ReadResponseHeadAsync(up, cancel).ConfigureAwait(false);
                        if (response == null) throw new UpstreamException("l'amont " + host + " a fermé la connexion sans répondre", null);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is UpstreamException || ex is IOException || ex is HttpProtocolException || ex is TimeoutException || ex is ObjectDisposedException)) throw;
                        if (upstream != null) { upstream.Dispose(); upstream = null; }
                        Log.Warn("proxy", "amont " + host + ":" + port + " en échec pour " + method + " " + originalTarget + " : " + ex.Message);
                        server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, method, originalTarget, 502, watch.ElapsedMilliseconds, null, null, null, processed.Flags));
                        await ConnectHandler.WriteSimpleResponseAsync(http, 502, "amont injoignable : " + ex.Message, cancel).ConfigureAwait(false);
                        return;
                    }

                    bool upstreamWantsClose = HttpParser.WantsClose(response.Version, response.Headers);
                    BodyFraming responseFraming;
                    bool relayFailed = false;
                    try
                    {
                        responseFraming = HttpParser.ResponseFraming(response.Headers, method, response.Status);
                        await HttpParser.WriteAsync(http, response, cancel).ConfigureAwait(false);
                        await http.FlushAsync(cancel).ConfigureAwait(false);
                        await HttpParser.RelayBodyAsync(upstream.Http, http, responseFraming, cancel).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is IOException || ex is HttpProtocolException || ex is TimeoutException || ex is ObjectDisposedException)) throw;
                        relayFailed = true;
                        responseFraming = BodyFraming.UntilClose;
                        Log.Warn("proxy", "réponse amont interrompue pour " + method + " " + originalTarget + " (" + host + ") : " + ex.Message);
                    }
                    server.Events.Emit(new Event(Guid.NewGuid(), started, relayFailed ? EventKind.Error : processed.EventKind, host, method, originalTarget,
                        response.Status, watch.ElapsedMilliseconds, processed.Substituted, processed.Alert, null, processed.Flags));
                    if (relayFailed) return; // tête déjà sur le fil : on tronque en fermant (spec §6.3)
                    if (upstreamWantsClose || responseFraming.Kind == BodyFramingKind.UntilClose) { upstream.Dispose(); upstream = null; }
                    if (clientWantsClose || responseFraming.Kind == BodyFramingKind.UntilClose) return;
                }
            }
            catch (IOException) { }
            catch (TimeoutException) { Log.Debug("proxy", "connexion déchiffrée vers " + host + " fermée pour inactivité"); }
            catch (ObjectDisposedException) { }
            finally
            {
                if (upstream != null) upstream.Dispose();
            }
        }
    }
}
```

- [ ] **Step 5: Sources + vert** — `IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Proxy\MITMHandler.cs"`. → `117 test(s) réussi(s)`. Diagnostic si besoin : `MITM_StreamingChunksArriveIncrementally` bloqué sur le premier chunk = un `FlushAsync` manque dans `RelayChunkedVerbatimAsync` après le chunk ; `MITM_KeepAlive_TwoRequests` avec `Connections == 2` = l'amont a été jeté entre les deux requêtes (vérifier que le mock ne ferme pas et que `upstreamWantsClose` est faux) ; `MITM_ClientRejectsCA_ErrorEvent` sans event = l'exception de `AuthenticateAsServerAsync` n'est pas une `IOException`/`AuthenticationException` (ajouter le type observé au filtre et consigner) ; `MITM_LargeBody_StreamedWithFlag` lent (> 5 s) = `MockUpstream` lit par blocs de 16 KiB en TLS, normal jusqu'à ~2 s.

- [ ] **Step 6: Commit**

```bash
git add src/IrisKit/Proxy/MITMHandler.cs src/IrisKit/Proxy/ConnectHandler.cs tests/MITMTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(iriskit): MITMHandler — TLS côté agent, keep-alive, 100 Continue, relais streaming, 502, events ; tests d'intégration en process

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---
### Task 8: Daemon — démarrage du proxy, code 3, arrêt en 5 s, Ctrl+C pendant la saisie, purge planifiée

**Files:**
- Create: `src\IrisKit\Events\PurgeScheduler.cs`
- Modify: `src\irisd\IConsoleInput.cs` (réécriture), `src\irisd\Daemon.cs` (réécriture), `tests\TestSupport.cs` (`ScriptedConsoleInput`, `CapturingWriter`)
- Create: `tests\DaemonProxyTests.cs`
- Modify: `tests\Tests.cs`, `test.bat`, `build.bat`

**Interfaces:**
- Consumes: `ProxyServer`, `ProxyOptions.FromConfig`, `ProxyPortInUseException`, `ProxyException` (tâche 5), `JsonlEventStore.Purge() : int`, `EventPipeline`, `ConfigStore`, `Config`, `BrokerConfig`, `DataDir`, `ExitCodes`, `Entry.Run` (phase 1).
- Produces: `PurgeScheduler(JsonlEventStore store, Func<DateTime> clock) : IDisposable` (`NextRunUtc`, `RunNow() : int`, `static NextMidnight(DateTime utcNow) : DateTime`) ; `IConsoleInput.ReadPassword(string prompt, CancellationToken cancel) : SecureString` (null = entrée fermée ; annulation = `OperationCanceledException`) ; `Daemon.Run` démarre le proxy après le CA et log `irisd ready on <ip:port>, ca=<chemin>` ; `ExitCodes.Port` (3) sur `ProxyPortInUseException` ; Ctrl+C à l'invite de mot de passe → `OperationCanceledException` attrapée par `Daemon.Run` → `arrêt demandé`, code 0 ; `ScriptedConsoleInput.BlockWhenExhausted` ; `CapturingWriter : TextWriter` (`Snapshot()`), `TestMain.StartDaemon(...)`, `TestMain.WaitFor(Func<bool>, int ms)`.

- [ ] **Step 1: Mettre à jour `tests\TestSupport.cs`**

Remplacer la classe `ScriptedConsoleInput` par :

```csharp
    /// <summary>Console scriptée : chaque ReadPassword rend la réponse suivante ; liste épuisée = null (EOF), ou attente de l'annulation (OperationCanceledException) si BlockWhenExhausted.</summary>
    public sealed class ScriptedConsoleInput : Irisd.IConsoleInput
    {
        private readonly System.Collections.Generic.Queue<string> answers;
        public System.Collections.Generic.List<string> Prompts = new System.Collections.Generic.List<string>();
        public bool BlockWhenExhausted;

        public ScriptedConsoleInput(params string[] answers)
        {
            this.answers = new System.Collections.Generic.Queue<string>(answers);
        }

        public SecureString ReadPassword(string prompt, System.Threading.CancellationToken cancel)
        {
            lock (Prompts) Prompts.Add(prompt);
            if (answers.Count > 0) return TestMain.Secure(answers.Dequeue());
            if (BlockWhenExhausted) { cancel.WaitHandle.WaitOne(); cancel.ThrowIfCancellationRequested(); }
            return null;
        }

        public int PromptCount { get { lock (Prompts) return Prompts.Count; } }
    }

    /// <summary>TextWriter verrouillé dont on peut lire un instantané depuis un autre thread (daemon lancé en tâche).</summary>
    public sealed class CapturingWriter : TextWriter
    {
        private readonly System.Text.StringBuilder sb = new System.Text.StringBuilder();
        private readonly object gate = new object();
        public override System.Text.Encoding Encoding { get { return System.Text.Encoding.UTF8; } }
        public override void Write(char value) { lock (gate) sb.Append(value); }
        public override void Write(string value) { lock (gate) sb.Append(value); }
        public string Snapshot() { lock (gate) return sb.ToString(); }
        public override string ToString() { return Snapshot(); }
    }
```

Les tests existants de `tests\DaemonTests.cs` restent valides : `ScriptedConsoleInput` sans `BlockWhenExhausted` rend null quand la liste est épuisée (EOF → code 2), comme avant.

- [ ] **Step 2: Écrire `tests\DaemonProxyTests.cs` (RED)**

```csharp
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Daemon avec proxy ---------------------------------------------------

        private sealed class LiveDaemon
        {
            public Task<int> Exit;
            public CapturingWriter Out = new CapturingWriter();
            public CapturingWriter Err = new CapturingWriter();
            public CancellationTokenSource Cts = new CancellationTokenSource();

            public int WaitExit()
            {
                if (!Exit.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("le daemon ne s'est pas arrêté : " + Out.Snapshot() + Err.Snapshot());
                return Exit.Result;
            }
        }

        private static LiveDaemon StartDaemon(ScriptedConsoleInput console, params string[] args)
        {
            LiveDaemon d = new LiveDaemon();
            Log.Reset();
            d.Exit = Task.Run(delegate { return Entry.Run(args, d.Out, d.Err, console, d.Cts.Token); });
            return d;
        }

        private static bool WaitFor(Func<bool> condition, int ms)
        {
            DateTime limit = DateTime.UtcNow.AddMilliseconds(ms);
            while (DateTime.UtcNow < limit)
            {
                if (condition()) return true;
                Wait(Task.Delay(25));
            }
            return condition();
        }

        private static void WriteListenPort(string data, int port)
        {
            DataDir.Prepare(data);
            ConfigStore store = ConfigStore.Open(data, T0);
            Config c = store.Current;
            BrokerConfig b = new BrokerConfig("127.0.0.1:" + port, c.Broker.EventsListen, c.Broker.AdminPipe, c.Broker.LogLevel, c.Broker.EventRetentionDays, c.Broker.EventRingSize);
            store.Save(new Config(c.Version, b, c.Security, c.Backups, c.Hosts, c.Plugins), T0);
        }

        private static void Entry_StartsProxyAndAnswersPing()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                int port = FreePort();
                WriteListenPort(data, port);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                try
                {
                    Check.True(WaitFor(delegate { return d.Out.Snapshot().Contains("irisd ready on 127.0.0.1:" + port); }, 10000), "log « irisd ready on <ip:port> » : " + d.Out.Snapshot() + d.Err.Snapshot());
                    Check.True(d.Out.Snapshot().Contains("ca=" + Path.Combine(data, "ca.pem")), "le log cite ca.pem");
                    string ping = Wait(TestProxyClient.RawAsync(port, "GET /__iris_ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
                    Check.True(ping.StartsWith("HTTP/1.1 200 OK"), "le proxy répond au ping");
                    Check.True(!d.Exit.IsCompleted, "le daemon attend Ctrl+C");
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre → 0 : " + d.Err.Snapshot());
                Check.True(d.Out.Snapshot().Contains("arrêt demandé"), "log d'arrêt");
                TcpListener free = new TcpListener(IPAddress.Loopback, port);
                free.Start(); free.Stop();
                Check.True(true, "le port est libéré après l'arrêt");
                Check.Eq("", d.Err.Snapshot(), "rien sur stderr");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Entry_PortInUse_Exit3()
        {
            string dir = TestDir.Create();
            TcpListener squatter = new TcpListener(IPAddress.Loopback, 0);
            squatter.Start();
            try
            {
                int port = ((IPEndPoint)squatter.LocalEndpoint).Port;
                string data = Path.Combine(dir, "data");
                WriteListenPort(data, port);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Port, d.WaitExit(), "port occupé → 3");
                string err = d.Err.Snapshot();
                Check.True(err.StartsWith("irisd : ") && err.Contains(port.ToString()) && err.Contains("déjà utilisé"), "message avec le port : " + err);
                Check.True(!err.Contains("   at ") && !err.Contains("   à "), "aucune trace de pile");
            }
            finally { squatter.Stop(); Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Entry_CtrlC_DuringPrompt_Exit0()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                ScriptedConsoleInput console = new ScriptedConsoleInput();
                console.BlockWhenExhausted = true;
                LiveDaemon d = StartDaemon(console, "--foreground", "--data", data);
                Check.True(WaitFor(delegate { return console.PromptCount >= 1; }, 10000), "le daemon attend le mot de passe du nouveau coffre");
                Check.True(!d.Exit.IsCompleted, "bloqué sur l'invite");
                d.Cts.Cancel();
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "Ctrl+C pendant la saisie → arrêt normal, code 0");
                Check.True(d.Err.Snapshot().Contains("arrêt demandé"), "message d'arrêt sur stderr");
                Check.True(!File.Exists(Path.Combine(data, "iris.kdbx")), "aucun coffre créé");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void PurgeScheduler_NextMidnightAndRunNow()
        {
            string dir = TestDir.Create();
            try
            {
                DateTime clock = new DateTime(2026, 10, 17, 23, 59, 59, DateTimeKind.Utc);
                Check.Eq(new DateTime(2026, 10, 18, 0, 0, 1, DateTimeKind.Utc), PurgeScheduler.NextMidnight(clock), "minuit UTC + 1 s");
                using (JsonlEventStore store = new JsonlEventStore(dir, 1, delegate { return clock; }))
                {
                    File.WriteAllText(Path.Combine(dir, "events-2026-10-10.jsonl"), "{}\n");
                    File.WriteAllText(Path.Combine(dir, "events-2026-10-17.jsonl"), "{}\n");
                    using (PurgeScheduler scheduler = new PurgeScheduler(store, delegate { return clock; }))
                    {
                        Check.Eq(new DateTime(2026, 10, 18, 0, 0, 1, DateTimeKind.Utc), scheduler.NextRunUtc, "prochaine purge planifiée à minuit");
                        Check.True(scheduler.RunNow() >= 1, "RunNow purge le fichier hors rétention");
                        Check.True(!File.Exists(Path.Combine(dir, "events-2026-10-10.jsonl")) && File.Exists(Path.Combine(dir, "events-2026-10-17.jsonl")), "vieux fichier supprimé, celui du jour gardé");
                        clock = new DateTime(2026, 10, 18, 0, 0, 2, DateTimeKind.Utc);
                        scheduler.RunNow();
                        Check.Eq(new DateTime(2026, 10, 19, 0, 0, 1, DateTimeKind.Utc), scheduler.NextRunUtc, "replanifiée au minuit suivant");
                    }
                }
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
```

`Main` : `Check.Run("Daemon : démarre le proxy et répond au ping", Entry_StartsProxyAndAnswersPing); Check.Run("Daemon : port occupé → 3", Entry_PortInUse_Exit3); Check.Run("Daemon : Ctrl+C pendant la saisie → 0", Entry_CtrlC_DuringPrompt_Exit0); Check.Run("PurgeScheduler : minuit UTC et RunNow", PurgeScheduler_NextMidnightAndRunNow);` — `TEST_SOURCES` : ajouter `"%TESTS%\DaemonProxyTests.cs"`.

- [ ] **Step 3: Vérifier l'échec** — `CS0535 'ScriptedConsoleInput' n'implémente pas 'IConsoleInput.ReadPassword(string)'` (signature) et `CS0246 'PurgeScheduler'`.

- [ ] **Step 4: Écrire `src\IrisKit\Events\PurgeScheduler.cs`**

```csharp
using System;
using System.Threading;

namespace IrisKit
{
    /// <summary>Purge du journal JSONL à chaque minuit UTC (spec §5.5), en plus de la purge au démarrage ; revue phase 1, mineur 7.</summary>
    public sealed class PurgeScheduler : IDisposable
    {
        private readonly JsonlEventStore store;
        private readonly Func<DateTime> clock;
        private readonly object gate = new object();
        private Timer timer;
        private bool disposed;

        public DateTime NextRunUtc { get; private set; }

        public PurgeScheduler(JsonlEventStore store, Func<DateTime> clock)
        {
            if (store == null) throw new ArgumentNullException("store");
            this.store = store;
            this.clock = clock;
            Schedule();
        }

        public static DateTime NextMidnight(DateTime utcNow)
        {
            return DateTime.SpecifyKind(utcNow.Date.AddDays(1).AddSeconds(1), DateTimeKind.Utc);
        }

        private void Schedule()
        {
            DateTime now = clock().ToUniversalTime();
            NextRunUtc = NextMidnight(now);
            TimeSpan due = NextRunUtc - now;
            if (due < TimeSpan.FromSeconds(1)) due = TimeSpan.FromSeconds(1);
            timer = new Timer(delegate { RunNow(); }, null, due, Timeout.InfiniteTimeSpan);
        }

        /// <summary>Purge immédiate puis replanification ; rend le nombre de fichiers supprimés.</summary>
        public int RunNow()
        {
            lock (gate)
            {
                if (disposed) return 0;
                int removed = 0;
                try
                {
                    removed = store.Purge();
                    if (removed > 0) Log.Info("events", removed + " fichier(s) de journal purgé(s)");
                }
                catch (Exception ex) { Log.Warn("events", "purge du journal impossible : " + ex.Message); }
                timer.Dispose();
                Schedule();
                return removed;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                disposed = true;
                if (timer != null) timer.Dispose();
            }
        }
    }
}
```

- [ ] **Step 5: Réécrire `src\irisd\IConsoleInput.cs`**

```csharp
using System;
using System.Security;
using System.Threading;
using System.Threading.Tasks;

namespace Irisd
{
    /// <summary>Saisie du mot de passe maître. null = entrée fermée (EOF) ; Ctrl+C = OperationCanceledException. Jamais loguée.</summary>
    public interface IConsoleInput
    {
        SecureString ReadPassword(string prompt, CancellationToken cancel);
    }

    /// <summary>
    /// Console réelle : saisie masquée (ReadKey) en surveillant l'annulation entre deux touches ; si l'entrée est redirigée,
    /// ReadLine avec avertissement unique. Revue phase 1, mineur 4 : Ctrl+C interrompt l'invite.
    /// </summary>
    public sealed class ConsoleInput : IConsoleInput
    {
        private bool warnedRedirected;

        public SecureString ReadPassword(string prompt, CancellationToken cancel)
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
                Task<string> line = Console.In.ReadLineAsync();
                int which = WaitHandle.WaitAny(new[] { ((IAsyncResult)line).AsyncWaitHandle, cancel.WaitHandle });
                if (which == 1) { Console.Error.WriteLine(); throw new OperationCanceledException(cancel); }
                string text;
                try { text = line.GetAwaiter().GetResult(); }
                catch (System.IO.IOException) { return null; }
                if (text == null) return null;
                foreach (char c in text) s.AppendChar(c);
                s.MakeReadOnly();
                return s;
            }
            while (true)
            {
                while (!Console.KeyAvailable)
                {
                    if (cancel.WaitHandle.WaitOne(50)) { Console.Error.WriteLine(); throw new OperationCanceledException(cancel); }
                }
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

- [ ] **Step 6: Réécrire `src\irisd\Daemon.cs`**

```csharp
using System;
using System.IO;
using System.Net;
using System.Security;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Séquence de démarrage de la spec §7 : data\ → config → events → coffre → CA → proxy → log « irisd ready on … » → attente
    /// Ctrl+C → arrêt (listener fermé, 5 s de grâce, flush du journal et des métadonnées, feuilles détruites).
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
            ProxyServer proxy = null;
            PurgeScheduler purge = null;
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
                    int rc;
                    try { rc = UnlockInteractive(session, clock, cancel); }
                    catch (OperationCanceledException)
                    {
                        stderr.WriteLine("irisd : arrêt demandé pendant la saisie du mot de passe.");
                        return ExitCodes.Ok;
                    }
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
                string pemPath = Path.Combine(dataDir, "ca.pem");
                ca = new CAManager(caStore, pemPath, clock);
                try { ca.EnsureCA(); }
                catch (SecretStoreException ex) { stderr.WriteLine("irisd : CA : " + ex.Message); return ExitCodes.Vault; }

                // 6. proxy
                proxy = new ProxyServer(ProxyOptions.FromConfig(config.Current), secrets, ca, events, clock);
                if (cancel.IsCancellationRequested) { Log.Info("irisd", "arrêt demandé avant le démarrage du proxy"); return ExitCodes.Ok; }
                IPEndPoint endpoint;
                try { endpoint = proxy.Start(); }
                catch (ProxyPortInUseException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Port; }
                catch (ProxyException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Data; }
                purge = new PurgeScheduler(eventStore, clock);

                // 7. prêt
                Log.Info("irisd", "irisd ready on " + endpoint + ", ca=" + pemPath + " (empreinte " + ca.Info.FingerprintSha256 + "). Ctrl+C pour arrêter.");
                cancel.WaitHandle.WaitOne();
                Log.Info("irisd", "arrêt demandé");
                proxy.StopAsync().GetAwaiter().GetResult();
                return ExitCodes.Ok;
            }
            finally
            {
                if (purge != null) purge.Dispose();
                if (proxy != null) proxy.Dispose();
                if (secrets != null) secrets.Clear();
                if (meta != null) meta.Dispose();
                if (ca != null) ca.Dispose();
                if (session != null) session.Dispose();
                eventStore.Dispose();
            }
        }

        /// <summary>Création (mot de passe + confirmation) ou ouverture ; trois échecs ou entrée fermée → code 2 ; Ctrl+C → OperationCanceledException (code 0 chez l'appelant).</summary>
        private int UnlockInteractive(VaultSession session, Func<DateTime> clock, CancellationToken cancel)
        {
            if (!session.Exists)
            {
                stderr.WriteLine("Aucun coffre dans " + session.KdbxPath + " : création d'un nouveau coffre KeePass.");
                for (int attempt = 1; attempt <= MaxPasswordAttempts; attempt++)
                {
                    SecureString first = console.ReadPassword("Mot de passe maître du nouveau coffre : ", cancel);
                    if (first == null) return Closed();
                    if (first.Length == 0) { stderr.WriteLine("Le mot de passe ne peut pas être vide (" + attempt + "/" + MaxPasswordAttempts + ")."); continue; }
                    SecureString second = console.ReadPassword("Confirmez le mot de passe maître : ", cancel);
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
                SecureString password = console.ReadPassword("Mot de passe maître (" + session.KdbxPath + ") : ", cancel);
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

- [ ] **Step 7: Ajuster le test de la phase 1 qui lit le log « prêt »**

Les tests de `tests\DaemonTests.cs` passent un jeton **déjà annulé** : le daemon ne doit alors pas lier le port (il s'arrêterait aussitôt, et le port 8888 par défaut n'est pas forcément libre sur la machine de test). `Daemon.Run` (ci-dessus, étape 6 du démarrage) vérifie `cancel.IsCancellationRequested` juste avant `proxy.Start()` et, le cas échéant, logue `arrêt demandé avant le démarrage du proxy` et rend `ExitCodes.Ok` (déjà dans le code de l'étape 6). Dans `tests\DaemonTests.cs`, ligne 76, remplacer `r.Out.Contains("prêt")` par `r.Out.Contains("arrêt demandé avant le démarrage du proxy")`. Les autres tests de ce fichier ne lisent pas le log « prêt ».

- [ ] **Step 8: Sources + vert + build**

`IRISKIT_SOURCES` : ajouter `"%SRC%\IrisKit\Events\PurgeScheduler.cs"`. `IRISD_SOURCES` inchangé (mêmes fichiers, réécrits).

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -3
cmd //c 'D:\Dev\irispc\build.bat' | tail -1
```

Attendu : `121 test(s) réussi(s), 0 échec(s)`, `[SUCCES]`.

- [ ] **Step 9: Démonstration réelle (spec §1, §11) en mode debug**

```powershell
$d = Join-Path $env:TEMP ("irispc-demo-" + [guid]::NewGuid().ToString("N"))
$env:IRIS_SECRET_demo_key = "sk-demo-VALUE"
$env:IRIS_SECRET_demo_key_HOSTS = "example.com"
$p = Start-Process -FilePath D:\Dev\irispc\build\Iris\irisd.exe -ArgumentList "--foreground","--data","$d","--in-memory-secrets","--in-memory-ca" -PassThru -NoNewWindow -RedirectStandardOutput "$d.log"
Start-Sleep -Seconds 4
curl.exe -s -o NUL -w "%{http_code}`n" http://127.0.0.1:8888/__iris_ping
curl.exe -s -x http://127.0.0.1:8888 --cacert "$d\ca.pem" -H "x-api-key: {{kc:demo_key}}" https://example.com/ -o NUL -w "%{http_code}`n"
Stop-Process -Id $p.Id -Force
Get-Content "$d.log" | Select-String "ready|substitut|passThrough|tunnel|exfil"
Get-ChildItem "$d\events" | Get-Content
Remove-Item -Recurse -Force $d, "$d.log"; Remove-Item Env:IRIS_SECRET_demo_key, Env:IRIS_SECRET_demo_key_HOSTS
```

Attendu : `200` au ping ; `example.com` n'étant pas dans la whitelist par défaut, la requête `curl` passe en tunnel (code HTTP de example.com, `200`), le log montre `tunnel fermé example.com:443` et le journal un event `passThrough`. Pour le chemin MITM réel : ajouter `example.com` dans `hosts` de `config.json` du dossier `$d` (rule `{"host":"example.com","created_at":"…","origin":"user"}`), relancer, refaire le `curl` : le log montre `substitution de demo_key pour GET example.com /` et l'event `substituted` ; sans `--cacert`, `curl` échoue sur le certificat et le log montre `ne fait pas confiance à data\ca.pem`. Ces deux vérifications manuelles vont dans la checklist de la PR.

- [ ] **Step 10: Commit**

```bash
git add src/IrisKit/Events/PurgeScheduler.cs src/irisd/IConsoleInput.cs src/irisd/Daemon.cs tests/TestSupport.cs tests/DaemonProxyTests.cs tests/DaemonTests.cs tests/Tests.cs test.bat build.bat
git commit -m "feat(irisd): démarre le proxy (code 3 si port occupé), arrêt en 5 s, Ctrl+C pendant la saisie, purge planifiée du journal

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: CLAUDE.md, listes de sources, push et PR de la phase 2

**Files:**
- Modify: `CLAUDE.md`, `test.bat`, `build.bat` (listes canoniques)

**Interfaces:**
- Consumes: la branche complète.
- Produces: CI verte, PR vers `main` (merge en squash après confirmation explicite de l'utilisateur, hors plan).

- [ ] **Step 1: Mettre à jour `CLAUDE.md`**

Dans « Phasage », remplacer la ligne `3. **Phase 2** — …` par : `3. **Phase 2** — proxy MITM : `HttpParser`, tunnel, `LeafCertCache`, scanner, `ExfilRuleEngine` R1–R5, `RequestProcessor`, `MITMHandler` (keep-alive, streaming), `irisd --foreground` écoute sur `127.0.0.1:8888` ; démontrable avec le scénario `curl` de la spec §1.`. Dans « Build, tests, rendu », après la puce « Pas de framework de test », ajouter : « Les tests d'intégration du proxy tournent en process : `tests\MockUpstream.cs` (TLS avec son propre CA) et `tests\TestProxyClient.cs` (`CONNECT` puis TLS en confiance au CA du proxy) ; tout sur `127.0.0.1` port 0, jamais de réseau externe. »

- [ ] **Step 2: Listes canoniques des sources**

`IRISKIT_SOURCES` (identique dans `test.bat` et `build.bat`) :

```bat
set IRISKIT_SOURCES="%SRC%\IrisKit\IrisVersion.cs" "%SRC%\IrisKit\DataDir.cs" "%SRC%\IrisKit\Json\JsonParser.cs" "%SRC%\IrisKit\Json\JsonObject.cs" "%SRC%\IrisKit\Json\JsonWriter.cs" "%SRC%\IrisKit\Models\HostName.cs" "%SRC%\IrisKit\Models\Secret.cs" "%SRC%\IrisKit\Models\MITMRule.cs" "%SRC%\IrisKit\Models\Alert.cs" "%SRC%\IrisKit\Models\Event.cs" "%SRC%\IrisKit\Logging\Log.cs" "%SRC%\IrisKit\Logging\Redaction.cs" "%SRC%\IrisKit\Config\Config.cs" "%SRC%\IrisKit\Config\Backups.cs" "%SRC%\IrisKit\Config\ConfigStore.cs" "%SRC%\IrisKit\Events\EventRing.cs" "%SRC%\IrisKit\Events\EventsBus.cs" "%SRC%\IrisKit\Events\JsonlEventStore.cs" "%SRC%\IrisKit\Events\EventPipeline.cs" "%SRC%\IrisKit\Events\PurgeScheduler.cs" "%SRC%\IrisKit\SecretStore\ISecretStore.cs" "%SRC%\IrisKit\SecretStore\InMemorySecretStore.cs" "%SRC%\IrisKit\SecretStore\SecretCache.cs" "%SRC%\IrisKit\SecretStore\EnvSecrets.cs" "%SRC%\IrisKit\SecretStore\SecretsMetaStore.cs" "%SRC%\IrisKit\SecretStore\KeePassVault.cs" "%SRC%\IrisKit\SecretStore\KeePassSecretStore.cs" "%SRC%\IrisKit\SecretStore\VaultSession.cs" "%SRC%\IrisKit\CA\CAMaterial.cs" "%SRC%\IrisKit\CA\CACrypto.cs" "%SRC%\IrisKit\CA\CAKeyStore.cs" "%SRC%\IrisKit\CA\CAManager.cs" "%SRC%\IrisKit\CA\LeafCertCache.cs" "%SRC%\IrisKit\Placeholder\PlaceholderHit.cs" "%SRC%\IrisKit\Placeholder\PlaceholderScanner.cs" "%SRC%\IrisKit\Placeholder\SlidingMinuteCounter.cs" "%SRC%\IrisKit\Placeholder\PlaceholderEngine.cs" "%SRC%\IrisKit\Placeholder\ExfilRuleEngine.cs" "%SRC%\IrisKit\Proxy\HttpMessage.cs" "%SRC%\IrisKit\Proxy\HttpConnection.cs" "%SRC%\IrisKit\Proxy\HttpParser.cs" "%SRC%\IrisKit\Proxy\UpstreamTrust.cs" "%SRC%\IrisKit\Proxy\ProxyOptions.cs" "%SRC%\IrisKit\Proxy\UpstreamClient.cs" "%SRC%\IrisKit\Proxy\ProxyServer.cs" "%SRC%\IrisKit\Proxy\ConnectHandler.cs" "%SRC%\IrisKit\Proxy\TunnelHandler.cs" "%SRC%\IrisKit\Proxy\RequestProcessor.cs" "%SRC%\IrisKit\Proxy\MITMHandler.cs"
```

`TEST_SOURCES` : `"%TESTS%\Check.cs" "%TESTS%\TestSupport.cs" "%TESTS%\Tests.cs" "%TESTS%\JsonTests.cs" "%TESTS%\ModelsTests.cs" "%TESTS%\LoggingTests.cs" "%TESTS%\ConfigTests.cs" "%TESTS%\EventsTests.cs" "%TESTS%\SecretStoreTests.cs" "%TESTS%\MetaStoreTests.cs" "%TESTS%\KeePassTests.cs" "%TESTS%\CATests.cs" "%TESTS%\DaemonTests.cs" "%TESTS%\HttpParserTests.cs" "%TESTS%\PlaceholderTests.cs" "%TESTS%\ExfilTests.cs" "%TESTS%\FuzzTests.cs" "%TESTS%\LeafTests.cs" "%TESTS%\MockUpstream.cs" "%TESTS%\TestProxyClient.cs" "%TESTS%\ProxyTests.cs" "%TESTS%\ProcessorTests.cs" "%TESTS%\MITMTests.cs" "%TESTS%\DaemonProxyTests.cs"`.

```bash
cmd //c 'D:\Dev\irispc\test.bat' | tail -2 && cmd //c 'D:\Dev\irispc\build.bat' | tail -1 && git status --short
```

Attendu : `121 test(s) réussi(s)`, `[SUCCES]`, seuls `CLAUDE.md` (et les `.bat` si réordonnés) modifiés.

- [ ] **Step 3: Commit, push, CI, PR**

```bash
git add CLAUDE.md test.bat build.bat
git commit -m "docs: CLAUDE.md phase 2 (proxy MITM, harnais d'intégration en process)

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
git push -u origin feat/phase-2-proxy
gh pr create --base main --head feat/phase-2-proxy --title "Phase 2 : proxy MITM — HttpParser, tunnel, feuilles, scanner, règles R1–R5, streaming ; irisd écoute sur 127.0.0.1:8888" --body-file <scratchpad>/pr2-body.md
RUN=$(gh run list --branch feat/phase-2-proxy --limit 1 --json databaseId --jq '.[0].databaseId'); gh run watch --exit-status "$RUN"; echo "EXIT=$?"
gh api repos/Sandjab/irispc/actions/runs/$RUN/artifacts --jq '.artifacts[].name'
```

Corps de la PR (`pr2-body.md`) :

```markdown
## Phase 2 — Proxy MITM : tunnel, feuilles, placeholders, règles R1–R5, streaming

Spec : `docs/superpowers/specs/2026-10-17-socle-design.md` (§1, §5.4, §6, §7, §8, §9, §11). Plan : `docs/superpowers/plans/2026-10-17-phase-2-proxy.md`.

- `HttpParser` HTTP/1.1 strict (têtes ≤ 64 KiB / 100 en-têtes, Content-Length, chunked, relais par blocs de 16 KiB avec flush), `HttpConnection` bufferisée avec restes pour la bascule TLS et délai d'inactivité.
- `PlaceholderScanner`, `PlaceholderEngine`, `ExfilRuleEngine` R1–R5 avec quarantaine, `SlidingMinuteCounter` : port d'IRIS, tests et corpus de fuzzing repris (2 010 entrées : robustesse, aucune valeur dans les events, aucune substitution hors scope).
- `LeafCertCache` : feuilles ECDSA P-256 par hôte (CN + SAN, 90 jours, serverAuth) signées par le CA, clé persistée dans le KSP pour Schannel et **supprimée** à l'éviction, au renouvellement et à l'arrêt (test `CngKey.Exists` = false).
- `ProxyServer` (bouclage seul, arrêt coopératif 5 s), `ConnectHandler` (`/__iris_ping`, `405`, `400`, whitelist à chaud), `TunnelHandler` (passthrough, `502`, event `passThrough`), `UpstreamClient` (TLS 1.2, SNI, validation magasin Windows), `RequestProcessor` (pause, drapeaux `bodyTooLarge|nonUtf8|compressedBody|paused`, politique `on_exfil_attempt`), `MITMHandler` (keep-alive, `100 Continue`, corps > 4 MiB en streaming, `502` avant la tête / troncature après, events).
- `irisd --foreground` : proxy démarré après le CA, `irisd ready on 127.0.0.1:8888, ca=data\ca.pem`, code 3 si port occupé ; Ctrl+C pendant la saisie du mot de passe → arrêt code 0 ; purge du journal à minuit UTC.
- Harnais d'intégration en process : `MockUpstream` (TLS, CA propre, streaming, coupure) et `TestProxyClient`.

## Smoke testing

- [ ] `test.bat` : 121 tests OK, code 0 (≈ 60 s)
- [ ] `build.bat` : `build\Iris\irisd.exe`, dossier portable complet
- [ ] `irisd.exe --foreground --data %TEMP%\demo` : mot de passe, `irisd ready on 127.0.0.1:8888, ca=…`, `curl -s http://127.0.0.1:8888/__iris_ping` → `ok`
- [ ] Ajouter `example.com` dans `hosts` de `config.json`, un secret `demo_key` scoped `example.com` (mode `--in-memory-secrets` : `IRIS_SECRET_demo_key` + `_HOSTS`), puis `curl -x http://127.0.0.1:8888 --cacert data\ca.pem -H "x-api-key: {{kc:demo_key}}" https://example.com/` → réponse ; log `substitution de demo_key` ; event `substituted` dans `data\events\events-*.jsonl` avec `status_code`, `duration_ms`, sans la valeur
- [ ] Même `curl` sans `--cacert` → échec TLS côté curl, log `ne fait pas confiance à data\ca.pem`, event `error`
- [ ] `curl -x … https://api.github.com/` (hors whitelist) → réponse GitHub, event `passThrough`, certificat GitHub vu par curl
- [ ] Même secret vers `https://example.org/` (hors `allowed_hosts`, `example.org` whitelisté) → event `exfilBlocked` `hostMismatch` high, requête transmise avec le placeholder littéral
- [ ] `on_exfil_attempt: block_notify_pause` : après le blocage, log `mise en pause`, la requête suivante vers `example.com` part sans substitution avec `"flags":["paused"]`
- [ ] Upload > 4 MiB (`curl --data-binary @gros.bin`) → relayé, event avec `"flags":["bodyTooLarge"]`
- [ ] Lancer un second `irisd` sur le même dossier → `irisd : le port 8888 est déjà utilisé…`, code 3
- [ ] Ctrl+C à l'invite de mot de passe → `arrêt demandé pendant la saisie`, code 0, pas de `iris.kdbx` créé
- [ ] Ctrl+C pendant un `curl` long (SSE) → le daemon s'arrête en moins de 5 s, `arrêté` dans le log
- [ ] CI verte sur la PR, artefact `irispc-portable`
- [ ] `git status` propre après `build.bat` + `test.bat`

🤖 Generated with [Claude Code](https://claude.com/claude-code)
```

- [ ] **Step 4: Rendre compte** — URL de la PR, état de la CI, rappel que le merge en squash attend la confirmation explicite de l'utilisateur. Ne pas merger.

---

## Auto-revue du plan

- **Couverture de la spec** : §5.4 scanner/engine/règles/politique/substitution (tâches 2, 3, 6) ; §6.1 `ProxyServer`, `HttpParser`, `ConnectHandler`, `TunnelHandler`, `MITMHandler`, `UpstreamClient`, `LeafCertCache` (1, 4, 5, 7), `CAManager` (phase 1) ; §6.2 flux par requête : 100 Continue (7), corps ≤ 4 MiB / streaming / nonUtf8 / compressedBody (1, 6, 7), Accept-Encoding et Proxy-Connection (6), scan → engine → règles → pause (6), envoi amont et relais par blocs de 16 KiB avec flush (1, 7), event + RecordUsage + R5 (6, 7), keep-alive / close (7) ; §6.3 poignée de main refusée (7), 502 amont (5, 7), 400 (5), inactivité 120 s (5), port occupé code 3 (8), Ctrl+C : listener, 5 s, flush, clés CNG (5, 8) ; §7 séquence et log `irisd ready on …` (8) ; §8 invariants 1 (`Security_NoSecretValueInProxyDumps`, fuzz I2), 2 (R1 + fuzz I3), 4 (`Leaf_CacheEvictAndDispose_DeleteCngKeys`), 5 (aucun mode ne désactive les règles ; la pause suspend la substitution, pas les règles… elle suspend tout le scan — conforme à §6.2 étape 4), 6 (`TunnelHandler`/`MITMHandler` ne se connectent qu'à l'autorité du CONNECT), bouclage seul (5) ; §9 lignes Scanner, Engine + règles, LeafCertCache, HttpParser, Proxy (intégration) ; §11 phase 2 démontrable (tâche 8 étape 9 et checklist PR).
- **Placeholders** : aucun ; chaque étape porte son code ou sa commande.
- **Cohérence des types** : `HttpHeaders.First/Set/Remove/Contains/All/Clone`, `HttpRequestHead(method, target, version, headers)`, `HttpResponseHead(version, status, reason, headers)` utilisés identiquement en 1, 2, 5, 6, 7, tests ; `HttpParser.ReadBodyAsync(conn, framing, max, ct) : BufferedBody` et `RelayRemainderAsync(from, to, framing, partial, ct)` en 1 et 7 ; `PlaceholderScanner.Scan(HttpHeaders, string, string)` en 2, 3, 6 ; `ExfilRuleEngine(ISecretStore, Func<int>, Func<DateTime>)` en 3, 6 ; `PlaceholderEngine.SubstituteAsync(HttpHeaders, string, byte[], IList<PlaceholderHit>)` en 2, 3, 6 ; `RequestProcessor.ProcessAsync(head, body, bodyTooLarge, host, paused)` en 6, 7 ; `ProxyServer(options, secrets, ca, events, clock)` en 5, 6, 7, 8 ; `LeafCertCache(ca, clock).Get(host)` en 4, 5, 7 ; `UpstreamClient.ConnectTcpAsync/ConnectTlsAsync` en 5, 7 ; `IConsoleInput.ReadPassword(prompt, cancel)` en 8 et `ScriptedConsoleInput` ; `Event` à douze arguments partout (`new Event(Guid, DateTime, EventKind, host, method, path, int?, long?, IList<string>, Alert, SystemAlert, EventFlags)`).
- **Review Focus** : 1 → `MITM_ClientRejectsCA_ErrorEvent` (7) ; 2 → `MITM_LargeBody_StreamedWithFlag` (7) ; 3 → `Proxy_Tunnel502` (5) et `MITM_Upstream502` (7) ; 4 → `Entry_PortInUse_Exit3` (8) ; 5 → `MITM_KeepAlive_TwoRequests` (7).
- **Décisions prises par le plan, à confirmer en revue** : (a) un corps entièrement bufferisé est toujours renvoyé à l'amont en `Content-Length` (chunked décodé), seul le corps trop grand garde son cadrage d'origine ; (b) corps trop grand, non UTF-8 ou compressé : en-têtes et URL quand même scannés et substitués (spec §6.2), le corps part intact ; (c) le port du `CONNECT` est honoré pour le MITM comme pour le tunnel (IRIS fixe 443 côté MITM) ; (d) `Expect` est retiré et le `100 Continue` est rendu par le proxy avant de lire le corps ; (e) `/__iris_ping` répond aussi dans un tunnel déchiffré sans fermer ; (f) une réponse amont sans cadrage (`UntilClose`) ferme la connexion cliente après relais ; (g) Ctrl+C pendant la saisie du mot de passe = arrêt normal, code 0 ; (h) le proxy refuse une adresse d'écoute hors bouclage (audit IRIS M-4, non écrit dans la spec socle) ; (i) la purge planifiée vit dans `PurgeScheduler` (timer), pas dans `JsonlEventStore` ; (j) l'alerte est celle de la première règle déclenchée (ordre R1→R5 = sévérité décroissante), identique à l'implémentation IRIS, ce que « sévérité = max » de la spec §5.4 décrit.
