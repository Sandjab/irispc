using System;
using System.IO;
using System.Reflection;
using System.Text;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    /// <summary>
    /// Harnais de tests sans framework : compilé et exécuté par test.bat avec le csc.exe natif.
    /// Remplace src\irisd\Program.cs ; chaque test est une méthode, Summary() donne le code de sortie.
    /// </summary>
    public static partial class TestMain
    {
        public static int Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Check.Run("Check : Eq et Throws signalent les écarts", Check_SelfTest);
            Check.Run("Version : constante, assembly et manifeste cohérents", Version_Consistent);
            Check.Run("KeePassLib : chargeable depuis KeePass.exe 2.61.1", KeePassLib_Loads);
            Check.Run("Arguments : --foreground seul", Arguments_ForegroundOnly);
            Check.Run("Arguments : toutes les options de la spec §7", Arguments_AllOptions);
            Check.Run("Arguments : --version, --help, vide", Arguments_VersionHelpEmpty);
            Check.Run("Arguments : option inconnue, casse, positionnel", Arguments_Unknown);
            Check.Run("Arguments : valeur manquante ou vide pour --data et --log-level", Arguments_MissingValue);
            Check.Run("Arguments : niveau de log inconnu", Arguments_BadLogLevel);
            Check.Run("Arguments : option répétée refusée", Arguments_Duplicate);
            Check.Run("Arguments : usage en français, accents intacts", Arguments_UsageText);
            Check.Run("Json : aller-retour ordonné, indentation", Json_RoundTripOrdered);
            Check.Run("Json : compact et échappements", Json_CompactAndEscapes);
            Check.Run("Json : dates ISO 8601 UTC", Json_Dates);
            Check.Run("Json : erreurs de parse et d'accès", Json_Errors);
            Check.Run("Json : nombres", Json_Numbers);
            Check.Run("Modèles : validation des hôtes", Models_HostName);
            Check.Run("Modèles : validation des secrets", Models_SecretValidation);
            Check.Run("Modèles : Secret ↔ JSON", Models_SecretJson);
            Check.Run("Modèles : MITMRule ↔ JSON", Models_MITMRule);
            Check.Run("Modèles : Event avec Alert (fixture IRIS)", Models_EventWithAlert);
            Check.Run("Modèles : Event systemAlert, flags, compat", Models_EventSystemAlertAndFlags);
            Check.Run("Modèles : valeurs de fil des énumérations", Models_EnumWire);
            Check.Run("Logging : niveaux et format", Logging_LevelsAndFormat);
            Check.Run("Logging : valeurs de fil des niveaux", Logging_LevelWire);
            Check.Run("Logging : redaction", Logging_Redaction);
            Check.Run("Config : défauts et format de fil", Config_DefaultAndWire);
            Check.Run("Config : plugins conservé tel quel", Config_PluginsPreservedRaw);
            Check.Run("Config : validation de chaque champ", Config_Validation);
            Check.Run("Backups : copie horodatée et rotation", Backups_CopyAndRotate);
            Check.Run("ConfigStore : seed et relecture", ConfigStore_SeedAndLoad);
            Check.Run("ConfigStore : Save, backups, rotation", ConfigStore_SaveBackupsRotation);
            Check.Run("ConfigStore : démarrage dégradé sur corruption", ConfigStore_Corrupted_DegradedBoot);
            Check.Run("ConfigStore : erreur d'E/S irrécupérable", ConfigStore_IOError);
            Check.Run("Events : ring borné et totaux", Events_Ring);
            Check.Run("Events : bus d'abonnés", Events_Bus);
            Check.Run("Events : journal JSONL par jour, purge", Events_JsonlStore);
            Check.Run("Events : pipeline", Events_Pipeline);
            Check.Run("SecretStore : contrat (mémoire)", SecretStore_InMemoryContract);
            Check.Run("SecretStore : copies défensives", SecretStore_InMemoryDefensiveCopies);
            Check.Run("SecretStore : cache LRU 32 / TTL", SecretStore_Cache);
            Check.Run("EnvSecrets : chargement IRIS_SECRET_*", EnvSecrets_Load);
            Check.Run("EnvSecrets : sans hôtes = ignoré", EnvSecrets_MissingHosts_Ignored);
            Check.Run("MetaStore : défauts, Flush, purge, format", MetaStore_DefaultsAndFlush);
            Check.Run("MetaStore : débounce et Dispose", MetaStore_DebounceAndDispose);
            Check.Run("MetaStore : fichier corrompu = repart vide", MetaStore_CorruptFileStartsEmpty);
            Check.Run("KeePass : création, contrat, réouverture, schéma", KeePass_CreateContractReopen);
            Check.Run("KeePass : mauvais mot de passe et corruption", KeePass_WrongPasswordAndCorruption);
            Check.Run("KeePass : .lock = VaultBusy en écriture seulement", KeePass_LockFile_VaultBusy);
            Check.Run("KeePass : backup avant écriture et rotation", KeePass_BackupsBeforeWrite);
            Check.Run("KeePass : contenu étranger ignoré", KeePass_ForeignContentIgnored);
            Check.Run("KeePass : entrée CA du groupe ca", KeePass_CAEntry);
            Check.Run("KeePass : entrée malformée sautée avec avertissement", KeePass_MalformedEntry_SkippedWithWarning);
            Check.Run("KeePass : Save échoué = rechargement depuis le disque", KeePass_SaveFailure_ReloadsFromDisk);
            Check.Run("CA : génération, export PEM, rechargement", CA_GenerateAndReload);
            Check.Run("CA : désaccord clé/certificat ou expiration → régénération", CA_MismatchOrExpiredRegenerates);
            Check.Run("CA : persistance dans le coffre KeePass", CA_KeePassKeyStore);
            Check.Run("Daemon : arguments, codes de sortie, résolution de data\\", Entry_ArgumentsAndExitCodes);
            Check.Run("Daemon : crée le coffre, le CA et ca.pem, puis les recharge", Entry_CreatesVaultAndCA);
            Check.Run("Daemon : trois mots de passe refusés → 2, EOF → 2", Entry_WrongPasswordThreeTimes_Exit2);
            Check.Run("Daemon : confirmation du mot de passe à la création", Entry_PasswordMismatchOnCreate);
            Check.Run("Daemon : data\\ inutilisable → 1", Entry_DataDirNotWritable_Exit1);
            Check.Run("Daemon : config.json corrompu = démarrage dégradé", Entry_CorruptedConfig_StillStarts);
            Check.Run("Daemon : --in-memory-secrets et --in-memory-ca", Entry_InMemorySecretsAndCA);
            Check.Run("Sécurité : aucune valeur de secret dans les dumps", Security_NoSecretValueInDumps);
            Check.Run("Daemon : exception inattendue → message et code 1", Entry_UnexpectedException_NoStackTrace);
            Check.Run("HTTP : tête de requête", Http_RequestHead);
            Check.Run("HTTP : limites et erreurs de tête", Http_HeadLimitsAndErrors);
            Check.Run("HTTP : tête de réponse et cadrage", Http_ResponseHeadAndFraming);
            Check.Run("HTTP : encodage des têtes et HttpHeaders", Http_EncodeHeads);
            Check.Run("HTTP : corps Content-Length et chunked bufferisés", Http_ReadBodyContentLengthAndChunked);
            Check.Run("HTTP : relais streaming", Http_RelayBodyStreaming);
            Check.Run("HTTP : restes, préfixe, délai, annulation", Http_ConnectionLeftoverAndTimeout);
            Check.Run("Scanner : emplacements", Scanner_Locations);
            Check.Run("Scanner : noms invalides et snippets", Scanner_InvalidNamesAndSnippets);
            Check.Run("Compteur : fenêtre glissante inclusive", Counter_SlidingMinute);
            Check.Run("Engine : substitue seulement les hits autorisés", Engine_SubstitutesOnlyAuthorized);
            Check.Run("Engine : toutes les occurrences, corps, URI, cache, non UTF-8", Engine_AllOccurrencesBodyUriAndCache);
            Check.Run("Exfil : R1 hostMismatch", Exfil_R1_HostMismatch);
            Check.Run("Exfil : R2 nonCanonicalLocation", Exfil_R2_NonCanonicalLocation);
            Check.Run("Exfil : R3 multipleSecrets (connus seulement)", Exfil_R3_MultipleSecrets);
            Check.Run("Exfil : R4 derrière R2", Exfil_R4_BehindR2);
            Check.Run("Exfil : R5 volumeAnomaly", Exfil_R5_VolumeAnomaly);
            Check.Run("Exfil : composition et quarantaine", Exfil_CompositionAndQuarantine);
            Check.Run("Fuzz : scan borné, pipeline sans exception", Fuzz_ScanBoundedAndPipelineNeverThrows);
            Check.Run("Fuzz : la valeur sentinelle n'apparaît dans aucun event", Fuzz_SentinelNeverInEncodedEvent);
            Check.Run("Fuzz : hors scope jamais substitué", Fuzz_OutOfScopeNeverSubstituted);
            Check.Run("Feuilles : signée par le CA, SAN, validité", Leaf_SignedByCA_SanValidity);
            Check.Run("Feuilles : cache, éviction et Dispose suppriment les clés CNG", Leaf_CacheEvictAndDispose_DeleteCngKeys);
            Check.Run("Feuilles : renouvellement avant expiration", Leaf_RenewalNearExpiry);
            Check.Run("Feuilles : poignée de main Schannel et racine épinglée", Leaf_SchannelHandshake_PinnedTrust);
            Check.Run("Confiance amont : magasin système", UpstreamTrust_System);
            Check.Run("Proxy : démarrage, arrêt, port occupé, bouclage seul", Proxy_StartStopAndLoopbackOnly);
            Check.Run("Proxy : /__iris_ping", Proxy_Ping);
            Check.Run("Proxy : 405 et 400", Proxy_NonConnect405_BadAuthority400);
            Check.Run("Proxy : tunnel hors whitelist, certificat amont préservé", Proxy_TunnelPassthrough);
            Check.Run("Proxy : amont injoignable → 502", Proxy_Tunnel502);
            Check.Run("Proxy : UpdateRules, pause, options", Proxy_UpdateRulesPauseAndOptions);
            Check.Run("Proxy : arrêt forcé et délai d'inactivité", Proxy_StopClosesConnections_AndIdleTimeout);
            Check.Run("Processor : substitution, en-têtes de saut, usage", Processor_SubstitutesStripsHopHeadersRecordsUsage);
            Check.Run("Processor : blocage et politique on_exfil_attempt", Processor_BlockedAppliesPolicy);
            Check.Run("Processor : pause = contournement avec drapeau", Processor_PausedBypasses);
            Check.Run("Processor : drapeaux bodyTooLarge, nonUtf8, compressedBody", Processor_FlagsBodyTooLargeNonUtf8Compressed);
            Check.Run("Processor : noMatch, inconnu, Content-Length", Processor_NoMatchUnknownAndContentLength);
            Check.Run("MITM : la valeur substituée atteint l'amont", MITM_SubstitutedValueReachesUpstream);
            Check.Run("MITM : R1 bloqué, littéral transmis, event", MITM_HostMismatch_BlockedForwardedLiteral);
            Check.Run("MITM : keep-alive, deux requêtes, amont réutilisé", MITM_KeepAlive_TwoRequests);
            Check.Run("MITM : streaming chunk par chunk", MITM_StreamingChunksArriveIncrementally);
            Check.Run("MITM : coupure amont en plein flux", MITM_UpstreamDropMidStream_TruncatesClient);
            Check.Run("MITM : corps > 4 MiB relayé avec bodyTooLarge", MITM_LargeBody_StreamedWithFlag);
            Check.Run("MITM : corps non UTF-8 et compressé", MITM_NonUtf8AndCompressedBody_Flags);
            Check.Run("MITM : amont injoignable → 502", MITM_Upstream502);
            Check.Run("MITM : client qui refuse le CA → event error", MITM_ClientRejectsCA_ErrorEvent);
            Check.Run("MITM : pause automatique et reprise", MITM_PausePolicyAndResume);
            Check.Run("MITM : R5 après le seuil", MITM_VolumeAnomaly_R5);
            Check.Run("MITM : Expect 100-continue et ping", MITM_Expect100ContinueAndPing);
            Check.Run("Sécurité : aucune valeur dans les dumps du proxy", Security_NoSecretValueInProxyDumps);
            Check.Run("Daemon : démarre le proxy et répond au ping", Entry_StartsProxyAndAnswersPing);
            Check.Run("Daemon : port occupé → 3", Entry_PortInUse_Exit3);
            Check.Run("Daemon : Ctrl+C pendant la saisie → 0", Entry_CtrlC_DuringPrompt_Exit0);
            Check.Run("PurgeScheduler : minuit UTC et RunNow", PurgeScheduler_NextMidnightAndRunNow);
            Check.Run("Revue : tunnel, long téléchargement avec client silencieux", Fix_TunnelLongDownload_SurvivesClientSilence);
            Check.Run("Revue : connexion déchiffrée inactive sans event error", Fix_IdleDecryptedConnection_NoErrorEvent);
            Check.Run("Revue : erreur du coffre → 502, event error, warn", Fix_SecretStoreError_502AndErrorEvent);
            Check.Run("Revue : valeur avec CR/LF/NUL jamais substituée", Fix_Engine_CrLfValueNeverSubstituted);
            Check.Run("Revue : valeur non ASCII octet pour octet dans les en-têtes", Fix_Engine_NonAsciiValueKeepsUtf8BytesInHeaders);
            Check.Run("Revue : Transfer-Encoding non chunked-final rejeté", Fix_Http_TransferEncodingNonChunkedRejected);
            Check.Run("Revue : corps chunked trop grand sans Content-Length", Fix_MITM_LargeChunkedBody_DropsContentLength);
            Check.Run("IPC : trames, aller-retour et plafonds", Frame_RoundTripAndLimits);
            Check.Run("IPC : décodage des requêtes JSON-RPC", JsonRpc_ParseRequest);
            Check.Run("IPC : enveloppes de réponse et côté client", JsonRpc_Envelopes);
            Check.Run("Config : config.set à chaud et structurel", Config_ApplyUpdates_HotAndStructural);
            Check.Run("Config : config.set atomique en cas d'erreur", Config_ApplyUpdates_AtomicOnError);
            Check.Run("Config : rule.add / rule.delete", Config_Hosts_AddDelete);
            Check.Run("Config : config.reload", Config_Reload);
            Check.Run("VaultGate : absent, création, déverrouillage, délai", VaultGate_AbsentCreateThenUnlock);
            Check.Run("VaultGate : délai exponentiel plafonné à 60 s", VaultGate_DelayDoublesAndCaps);
            Check.Run("VaultGate : tentatives concurrentes", VaultGate_ConcurrentWrongAttempts);
            Check.Run("VaultGate : échec du CA, porte fermée", VaultGate_CAFailureStaysLocked);
            Check.Run("VaultGate : mode --in-memory-secrets", VaultGate_InMemory);
            Check.Run("Porte : coffre fermé → 503 pour la whitelist, tunnel sinon", ProxyGate_LockedRefusesWhitelistedTunnelsOthers);
            Check.Run("Porte : Activate active le MITM sans redémarrer", ProxyGate_ActivateEnablesMITMWithoutRestart);
            Check.Run("Porte : UpdateSecurity à chaud", ProxyGate_UpdateSecurityHot);
            Check.Run("Porte : bind, InUse et AccessDenied distincts", PortBinding_Translate);
            Check.Run("Pipe : requêtes successives et clients concurrents", AdminPipe_RoundTripSequentialAndConcurrent);
            Check.Run("Pipe : second serveur refusé (FIRST_PIPE_INSTANCE)", AdminPipe_SecondServerRefused);
            Check.Run("Pipe : identité du serveur vérifiée avant tout envoi", AdminPipe_IdentityChecked);
            Check.Run("Pipe : trame trop grande ou tronquée", AdminPipe_OversizeAndTruncatedFrames);
            Check.Run("Pipe : ACL utilisateur courant, NETWORK refusé", AdminPipe_SecurityDescriptor);
            Check.Run("Pipe : Stop avec un client inactif", AdminPipe_StopReleasesName);
            Check.Run("Pipe : Stop ne laisse jamais d'instance derrière lui", AdminPipe_StopRaceNeverLeaksInstance);
            Check.Run("Dispatcher : enveloppes et erreurs standard", Dispatcher_EnvelopeErrors);
            Check.Run("Dispatcher : secret.* sans jamais de valeur", Dispatcher_SecretMethods);
            Check.Run("Dispatcher : secret.* refusées coffre fermé (-32020)", Dispatcher_VaultLockedRefusals);
            Check.Run("Dispatcher : vault.status / unlock / create", Dispatcher_VaultMethods);
            Check.Run("Dispatcher : logs sans paramètres", Dispatcher_LogsMethodNeverParams);
            Check.Run("Méthodes : rule.* et config.*", Methods_RulesAndConfig);
            Check.Run("Méthodes : daemon.status / stats / pause / resume", Methods_DaemonStatusAndPause);
            Check.Run("Méthodes : events.query (ring + journal) et events.clear", Methods_EventsQueryAndClear);
            Check.Run("Méthodes : ca.export_path / fingerprint / is_trusted", Methods_CA);
            Check.Run("SSE : en-têtes, connected, event en direct", Sse_StreamsLiveEventsWithHeaders);
            Check.Run("SSE : backlog since sans doublon", Sse_SinceBacklogNoDuplicates);
            Check.Run("SSE : filtres kind et host", Sse_FiltersKindAndHost);
            Check.Run("SSE : ping périodique", Sse_Ping);
            Check.Run("SSE : 404, 405, 400", Sse_Errors);
            Check.Run("SSE : 32 abonnés au plus (503)", Sse_SubscriberLimit);
            Check.Run("SSE : abonné lent → dropped, Emit jamais bloqué", Sse_SlowConsumerDropped);
            Check.Run("SSE : bouclage seul, port occupé", Sse_LoopbackAndPortInUse);
            Check.Run("SSE : Stop ferme les abonnés", Sse_StopClosesSubscribers);
            Check.Run("irisd : --locked et incompatibilité", Arguments_Locked);
            Check.Run("irisd : --locked → 503, vault.unlock par le pipe → MITM", Daemon_LockedThenPipeUnlock_EnablesMITM);
            Check.Run("irisd : vault.unlock annule l'invite console", Daemon_PipeUnlockCancelsConsolePrompt);
            Check.Run("irisd : pipe déjà existant → 3", Daemon_PipeInUse_Exit3);
            Check.Run("irisd : port SSE occupé → 3", Daemon_SsePortInUse_Exit3);
            Check.Run("irisd : rule.add et config.set à chaud par le pipe", Daemon_HotRulesViaPipe);
            Check.Run("irisd : arrêt avec un client du pipe inactif", Daemon_StopWithIdlePipeClient);
            Check.Run("Sécurité : ni valeur ni mot de passe nulle part (pipe, SSE, logs, fichiers)", Security_NoValueOrPasswordAnywhere);
            Check.Run("Revue finale : lire le journal ne bloque pas Append", Final_JournalReadDoesNotBlockAppend);
            Check.Run("Revue finale : -32700 sans fragment de la requête", Final_ParseErrorNeverEchoesPayload);
            Check.Run("Revue finale : le pipe survit à un échec de création d'instance", Final_AdminPipeSurvivesInstanceFailure);
            Check.Run("FileIdentity : jonction, casse, copie, absent", FileIdentity_SameFileThroughJunctionCaseAndCopy);
            Check.Run("Pipe admin : identité du serveur par fichier (jonction acceptée, copie refusée)", AdminPipe_IdentityByFile);
            Check.Run("OrderedJson : aller-retour, ordre des clés, format", OrderedJson_RoundTripAndOrder);
            Check.Run("OrderedJson : chaînes, échappements, nombres", OrderedJson_StringsAndNumbers);
            Check.Run("OrderedJson : refus du mode strict, positions", OrderedJson_StrictRejections);
            Check.Run("OrderedJson : JSONC (commentaires, virgules finales)", OrderedJson_Jsonc);
            Check.Run("OrderedJson : Set et Clone", OrderedJson_SetAndClone);
            Check.Run("OrderedJson : limite d'imbrication", OrderedJson_DepthLimit);
            Check.Run("OrderedJson : plusieurs Mo, non ASCII, temps linéaire", OrderedJson_LargeUnicodeRoundTrip);
            Check.Run("McpPatcher : six variables, ordre, chemin Windows", McpPatcher_AddsSixVarsInOrder);
            Check.Run("McpPatcher : valeurs utilisateur et placeholders conservés", McpPatcher_PreservesUserValues);
            Check.Run("McpPatcher : http/sse sans env ignorés", McpPatcher_HttpSseRules);
            Check.Run("McpPatcher : idempotence, emplacement de mcpServers, cas limites", McpPatcher_IdempotentAndLocations);
            Check.Run("Registre des fichiers enrobés : ajout, retrait, corruption", WrappedPaths_Registry);
            Check.Run("CLI : analyse des arguments", CliArguments_Parse);
            Check.Run("CLI : aide, version, codes d'usage", Cli_HelpVersionAndUsageCodes);
            Check.Run("CLI : résolution du nom du pipe", PipeNames_Resolution);
            Check.Run("CLI : daemon injoignable et identité refusée → 2", Cli_DaemonUnreachableAndIdentity);
            Check.Run("CLI : pipe fermé en cours d'appel → 2", Cli_PipeClosedMidCall_Exit2);
            Check.Run("CLI : status, pause, resume", Cli_StatusPauseResume);
            Check.Run("CLI : durées et tableaux", TextFormatter_Durations);
            Check.Run("CLI : valeur de secret (saut de ligne, vide, binaire)", SecretValue_Normalize);
            Check.Run("CLI : cycle de vie d'un secret, sans valeur en sortie", Cli_SecretLifecycle);
            Check.Run("CLI : règles MITM", Cli_Rules);
            Check.Run("CLI : temps relatifs", RelativeTime_Parse);
            Check.Run("CLI : config get/set/reload", Cli_ConfigGetSetReload);
            Check.Run("CLI : ca export/fingerprint/is-trusted", Cli_Ca);
            Check.Run("CLI : logs ponctuel et filtres", Cli_LogsOneShot);
            Check.Run("CLI : logs --follow puis annulation", Cli_LogsFollow);
            Check.Run("CLI : logs --follow quand le daemon s'arrête → 3", Cli_LogsFollowEndsWhenDaemonStops);
            Check.Run("CLI : vault unlock/create exigent une console", Cli_VaultRequiresConsole);
            Check.Run("CLI : vault unlock sur un coffre verrouillé", Cli_VaultUnlockLocked);
            Check.Run("CLI : vault create sur un coffre absent", Cli_VaultCreateAbsent);
            Check.Run("McpWrapper : wrap, idempotence, unwrap, registre", McpWrapper_WrapAndUnwrap);
            Check.Run("McpWrapper : BOM et CRLF conservés", McpWrapper_BomCrlfPreserved);
            Check.Run("McpWrapper : commentaires, --dry-run, écriture concurrente, contenu déjà vu", McpWrapper_CommentsDryRunAndRace);
            Check.Run("McpWrapper : fichier absent, invalide, non UTF-8, backup invalide", McpWrapper_Errors);
            Check.Run("McpFileWatcher : debounce et filtre de nom", McpFileWatcher_Debounces);
            Check.Run("CLI : mcp wrap/unwrap, --dry-run, --json, codes", Cli_McpWrapUnwrap);
            Check.Run("CLI : mcp wrap sur un chemin avec espaces et accents (~)", Cli_McpWrapPathWithSpacesAndAccents);
            Check.Run("CLI : mcp wrap --watch (re-patch, pas de boucle, daemon relancé)", Cli_McpWatch);
            Check.Run("Doctor : contrôles unitaires", Doctor_PureChecks);
            Check.Run("CLI : doctor (ok, fail, sans daemon)", Cli_Doctor);
            Check.Run("Sécurité : la CLI n'affiche jamais une valeur ni un mot de passe", Security_CliNeverPrintsValuesOrPasswords);
            Check.Run("Revue finale 5 : changement avant l'attente jamais perdu (--watch)", Final5_WatcherChangeBeforeWaitNotLost);
            Check.Run("Revue finale 5 : secret add à la console sans écho", Final5_SecretAddAtConsoleNoEcho);
            Check.Run("Revue finale 5 : BOM UTF-8 en tête retiré de la valeur", Final5_SecretValueStripsLeadingBom);
            Check.Run("Revue finale 5 : erreur d'usage sans recopier l'argument en trop", Final5_UsageNeverEchoesStrayArgument);

            return Check.Summary();
        }

        // ---- Harnais ---------------------------------------------------

        private static void Check_SelfTest()
        {
            CheckException ex = Check.Throws<CheckException>(delegate { Check.Eq(1, 2, "un contre deux"); }, "Eq détecte l'écart");
            Check.True(ex.Message.Contains("attendu <1>") && ex.Message.Contains("obtenu <2>"), "le message cite les deux valeurs");
            Check.Throws<CheckException>(delegate { Check.True(false, "faux"); }, "True(false) lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { }, "rien"); },
                "Throws sans exception lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { throw new ArgumentException("x"); }, "autre"); },
                "Throws avec un autre type lève");
        }

        // ---- Version ---------------------------------------------------

        private static void Version_Consistent()
        {
            Version assembly = typeof(IrisVersion).Assembly.GetName().Version;
            Check.Eq(IrisVersion.Value + ".0", assembly.ToString(), "AssemblyVersion = IrisVersion.Value + .0");

            string manifest = File.ReadAllText(RepoPath("app.manifest"));
            Check.True(manifest.Contains("version=\"" + IrisVersion.Value + ".0\""), "app.manifest porte la même version");
        }

        // ---- KeePass ---------------------------------------------------

        private static void KeePassLib_Loads()
        {
            KeePassLib.PwDatabase db = new KeePassLib.PwDatabase();
            Check.True(!db.IsOpen, "base neuve fermée");
            Check.Eq("2.61.1.0", typeof(KeePassLib.PwDatabase).Assembly.GetName().Version.ToString(), "version de l'assembly KeePass");
        }

        // ---- Arguments de irisd ----------------------------------------

        private static void Arguments_ForegroundOnly()
        {
            Arguments a = Arguments.Parse(new[] { "--foreground" });
            Check.True(a.Foreground, "Foreground");
            Check.True(!a.ShowVersion && !a.ShowHelp && !a.InMemorySecrets && !a.InMemoryCa, "autres drapeaux à faux");
            Check.Eq(null, a.Data, "Data par défaut");
            Check.Eq(null, a.LogLevel, "LogLevel par défaut");
        }

        private static void Arguments_AllOptions()
        {
            Arguments a = Arguments.Parse(new[] {
                "--foreground", "--data", "D:\\iris data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "debug" });
            Check.True(a.Foreground && a.InMemorySecrets && a.InMemoryCa, "drapeaux");
            Check.Eq("D:\\iris data", a.Data, "Data conservé tel quel, espace compris");
            Check.Eq("debug", a.LogLevel, "LogLevel");
            foreach (string level in Arguments.LogLevels)
                Check.Eq(level, Arguments.Parse(new[] { "--log-level", level }).LogLevel, "niveau " + level);
            Check.Eq("trace,debug,info,warn,error", string.Join(",", Arguments.LogLevels), "niveaux IRIS");
        }

        private static void Arguments_VersionHelpEmpty()
        {
            Check.True(Arguments.Parse(new[] { "--version" }).ShowVersion, "--version");
            Check.True(Arguments.Parse(new[] { "--help" }).ShowHelp, "--help");
            Arguments empty = Arguments.Parse(new string[0]);
            Check.True(!empty.Foreground && !empty.ShowVersion && !empty.ShowHelp, "vide : rien de demandé");
        }

        private static void Arguments_Unknown()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--foreground", "--verbose" }); }, "option inconnue");
            Check.True(ex.Message.Contains("--verbose"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--Foreground" }); }, "sensible à la casse");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "foreground" }); }, "positionnel refusé");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "-f" }); }, "forme courte refusée");
        }

        private static void Arguments_MissingValue()
        {
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--data" }); }, "--data en fin");
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "--foreground" }); }, "--data suivi d'une option");
            Check.True(ex.Message.Contains("--data"), "le message cite --data");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--data", "" }); }, "--data vide");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--data", "  " }); }, "--data fait d'espaces (revue phase 0)");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level" }); }, "--log-level en fin");
        }

        private static void Arguments_BadLogLevel()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--log-level", "verbose" }); }, "niveau inconnu");
            Check.True(ex.Message.Contains("verbose") && ex.Message.Contains("debug"), "le message cite la valeur et les niveaux attendus");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level", "INFO" }); }, "casse des niveaux");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level", "warning" }); }, "warning n'est pas une valeur IRIS (warn)");
        }

        private static void Arguments_Duplicate()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "a", "--data", "b" }); }, "--data répété");
            Check.True(ex.Message.Contains("--data"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--foreground" }); }, "--foreground répété");
        }

        private static void Arguments_UsageText()
        {
            string usage = Arguments.Usage();
            Check.True(usage.StartsWith("Usage : irisd --foreground"), "première ligne");
            foreach (string option in new[] { "--foreground", "--data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "--version", "--help" })
                Check.True(usage.Contains(option), "usage cite " + option);
            Check.True(usage.Contains("d\u00e9faut"), "accent é intact (codepage 65001)");
            Check.True(usage.Contains("DEBUG"), "les modes in-memory sont marqués DEBUG");
            Check.True(usage.Contains("trace | debug | info | warn | error"), "niveaux IRIS dans l'aide");
        }

        // ---- Outils ----------------------------------------------------

        /// <summary>Chemin d'un fichier du dépôt, depuis l'emplacement de Iris.Tests.exe (tests\).</summary>
        private static string RepoPath(string relative)
        {
            string testsDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            return Path.GetFullPath(Path.Combine(testsDir, "..", relative));
        }
    }
}
