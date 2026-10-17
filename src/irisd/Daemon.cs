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
