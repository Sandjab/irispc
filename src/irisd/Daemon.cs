using System;
using System.IO;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Séquence de démarrage (spec phase 3 §9) : data\ → config → events → porte du coffre → proxy → SSE → pipe admin →
    /// « irisd ready » → invite console (sauf --locked ou coffre déjà ouvert) → attente de Ctrl+C → arrêt pipe, SSE, proxy,
    /// puis coffre et journal. Rend un code de sortie ; stderr ne reçoit que l'invite et les erreurs fatales, le reste passe par Log.
    /// </summary>
    public sealed class Daemon
    {
        public const int MaxPasswordAttempts = 3;

        private readonly Arguments options;
        private readonly TextWriter stdout;
        private readonly TextWriter stderr;
        private readonly IPasswordReader console;

        public Daemon(Arguments options, TextWriter stdout, TextWriter stderr, IPasswordReader console)
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
            JsonlEventStore eventStore = new JsonlEventStore(Path.Combine(dataDir, "events"), config.Current.Broker.EventRetentionDays, clock);
            eventStore.Purge();
            EventPipeline events = new EventPipeline(ring, eventStore, new EventsBus());
            if (config.RecoveredFromCorruption)
                events.Emit(Event.System(clock(), AlertSeverity.High, "config",
                    "config.json corrompu, valeurs par défaut rétablies (copie dans backups\\) : " + config.CorruptionDetail));

            VaultGate vault = null;
            DaemonServices services = null;
            PurgeScheduler purge = null;
            try
            {
                // 4. porte du coffre
                try { vault = OpenGate(dataDir, clock); }
                catch (SecretStoreException ex) { stderr.WriteLine("irisd : CA : " + ex.Message); return ExitCodes.Vault; }
                vault.MaxBackups = config.Current.Backups.MaxCount;
                if (cancel.IsCancellationRequested) { Log.Info("irisd", "arrêt demandé avant le démarrage des services"); return ExitCodes.Ok; }

                // 5. proxy, flux SSE, pipe admin
                services = new DaemonServices(config, vault, events, clock);
                int rc = services.Start(stderr);
                if (rc != ExitCodes.Ok) return rc;
                purge = new PurgeScheduler(eventStore, clock);
                Log.Info("irisd", "irisd ready on " + services.Proxy.ListenEndPoint + ", events " + services.Sse.ListenEndPoint
                    + ", pipe \\\\.\\pipe\\" + config.Current.Broker.AdminPipe + ", coffre " + StateLabel(vault.State)
                    + ", ca=" + vault.PemPath + ". Ctrl+C pour arrêter.");

                // 6. invite console
                if (!options.Locked && vault.State != VaultState.Unlocked)
                {
                    int code = new ConsoleUnlock(vault, console, stderr).Run(cancel);
                    if (code != ExitCodes.Ok) return code;
                }

                // 7. attente
                cancel.WaitHandle.WaitOne();
                Log.Info("irisd", "arrêt demandé");
                return ExitCodes.Ok;
            }
            finally
            {
                if (purge != null) purge.Dispose();
                if (services != null) services.Dispose();
                if (vault != null) vault.Dispose();
                eventStore.Dispose();
            }
        }

        /// <summary>Porte KeePass (CA dans le coffre, ou éphémère avec --in-memory-ca), ou porte en mémoire ouverte d'emblée (--in-memory-secrets).</summary>
        private VaultGate OpenGate(string dataDir, Func<DateTime> clock)
        {
            if (options.InMemorySecrets)
            {
                Log.Warn("secrets", "DEBUG : --in-memory-secrets, aucun coffre ouvert, secrets lus depuis IRIS_SECRET_<NAME> / IRIS_SECRET_<NAME>_HOSTS");
                InMemorySecretStore memory = new InMemorySecretStore();
                int n = EnvSecrets.LoadInto(memory, Environment.GetEnvironmentVariables(), clock());
                Log.Info("secrets", n + " secret(s) chargé(s) depuis l'environnement");
                if (options.InMemoryCa) Log.Warn("ca", "DEBUG : --in-memory-ca, CA régénéré à chaque démarrage, jamais persisté");
                else Log.Warn("ca", "--in-memory-secrets sans coffre ouvert : le CA est aussi éphémère (équivalent à --in-memory-ca)");
                return VaultGate.InMemory(dataDir, memory, clock);
            }
            bool memoryCa = options.InMemoryCa;
            if (memoryCa) Log.Warn("ca", "DEBUG : --in-memory-ca, CA régénéré à chaque démarrage, jamais persisté");
            return new VaultGate(dataDir, delegate(KeePassVault v)
            {
                return memoryCa ? (ICAKeyStore)new InMemoryCAKeyStore() : new KeePassCAKeyStore(v);
            }, clock);
        }

        private static string StateLabel(VaultState state)
        {
            switch (state)
            {
                case VaultState.Absent: return "absent";
                case VaultState.Locked: return "verrouillé";
                default: return "ouvert";
            }
        }
    }
}
