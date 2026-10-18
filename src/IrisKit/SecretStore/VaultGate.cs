using System;
using System.IO;
using System.Security;

namespace IrisKit
{
    public enum VaultState { Absent, Locked, Unlocked }

    public static class VaultStateWire
    {
        public static string ToWire(VaultState state)
        {
            switch (state)
            {
                case VaultState.Absent: return "absent";
                case VaultState.Locked: return "locked";
                default: return "unlocked";
            }
        }
    }

    public enum VaultGateErrorKind { BadPassword, RateLimited, Exists, Absent }

    /// <summary>Refus de la porte du coffre (spec phase 3 §6) ; message en français, jamais le mot de passe.</summary>
    public sealed class VaultGateException : Exception
    {
        public VaultGateErrorKind Kind { get; private set; }
        public TimeSpan RetryAfter { get; private set; }

        public VaultGateException(VaultGateErrorKind kind, string message, TimeSpan retryAfter) : base(message)
        {
            Kind = kind;
            RetryAfter = retryAfter;
        }
    }

    /// <summary>
    /// Porte du coffre (spec phase 3 §3, §6) : état Absent / Locked / Unlocked. L'ouverture (console ou pipe) charge coffre,
    /// métadonnées, cache et CA, publie le tout d'un coup puis lève Opened. Une ouverture à la fois ; après le n-ième échec,
    /// toute tentative est refusée pendant min(2^(n-1), 60) s sans examiner le mot de passe. Pas de reverrouillage.
    /// </summary>
    public sealed class VaultGate : IDisposable
    {
        public const int MaxDelaySeconds = 60;

        private readonly object gate = new object();
        private readonly object delayGate = new object();
        private readonly string dataDir;
        private readonly string pemPath;
        private readonly Func<KeePassVault, ICAKeyStore> caStoreFor;
        private readonly Func<DateTime> clock;
        private VaultSession session;
        private SecretsMetaStore meta;
        private SecretCache secrets;
        private CAManager ca;
        private volatile bool unlocked;
        private bool inMemory;
        private int failures;
        private DateTime notBefore = DateTime.MinValue;
        private int maxBackups = 10;

        /// <summary>Levé (hors verrou) après chaque ouverture réussie ; un abonné qui lève est journalisé.</summary>
        public event Action Opened;

        public VaultGate(string dataDir, Func<KeePassVault, ICAKeyStore> caStoreFor, Func<DateTime> clock)
        {
            this.dataDir = dataDir;
            this.pemPath = Path.Combine(dataDir, "ca.pem");
            this.caStoreFor = caStoreFor;
            this.clock = clock;
            session = new VaultSession(dataDir);
        }

        /// <summary>Mode `--in-memory-secrets` : porte ouverte d'emblée, secrets en mémoire, CA éphémère (jamais persisté).</summary>
        public static VaultGate InMemory(string dataDir, ISecretStore store, Func<DateTime> clock)
        {
            VaultGate g = new VaultGate(dataDir, null, clock);
            g.inMemory = true;
            g.session = null;
            g.secrets = new SecretCache(store);
            g.ca = new CAManager(new InMemoryCAKeyStore(), g.pemPath, clock);
            g.ca.EnsureCA();
            g.unlocked = true;
            return g;
        }

        public VaultState State
        {
            get
            {
                if (unlocked || inMemory) return VaultState.Unlocked;
                return File.Exists(session.KdbxPath) ? VaultState.Locked : VaultState.Absent;
            }
        }

        public string KdbxPath { get { return inMemory ? null : session.KdbxPath; } }
        public string PemPath { get { return pemPath; } }
        public ISecretStore Secrets { get { return unlocked ? secrets : null; } }
        public CAManager CA { get { return unlocked ? ca : null; } }

        public int MaxBackups
        {
            get { return maxBackups; }
            set
            {
                maxBackups = value;
                KeePassVault v = session == null ? null : session.Vault;
                if (v != null) v.MaxBackups = value;
            }
        }

        /// <summary>Temps restant avant qu'une tentative soit examinée (zéro si aucune attente).</summary>
        public TimeSpan RetryAfter
        {
            get
            {
                lock (delayGate)
                {
                    TimeSpan left = notBefore - clock();
                    return left > TimeSpan.Zero ? left : TimeSpan.Zero;
                }
            }
        }

        /// <summary>Délai imposé après `failures` échecs consécutifs : 1, 2, 4… secondes, plafonné à 60.</summary>
        public static TimeSpan DelayAfter(int failures)
        {
            if (failures <= 0) return TimeSpan.Zero;
            if (failures > 7) return TimeSpan.FromSeconds(MaxDelaySeconds);
            return TimeSpan.FromSeconds(Math.Min(Math.Pow(2, failures - 1), MaxDelaySeconds));
        }

        /// <summary>Déverrouille ; déjà ouvert → retour immédiat sans examen (pas d'oracle). Absent, BadPassword, RateLimited → VaultGateException.</summary>
        public void Unlock(SecureString password)
        {
            lock (gate)
            {
                if (unlocked || inMemory) return;
                if (!session.Exists)
                    throw new VaultGateException(VaultGateErrorKind.Absent, "aucun coffre dans " + session.KdbxPath + " : créez-le d'abord", TimeSpan.Zero);
                CheckDelay();
                try { session.Unlock(password); }
                catch (SecretStoreException ex)
                {
                    if (ex.Kind != SecretStoreErrorKind.VaultLocked) throw;
                    TimeSpan delay = RecordFailure();
                    throw new VaultGateException(VaultGateErrorKind.BadPassword,
                        "mot de passe maître refusé ; nouvel essai possible dans " + (int)Math.Ceiling(delay.TotalSeconds) + " s", delay);
                }
                OpenServices();
                lock (delayGate) { failures = 0; notBefore = DateTime.MinValue; }
            }
            RaiseOpened();
        }

        /// <summary>Crée le coffre (seulement s'il n'existe pas) puis l'ouvre.</summary>
        public void Create(SecureString password)
        {
            lock (gate)
            {
                if (unlocked || inMemory)
                    throw new VaultGateException(VaultGateErrorKind.Exists, "le coffre est déjà ouvert", TimeSpan.Zero);
                if (session.Exists)
                    throw new VaultGateException(VaultGateErrorKind.Exists, "le coffre existe déjà : " + session.KdbxPath, TimeSpan.Zero);
                session.Create(password, clock());
                OpenServices();
            }
            RaiseOpened();
        }

        private void CheckDelay()
        {
            lock (delayGate)
            {
                TimeSpan left = notBefore - clock();
                if (left > TimeSpan.Zero)
                    throw new VaultGateException(VaultGateErrorKind.RateLimited,
                        "trop d'essais : nouvel essai possible dans " + (int)Math.Ceiling(left.TotalSeconds) + " s", left);
            }
        }

        private TimeSpan RecordFailure()
        {
            lock (delayGate)
            {
                failures++;
                TimeSpan delay = DelayAfter(failures);
                notBefore = clock() + delay;
                return delay;
            }
        }

        /// <summary>Sous le verrou : métadonnées, magasin, cache, CA ; en cas d'échec tout est libéré et le coffre refermé.</summary>
        private void OpenServices()
        {
            KeePassVault vault = session.Vault;
            vault.MaxBackups = maxBackups;
            vault.Clock = clock;
            SecretsMetaStore m = null;
            CAManager c = null;
            try
            {
                m = new SecretsMetaStore(Path.Combine(dataDir, "secrets-meta.json"), vault.SecretNames, SecretsMetaStore.DefaultDebounce, clock);
                SecretCache cache = new SecretCache(new KeePassSecretStore(vault, m));
                c = new CAManager(caStoreFor(vault), pemPath, clock);
                c.EnsureCA();
                meta = m;
                secrets = cache;
                ca = c;
                unlocked = true;
                Log.Info("vault", "coffre déverrouillé, MITM actif : " + session.KdbxPath + ", " + vault.SecretNames().Count + " secret(s)");
            }
            catch
            {
                if (c != null) c.Dispose();
                if (m != null) m.Dispose();
                session.Dispose();
                throw;
            }
        }

        private void RaiseOpened()
        {
            Action handler = Opened;
            if (handler == null) return;
            try { handler(); }
            catch (Exception ex) { Log.Error("vault", "abonné à l'ouverture du coffre en échec : " + ex.GetType().Name + " : " + ex.Message); }
        }

        public void Dispose()
        {
            lock (gate)
            {
                unlocked = false;
                if (secrets != null) { secrets.Clear(); secrets = null; }
                if (meta != null) { meta.Dispose(); meta = null; }
                if (ca != null) { ca.Dispose(); ca = null; }
                if (session != null) session.Dispose();
            }
        }
    }
}
