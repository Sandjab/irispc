using System;

namespace IrisKit
{
    /// <summary>État vivant du daemon vu par le dispatcher : pid, démarrage, version, pause. Faux en test.</summary>
    public interface IDaemonControl
    {
        int ProcessId { get; }
        DateTime StartedAt { get; }
        string Version { get; }
        bool IsPaused { get; }
        void SetPaused(bool paused);
    }

    /// <summary>Collaborateurs du dispatcher admin (spec phase 3 §5–§7). `OnConfigChanged` applique la config à chaud après chaque mutation réussie.</summary>
    public sealed class AdminContext
    {
        public ConfigStore Config;
        public VaultGate Vault;
        public EventPipeline Events;
        public IDaemonControl Daemon;
        public Func<DateTime> Clock;
        public Action<Config> OnConfigChanged;
        /// <summary>Empreinte SHA-1 (`X509Certificate2.Thumbprint`) → présente dans CurrentUser\Root.</summary>
        public Func<string, bool> IsCATrusted;
    }
}
