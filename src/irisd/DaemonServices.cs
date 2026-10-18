using System;
using System.Diagnostics;
using System.IO;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Proxy, flux SSE et pipe admin d'un daemon (spec phase 3 §9), câblés sur la porte du coffre (activation du MITM à l'ouverture)
    /// et sur la config (application à chaud après chaque mutation RPC). Arrêt dans l'ordre pipe → SSE → proxy.
    /// </summary>
    internal sealed class DaemonServices : IDisposable
    {
        private readonly ConfigStore config;
        private readonly VaultGate vault;
        private readonly EventPipeline events;
        private readonly Func<DateTime> clock;

        public ProxyServer Proxy { get; private set; }
        public EventsServer Sse { get; private set; }
        public AdminServer Admin { get; private set; }

        public DaemonServices(ConfigStore config, VaultGate vault, EventPipeline events, Func<DateTime> clock)
        {
            this.config = config;
            this.vault = vault;
            this.events = events;
            this.clock = clock;
        }

        /// <summary>Démarre les trois services ; rend ExitCodes.Ok ou le code de sortie avec un message sur stderr.</summary>
        public int Start(TextWriter stderr)
        {
            Proxy = new ProxyServer(ProxyOptions.FromConfig(config.Current), events, clock);
            vault.Opened += Activate;
            Activate(); // porte déjà ouverte (--in-memory-secrets) ; idempotent
            try { Proxy.Start(); }
            catch (PortBindException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Port; }
            catch (ProxyException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Data; }

            Sse = new EventsServer(config.Current.Broker.EventsListen, events);
            try { Sse.Start(); }
            catch (PortBindException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Port; }
            catch (ProxyException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Data; }

            AdminContext ctx = new AdminContext();
            ctx.Config = config;
            ctx.Vault = vault;
            ctx.Events = events;
            ctx.Daemon = new DaemonControl(Proxy, clock());
            ctx.Clock = clock;
            ctx.OnConfigChanged = ApplyConfig;
            ctx.IsCATrusted = CATrust.IsInCurrentUserRoot;
            AdminDispatcher dispatcher = new AdminDispatcher(ctx);
            Admin = new AdminServer(config.Current.Broker.AdminPipe, dispatcher.HandleAsync);
            try { Admin.Start(); }
            catch (AdminPipeInUseException ex) { stderr.WriteLine("irisd : " + ex.Message); return ExitCodes.Port; }
            catch (IOException ex) { stderr.WriteLine("irisd : pipe admin : " + ex.Message); return ExitCodes.Data; }
            return ExitCodes.Ok;
        }

        private void Activate()
        {
            if (vault.State == VaultState.Unlocked) Proxy.Activate(vault.Secrets, vault.CA);
        }

        /// <summary>Après rule.*, config.set, config.reload : sécurité, whitelist et rotation des backups du coffre, sans redémarrage.</summary>
        private void ApplyConfig(Config c)
        {
            Proxy.UpdateSecurity(c.Security);
            Proxy.UpdateRules(c.Hosts);
            vault.MaxBackups = c.Backups.MaxCount;
        }

        public void Dispose()
        {
            vault.Opened -= Activate;
            if (Admin != null) Admin.Dispose();
            if (Sse != null) Sse.Dispose();
            if (Proxy != null) Proxy.Dispose();
        }
    }

    /// <summary>IDaemonControl du processus courant : pid, démarrage, version, pause du proxy.</summary>
    internal sealed class DaemonControl : IDaemonControl
    {
        private readonly ProxyServer proxy;
        private readonly DateTime startedAt;
        private readonly int processId;

        public DaemonControl(ProxyServer proxy, DateTime startedAt)
        {
            this.proxy = proxy;
            this.startedAt = startedAt;
            processId = Process.GetCurrentProcess().Id;
        }

        public int ProcessId { get { return processId; } }
        public DateTime StartedAt { get { return startedAt; } }
        public string Version { get { return IrisVersion.Value; } }
        public bool IsPaused { get { return proxy.Paused; } }
        public void SetPaused(bool paused) { proxy.SetPaused(paused); }
    }
}
