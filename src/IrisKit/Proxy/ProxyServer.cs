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
        public EventPipeline Events { get; private set; }
        public UpstreamClient Upstream { get; private set; }
        public Func<DateTime> Clock { get; private set; }
        /// <summary>Feuilles par hôte ; null tant que le coffre est fermé.</summary>
        public LeafCertCache Leaves { get { return leaves; } }
        /// <summary>Magasin de secrets ; null tant que le coffre est fermé.</summary>
        public ISecretStore Secrets { get { return secrets; } }
        /// <summary>Scan → règles → substitution ; null tant que le coffre est fermé.</summary>
        public RequestProcessor Processor { get { return processor; } }
        /// <summary>Coffre et CA branchés : le MITM est possible (spec phase 3 §3).</summary>
        public bool VaultActive { get { return processor != null; } }

        private readonly object gate = new object();
        private readonly HashSet<ClientConnection> connections = new HashSet<ClientConnection>();
        private readonly List<Task> tasks = new List<Task>();
        private HashSet<string> allowed;
        private volatile bool paused;
        private TcpListener listener;
        private CancellationTokenSource stopping;
        private Task acceptLoop;
        private volatile LeafCertCache leaves;
        private volatile ISecretStore secrets;
        private volatile RequestProcessor processor;
        private int lockedRefusals;

        /// <summary>Proxy verrouillé (spec phase 3 §3) : tunnel pour tout hôte hors whitelist, 503 pour la whitelist jusqu'à Activate.</summary>
        public ProxyServer(ProxyOptions options, EventPipeline events, Func<DateTime> clock)
        {
            if (options == null) throw new ArgumentNullException("options");
            if (events == null) throw new ArgumentNullException("events");
            Options = options;
            Events = events;
            Clock = clock;
            Upstream = new UpstreamClient(options.UpstreamTrust, options.ConnectTimeout);
            allowed = new HashSet<string>(StringComparer.Ordinal);
            foreach (string h in options.AllowedHosts) allowed.Add(HostName.Normalize(h));
        }

        /// <summary>Proxy actif d'emblée (tests, phase 2).</summary>
        public ProxyServer(ProxyOptions options, ISecretStore secrets, CAManager ca, EventPipeline events, Func<DateTime> clock)
            : this(options, events, clock)
        {
            if (secrets == null) throw new ArgumentNullException("secrets");
            if (ca == null) throw new ArgumentNullException("ca");
            Activate(secrets, ca);
        }

        /// <summary>Branche coffre et CA (au démarrage ou au déverrouillage) ; idempotent ; vaut pour toute nouvelle connexion.</summary>
        public void Activate(ISecretStore secretStore, CAManager ca)
        {
            if (secretStore == null) throw new ArgumentNullException("secretStore");
            if (ca == null) throw new ArgumentNullException("ca");
            lock (gate)
            {
                if (processor != null) return;
                ProxyServer self = this;
                LeafCertCache l = new LeafCertCache(ca, Clock);
                RequestProcessor p = new RequestProcessor(secretStore,
                    delegate { return self.Options.Security.MaxSubstitutionsPerMinute; },
                    delegate { return self.Options.Security.OnExfilAttempt; },
                    delegate { self.SetPaused(true); },
                    Clock);
                secrets = secretStore;
                leaves = l;
                processor = p; // en dernier : VaultActive ne passe à vrai qu'une fois tout prêt
            }
        }

        /// <summary>`security.*` à chaud (spec phase 3 §7) : validée, puis lue par RequestProcessor à la requête suivante.</summary>
        public void UpdateSecurity(SecurityConfig security)
        {
            if (security == null) throw new ArgumentNullException("security");
            security.Validate();
            Options.Security = security;
            Log.Info("proxy", "sécurité mise à jour : on_exfil_attempt=" + ExfilPolicyWire.ToWire(security.OnExfilAttempt)
                + ", max_substitutions_per_minute=" + security.MaxSubstitutionsPerMinute);
        }

        /// <summary>Vrai au premier refus « coffre verrouillé » (log warn), faux ensuite (log debug).</summary>
        public bool NoteLockedRefusal() { return Interlocked.Increment(ref lockedRefusals) == 1; }

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
            PortBinding.Start(l, 64, "proxy", Options.ListenPort);
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
            LeafCertCache l = leaves;
            if (l != null) l.Dispose();
            Log.Info("proxy", "arrêté");
        }

        public void Dispose()
        {
            if (listener != null) { StopAsync().GetAwaiter().GetResult(); return; }
            LeafCertCache l = leaves;
            if (l != null) l.Dispose();
        }
    }
}
