using System;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Proxy derrière la porte du coffre (spec phase 3 §3) ----------------------

        private static ProxyServer LockedProxy(ProxyOptions options)
        {
            EventPipeline events = new EventPipeline(new EventRing(1000), null, new EventsBus());
            return new ProxyServer(options, events, delegate { return DateTime.UtcNow; });
        }

        private static void ProxyGate_LockedRefusesWhitelistedTunnelsOthers()
        {
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log;
            try
            {
                using (MockUpstream mock = MockUpstream.Start("localhost"))
                using (ProxyServer p = LockedProxy(TestOptions("api.example.test")))
                {
                    Check.True(!p.VaultActive && p.Leaves == null && p.Processor == null && p.Secrets == null, "verrouillé : rien n'est branché");
                    int port = p.Start().Port;
                    for (int i = 0; i < 2; i++)
                        using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                        {
                            Check.Eq(503, Wait(c.ConnectTunnelAsync("api.example.test", 443)), "hôte whitelisté, coffre fermé → 503");
                            Check.True(c.LastErrorBody.Contains("coffre verrouillé"), "message explicite : " + c.LastErrorBody);
                        }
                    Event e = FirstEvent(p, EventKind.Error);
                    Check.True(e != null && e.StatusCode == 503 && e.Method == "CONNECT" && e.Path == "api.example.test:443" && e.Host == "api.example.test", "event error 503");
                    int warns = 0, from = 0;
                    string text = log.ToString();
                    while ((from = text.IndexOf("refusé (503)", from, StringComparison.Ordinal)) >= 0) { warns++; from++; }
                    Check.True(text.Contains("WARN") && warns >= 1, "warn au premier refus");
                    Check.True(p.NoteLockedRefusal() == false, "le premier refus est déjà noté");
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "hôte hors whitelist : tunnel même coffre fermé");
                        Wait(c.StartTlsAsync("localhost", mock.CACertificate));
                        Wait(c.SendAsync("GET", "/", H("Host", "localhost"), null));
                        Check.Eq(200, Wait(c.ReadResponseAsync()).Status, "réponse du mock à travers le tunnel");
                    }
                    Wait(p.StopAsync());
                }
            }
            finally { Log.Reset(); }
        }

        private static void ProxyGate_ActivateEnablesMITMWithoutRestart()
        {
            const string value = "sk-ant-gate-0001";
            InMemorySecretStore store = StoreFor("gate_key", value, "localhost");
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = LockedProxy(o))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                        Check.Eq(503, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "503 avant l'activation");
                    p.Activate(store, ca);
                    RequestProcessor first = p.Processor;
                    p.Activate(store, ca);
                    Check.True(p.VaultActive && ReferenceEquals(first, p.Processor), "activation idempotente");
                    ProxyClientResponse r = Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "GET", "/v1/models", H("Host", "localhost", "x-api-key", "{{kc:gate_key}}"), null));
                    Check.Eq(200, r.Status, "MITM actif sur le même port, sans redémarrage");
                    Check.Eq(value, Wait(mock.WaitForRequestAsync(MockWait)).Head.Headers.First("x-api-key"), "substitution après activation");
                    Wait(p.StopAsync());
                }
            }
        }

        private static void ProxyGate_UpdateSecurityHot()
        {
            InMemorySecretStore store = StoreFor("k", "valeur-k", "good.example");
            using (CAManager ca = FreshCA())
            using (ProxyServer p = NewProxy(TestOptions("good.example", "evil.example"), store, ca))
            {
                HttpRequestHead head = new HttpRequestHead("GET", "/", "HTTP/1.1", H("Host", "evil.example", "x-api-key", "{{kc:k}}"));
                ProcessedRequest r = Wait(p.Processor.ProcessAsync(head, null, false, "evil.example", false));
                Check.True(r.Outcome == RequestOutcome.Blocked && !p.Paused, "BlockOnly : bloqué, pas de pause");
                p.UpdateSecurity(new SecurityConfig(ExfilPolicy.BlockNotifyPause, 60));
                Check.Eq(ExfilPolicy.BlockNotifyPause, p.Options.Security.OnExfilAttempt, "nouvelle politique visible");
                r = Wait(p.Processor.ProcessAsync(head, null, false, "evil.example", false));
                Check.True(r.Outcome == RequestOutcome.Blocked && p.Paused, "block_notify_pause appliqué à chaud : pause");
                Check.Throws<ConfigException>(delegate { p.UpdateSecurity(new SecurityConfig(ExfilPolicy.BlockOnly, 0)); }, "valeur invalide refusée");
                Check.Eq(ExfilPolicy.BlockNotifyPause, p.Options.Security.OnExfilAttempt, "rien n'a changé");
            }
        }

        private static void PortBinding_Translate()
        {
            ProxyException inUse = PortBinding.Translate(new SocketException((int)SocketError.AddressAlreadyInUse), "proxy", 8888);
            Check.True(inUse is ProxyPortInUseException && ((PortBindException)inUse).Failure == PortBindFailure.InUse, "proxy : ProxyPortInUseException");
            PortBindException sse = (PortBindException)PortBinding.Translate(new SocketException((int)SocketError.AddressAlreadyInUse), "flux d'events", 8899);
            Check.True(sse.Failure == PortBindFailure.InUse && sse.Role == "flux d'events" && sse.Port == 8899 && sse.Message.Contains("déjà utilisé"), "SSE : InUse");
            PortBindException denied = (PortBindException)PortBinding.Translate(new SocketException((int)SocketError.AccessDenied), "proxy", 8888);
            Check.True(denied.Failure == PortBindFailure.AccessDenied && !(denied is ProxyPortInUseException), "AccessDenied n'est plus « déjà utilisé »");
            Check.True(denied.Message.Contains("accès refusé au port 8888") && !denied.Message.Contains("déjà utilisé"), "message dédié : " + denied.Message);
            ProxyException other = PortBinding.Translate(new SocketException((int)SocketError.NetworkDown), "proxy", 8888);
            Check.True(!(other is PortBindException), "autre erreur : ProxyException simple");
            Check.Eq("503 Service Unavailable", HttpParser.StatusLine(503), "statut 503");
            Check.Eq("404 Not Found", HttpParser.StatusLine(404), "statut 404");
        }
    }
}
