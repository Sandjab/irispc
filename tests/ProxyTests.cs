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
