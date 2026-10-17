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
                        Check.Eq("15", got.Head.Headers.First("Content-Length"), "Content-Length normalisé");
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
