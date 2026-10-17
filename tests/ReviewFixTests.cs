using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>Coffre dont les lectures échouent (coffre illisible) : chemin d'erreur du proxy.</summary>
    internal sealed class FailingSecretStore : ISecretStore
    {
        private readonly ISecretStore inner;
        public FailingSecretStore(ISecretStore inner) { this.inner = inner; }

        private static Task<T> Fail<T>()
        {
            TaskCompletionSource<T> tcs = new TaskCompletionSource<T>();
            tcs.SetException(new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "coffre illisible (test)"));
            return tcs.Task;
        }

        public Task<Secret> AddAsync(string name, byte[] value, IList<string> allowedHosts, DateTime createdAt) { return inner.AddAsync(name, value, allowedHosts, createdAt); }
        public Task<Secret> UpdateAsync(string name, IList<string> allowedHosts) { return inner.UpdateAsync(name, allowedHosts); }
        public Task<Secret> RotateAsync(string name, byte[] newValue) { return inner.RotateAsync(name, newValue); }
        public Task DeleteAsync(string name) { return inner.DeleteAsync(name); }
        public Task<byte[]> ValueAsync(string name) { return Fail<byte[]>(); }
        public Task<Secret> SecretAsync(string name) { return Fail<Secret>(); }
        public Task<IList<Secret>> ListAsync() { return inner.ListAsync(); }
        public Task<Secret> RecordUsageAsync(string name, DateTime at) { return inner.RecordUsageAsync(name, at); }
        public Task<Secret> SetQuarantinedAsync(string name, bool quarantined) { return inner.SetQuarantinedAsync(name, quarantined); }
    }

    public static partial class TestMain
    {
        // ---- Passe de correction après la revue de la phase 2 -------------------------

        /// <summary>Revue 1 : un tunnel ne doit pas être coupé parce qu'une seule direction est silencieuse (long téléchargement).</summary>
        private static void Fix_TunnelLongDownload_SurvivesClientSilence()
        {
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                MockUpstream.StreamingPlan plan = new MockUpstream.StreamingPlan();
                plan.FirstChunk = Bytes("part0");
                for (int i = 1; i <= 6; i++) plan.RemainingChunks.Add(Bytes("part" + i));
                plan.ChunkDelay = TimeSpan.FromMilliseconds(150);
                plan.ReleaseRest.SetResult(true);
                mock.Streaming = plan;
                ProxyOptions o = TestOptions(); // localhost hors whitelist → tunnel
                o.IdleTimeout = TimeSpan.FromMilliseconds(300);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", mock.Port)), "tunnel ouvert");
                        Wait(c.StartTlsAsync("localhost", mock.CACertificate));
                        Wait(c.SendAsync("GET", "/big", H("Host", "localhost"), null));
                        HttpResponseHead head = Wait(c.ReadResponseHeadAsync());
                        Check.Eq(200, head.Status, "réponse streamée");
                        StringBuilder all = new StringBuilder();
                        byte[] chunk;
                        while ((chunk = Wait(c.ReadChunkAsync())) != null) all.Append(Encoding.UTF8.GetString(chunk));
                        Check.Eq("part0part1part2part3part4part5part6", all.ToString(), "téléchargement de 900 ms reçu en entier malgré 300 ms d'inactivité côté client");
                    }
                    Check.True(WaitEvent(p, EventKind.PassThrough, 1) != null, "event passThrough à la fermeture");
                    Wait(p.StopAsync());
                }
            }
        }

        /// <summary>Revue 2 : une connexion déchiffrée inactive sans requête n'est pas un refus du CA.</summary>
        private static void Fix_IdleDecryptedConnection_NoErrorEvent()
        {
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost");
                o.IdleTimeout = TimeSpan.FromMilliseconds(300);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", 443)), "CONNECT accepté");
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        byte[] buf = new byte[8];
                        int n;
                        try { n = Wait(c.Http.ReadAsync(buf, 0, 8, CancellationToken.None)); } catch (IOException) { n = 0; }
                        Check.Eq(0, n, "connexion déchiffrée inactive fermée après le délai");
                        Check.True(WaitEvent(p, EventKind.Error, 1) == null, "aucun event error : inactivité ≠ refus du CA");
                    }
                    Wait(p.StopAsync());
                }
            }
        }

        /// <summary>Revue 3 : une erreur du coffre pendant le traitement donne un 502, un event error et un warn, pas une coupure muette.</summary>
        private static void Fix_SecretStoreError_502AndErrorEvent()
        {
            StringWriter log = new StringWriter();
            Log.Reset(); Log.Writer = log;
            try
            {
                using (MockUpstream mock = MockUpstream.Start("localhost"))
                using (CAManager ca = FreshCA())
                {
                    ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                    using (ProxyServer p = NewProxy(o, new FailingSecretStore(new InMemorySecretStore()), ca))
                    {
                        int port = p.Start().Port;
                        ProxyClientResponse r = Wait(TestProxyClient.RequestAsync(port, "localhost", mock.Port, ca.Certificate, "GET", "/v1", H("Host", "localhost", "x-api-key", "{{kc:k}}"), null));
                        Check.Eq(502, r.Status, "coffre en erreur → 502 au client, pas une coupure");
                        Check.True(r.Text.Contains("coffre"), "corps texte court");
                        Event e = WaitEvent(p, EventKind.Error, 1);
                        Check.True(e != null && e.Host == "localhost" && e.Path == "/v1" && e.StatusCode == 502, "event error avec le chemin et 502");
                        string text = log.ToString();
                        Check.True(text.Contains("WARN") && text.Contains("coffre"), "warn dans le log");
                        Check.Eq(0, mock.Received.Count, "rien n'est parti vers l'amont");
                        Wait(p.StopAsync());
                    }
                }
            }
            finally { Log.Reset(); }
        }

        /// <summary>Revue 4 : une valeur contenant CR, LF ou NUL n'est jamais substituée (pas d'injection d'en-tête ni de request splitting).</summary>
        private static void Fix_Engine_CrLfValueNeverSubstituted()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync("inj", Bytes("abc\r\nX-Injected: 1"), new[] { "example.com" }, T0));
            Wait(store.AddAsync("nul", Bytes("a\0b"), new[] { "example.com" }, T0));
            Wait(store.AddAsync("ok", Bytes("fine"), new[] { "example.com" }, T0));
            PlaceholderEngine engine = new PlaceholderEngine(store);
            HttpHeaders h = H("x-api-key", "{{kc:inj}}", "x-other", "{{kc:nul}}", "x-ok", "{{kc:ok}}");
            List<PlaceholderHit> hits = new List<PlaceholderHit> { Hit("inj", HitLocation.Header("x-api-key")), Hit("nul", HitLocation.Header("x-other")), Hit("ok", HitLocation.Header("x-ok")), Hit("inj", HitLocation.Body) };
            ResolvedPayload r = Wait(engine.SubstituteAsync(h, "/", Bytes("{{kc:inj}}"), hits));
            Check.Eq("{{kc:inj}}", r.Headers.First("x-api-key"), "valeur avec CR/LF : placeholder laissé tel quel");
            Check.Eq("{{kc:nul}}", r.Headers.First("x-other"), "valeur avec octet nul : laissée");
            Check.Eq("fine", r.Headers.First("x-ok"), "les autres valeurs sont substituées");
            Check.Eq("{{kc:inj}}", Encoding.UTF8.GetString(r.Body), "jamais substituée, même dans le corps");
            Check.Eq("inj,nul", string.Join(",", r.Unresolved), "signalées non résolues");
            Check.Eq("ok", string.Join(",", r.Substituted), "substituées");
            string wire = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpRequestHead("GET", r.Uri, "HTTP/1.1", r.Headers)));
            Check.True(wire.IndexOf("X-Injected", StringComparison.Ordinal) < 0, "rien d'injecté sur le fil");
        }

        /// <summary>Revue 5 : une valeur non ASCII part octet pour octet (UTF-8) dans les en-têtes et l'URI, modélisés en Latin-1.</summary>
        private static void Fix_Engine_NonAsciiValueKeepsUtf8BytesInHeaders()
        {
            InMemorySecretStore store = new InMemorySecretStore();
            Wait(store.AddAsync("acc", Bytes("clé€"), new[] { "example.com" }, T0));
            PlaceholderEngine engine = new PlaceholderEngine(store);
            HttpHeaders h = H("x-api-key", "{{kc:acc}}");
            List<PlaceholderHit> hits = new List<PlaceholderHit> { Hit("acc", HitLocation.Header("x-api-key")), Hit("acc", HitLocation.UrlPath), Hit("acc", HitLocation.Body) };
            ResolvedPayload r = Wait(engine.SubstituteAsync(h, "/p/{{kc:acc}}", Bytes("{\"k\":\"{{kc:acc}}\"}"), hits));
            string expectedLatin1 = HttpParser.Latin1.GetString(Bytes("clé€"));
            string wire = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpRequestHead("GET", r.Uri, "HTTP/1.1", r.Headers)));
            Check.True(wire.Contains("x-api-key: " + expectedLatin1 + "\r\n"), "en-tête : les octets UTF-8 de la valeur partent tels quels");
            Check.True(wire.StartsWith("GET /p/" + expectedLatin1 + " HTTP/1.1"), "URI : idem");
            Check.True(wire.IndexOf('?') < 0, "aucun caractère remplacé par ?");
            Check.Eq("{\"k\":\"clé€\"}", Encoding.UTF8.GetString(r.Body), "corps : UTF-8 valide");
        }

        /// <summary>Revue 6a : Transfer-Encoding dont chunked n'est pas le codage final (RFC 7230 §3.3.3).</summary>
        private static void Fix_Http_TransferEncodingNonChunkedRejected()
        {
            HttpProtocolException ex = Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Transfer-Encoding: chunked, identity")); }, "chunked non final (requête)");
            Check.Eq(400, ex.Status, "400");
            Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Transfer-Encoding: gzip")); }, "codage non chunked (requête)");
            Check.Eq(BodyFramingKind.Chunked, HttpParser.RequestFraming(HeadersOf("Transfer-Encoding: gzip, Chunked", "Content-Length: 5")).Kind, "chunked final, insensible à la casse, prime sur Content-Length");
            Check.Eq(BodyFramingKind.UntilClose, HttpParser.ResponseFraming(HeadersOf("Transfer-Encoding: gzip", "Content-Length: 5"), "GET", 200).Kind, "réponse non chunked-final : jusqu'à la fermeture");
            ex = Check.Throws<HttpProtocolException>(delegate { HttpParser.ResponseFraming(HeadersOf("Transfer-Encoding: chunked, gzip"), "GET", 200); }, "chunked non final (réponse)");
            Check.Eq(502, ex.Status, "502");
        }

        /// <summary>Revue 6b : un corps chunked trop grand pour être bufferisé repart en chunked sans le Content-Length d'origine.</summary>
        private static void Fix_MITM_LargeChunkedBody_DropsContentLength()
        {
            using (MockUpstream mock = MockUpstream.Start("localhost"))
            using (CAManager ca = FreshCA())
            {
                ProxyOptions o = TestOptions("localhost"); o.UpstreamTrust = new PinnedRootTrust(mock.CACertificate);
                using (ProxyServer p = NewProxy(o, new InMemorySecretStore(), ca))
                {
                    int port = p.Start().Port;
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(port)))
                    {
                        Wait(c.ConnectTunnelAsync("localhost", mock.Port));
                        Wait(c.StartTlsAsync("localhost", ca.Certificate));
                        Wait(c.SendAsync("POST", "/upload", H("Host", "localhost", "Transfer-Encoding", "chunked", "Content-Length", "5"), null));
                        byte[] block = new byte[64 * 1024];
                        for (int i = 0; i < block.Length; i++) block[i] = (byte)('a' + (i % 26));
                        int total = 0;
                        while (total <= HttpParser.MaxBufferedBody)
                        {
                            Wait(HttpParser.WriteChunkAsync(c.Http, block, 0, block.Length, CancellationToken.None));
                            total += block.Length;
                        }
                        Wait(HttpParser.WriteLastChunkAsync(c.Http, CancellationToken.None));
                        Wait(c.Http.FlushAsync(CancellationToken.None));
                        ProxyClientResponse r = Wait(c.ReadResponseAsync());
                        Check.Eq(200, r.Status, "réponse");
                        MockUpstream.ReceivedRequest got = Wait(mock.WaitForRequestAsync(MockWait));
                        Check.Eq(total, got.Body.Length, "corps relayé en entier");
                        Check.True(got.Head.Headers.First("Content-Length") == null, "Content-Length retiré quand le corps repart en chunked");
                        Check.Eq("chunked", got.Head.Headers.First("Transfer-Encoding"), "Transfer-Encoding chunked conservé");
                    }
                    Wait(p.StopAsync());
                }
            }
        }
    }
}
