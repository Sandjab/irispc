using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public sealed class ProxyClientResponse
    {
        public int Status;
        public HttpHeaders Headers;
        public byte[] Body;
        public string Text { get { return Encoding.UTF8.GetString(Body ?? new byte[0]); } }
    }

    /// <summary>Client HTTP/1.1 manuel à travers le proxy (cf. ../Iris/Tests/IntegrationTests/TestProxyClient.swift) : TCP → CONNECT → TLS → requêtes.</summary>
    public sealed class TestProxyClient : IDisposable
    {
        private TcpClient tcp;
        private HttpConnection plain;
        private SslStream tls;
        public HttpConnection Http { get; private set; }

        public static async Task<TestProxyClient> ConnectAsync(int proxyPort)
        {
            TestProxyClient c = new TestProxyClient();
            c.tcp = new TcpClient();
            await c.tcp.ConnectAsync("127.0.0.1", proxyPort);
            c.plain = new HttpConnection(c.tcp.GetStream());
            c.plain.ReadTimeout = TimeSpan.FromSeconds(10);
            c.Http = c.plain;
            return c;
        }

        /// <summary>Envoie CONNECT host:port et rend le statut de la réponse du proxy.</summary>
        public async Task<int> ConnectTunnelAsync(string host, int port)
        {
            byte[] req = HttpParser.Latin1.GetBytes("CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\n\r\n");
            await plain.WriteAsync(req, 0, req.Length, CancellationToken.None);
            await plain.FlushAsync(CancellationToken.None);
            HttpResponseHead head = await HttpParser.ReadResponseHeadAsync(plain, CancellationToken.None);
            if (head == null) throw new IOException("le proxy a fermé la connexion sans répondre au CONNECT");
            if (head.Status != 200)
            {
                BufferedBody body = await HttpParser.ReadBodyAsync(plain, HttpParser.ResponseFraming(head.Headers, "CONNECT", head.Status), 65536, CancellationToken.None);
                LastErrorBody = HttpParser.Latin1.GetString(body.Bytes);
            }
            return head.Status;
        }

        public string LastErrorBody { get; private set; }

        /// <summary>TLS dans le tunnel, en ne faisant confiance qu'à `root` (le CA du proxy pour le MITM, celui du mock pour un tunnel brut).</summary>
        public async Task StartTlsAsync(string host, X509Certificate2 root)
        {
            Stream inner = new PrefixedStream(plain.TakeBuffered(), tcp.GetStream());
            tls = new SslStream(inner, false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(root)));
            await tls.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false);
            Http = new HttpConnection(tls);
            Http.ReadTimeout = TimeSpan.FromSeconds(10);
        }

        public async Task SendAsync(string method, string path, HttpHeaders headers, byte[] body)
        {
            HttpHeaders h = headers == null ? new HttpHeaders() : headers.Clone();
            if (body != null && !h.Contains("Content-Length") && !h.Contains("Transfer-Encoding")) h.Add("Content-Length", body.Length.ToString());
            await HttpParser.WriteAsync(Http, new HttpRequestHead(method, path, "HTTP/1.1", h), CancellationToken.None);
            if (body != null) await Http.WriteAsync(body, 0, body.Length, CancellationToken.None);
            await Http.FlushAsync(CancellationToken.None);
        }

        public Task<HttpResponseHead> ReadResponseHeadAsync() { return HttpParser.ReadResponseHeadAsync(Http, CancellationToken.None); }

        public async Task<ProxyClientResponse> ReadResponseAsync()
        {
            HttpResponseHead head = await ReadResponseHeadAsync();
            if (head == null) throw new IOException("connexion fermée avant la réponse");
            BufferedBody body = await HttpParser.ReadBodyAsync(Http, HttpParser.ResponseFraming(head.Headers, "GET", head.Status), 64 * 1024 * 1024, CancellationToken.None);
            ProxyClientResponse r = new ProxyClientResponse();
            r.Status = head.Status; r.Headers = head.Headers; r.Body = body.Bytes;
            return r;
        }

        /// <summary>Un chunk d'une réponse chunked ; null au dernier chunk (trailers consommés) ou si le pair ferme.</summary>
        public async Task<byte[]> ReadChunkAsync()
        {
            string line = await Http.ReadLineAsync(1024, CancellationToken.None);
            if (line == null) return null;
            int size = Convert.ToInt32(line.Split(';')[0].Trim(), 16);
            if (size == 0)
            {
                while (true) { string t = await Http.ReadLineAsync(65536, CancellationToken.None); if (t == null || t.Length == 0) break; }
                return null;
            }
            byte[] data = new byte[size];
            await Http.ReadExactAsync(data, 0, size, CancellationToken.None);
            await Http.ReadLineAsync(16, CancellationToken.None);
            return data;
        }

        public void Dispose()
        {
            if (tls != null) { try { tls.Dispose(); } catch (IOException) { } }
            if (tcp != null) tcp.Close();
        }

        /// <summary>CONNECT + TLS (racine `root`) + une requête ; lève si le CONNECT n'est pas accepté.</summary>
        public static async Task<ProxyClientResponse> RequestAsync(int proxyPort, string host, int port, X509Certificate2 root, string method, string path, HttpHeaders headers, byte[] body)
        {
            using (TestProxyClient c = await ConnectAsync(proxyPort))
            {
                int status = await c.ConnectTunnelAsync(host, port);
                if (status != 200) throw new InvalidOperationException("CONNECT refusé : " + status + " " + c.LastErrorBody);
                await c.StartTlsAsync(host, root);
                await c.SendAsync(method, path, headers, body);
                return await c.ReadResponseAsync();
            }
        }

        /// <summary>Envoie des octets bruts au proxy et rend tout ce qu'il répond jusqu'à la fermeture (ping, 405, 400).</summary>
        public static async Task<string> RawAsync(int proxyPort, string request)
        {
            using (TcpClient tcp = new TcpClient())
            {
                await tcp.ConnectAsync("127.0.0.1", proxyPort);
                NetworkStream s = tcp.GetStream();
                byte[] bytes = HttpParser.Latin1.GetBytes(request);
                await s.WriteAsync(bytes, 0, bytes.Length);
                MemoryStream all = new MemoryStream();
                byte[] buf = new byte[4096];
                Task<int> read;
                while (true)
                {
                    read = s.ReadAsync(buf, 0, buf.Length);
                    if (await Task.WhenAny(read, Task.Delay(5000)) != read) throw new TimeoutException("le proxy n'a pas fermé la connexion");
                    int n = await read;
                    if (n == 0) break;
                    all.Write(buf, 0, n);
                }
                return HttpParser.Latin1.GetString(all.ToArray());
            }
        }
    }
}
