using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- HTTP/1.1 ---------------------------------------------------

        private static HttpConnection Conn(string text)
        {
            return new HttpConnection(new MemoryStream(HttpParser.Latin1.GetBytes(text)));
        }


        private static void Http_RequestHead()
        {
            HttpConnection c = Conn("POST /v1/messages?x=1 HTTP/1.1\r\nHost: api.example\r\nX-Api-Key: {{kc:k}}\r\ncontent-length:  7 \r\n\r\nbody...");
            HttpRequestHead h = Wait(HttpParser.ReadRequestHeadAsync(c, CancellationToken.None));
            Check.Eq("POST", h.Method, "méthode");
            Check.Eq("/v1/messages?x=1", h.Target, "cible");
            Check.Eq("HTTP/1.1", h.Version, "version");
            Check.Eq(3, h.Headers.Count, "trois en-têtes");
            Check.Eq("api.example", h.Headers.First("host"), "nom insensible à la casse");
            Check.Eq("7", h.Headers.First("Content-Length"), "valeur sans espaces autour");
            Check.Eq("X-Api-Key", System.Linq.Enumerable.ElementAt(h.Headers, 1).Name, "casse d'origine conservée");
            Check.Eq(7L, HttpParser.RequestFraming(h.Headers).Length, "cadrage Content-Length");
            byte[] rest = new byte[7];
            Wait(c.ReadExactAsync(rest, 0, 7, CancellationToken.None));
            Check.Eq("body...", HttpParser.Latin1.GetString(rest), "le corps suit exactement la tête");
            Check.True(Wait(HttpParser.ReadRequestHeadAsync(Conn(""), CancellationToken.None)) == null, "EOF propre → null");
            HttpRequestHead connect = Wait(HttpParser.ReadRequestHeadAsync(Conn("CONNECT api.example:443 HTTP/1.1\r\nHost: api.example:443\r\n\r\n"), CancellationToken.None));
            Check.Eq("api.example:443", connect.Target, "CONNECT authority");
            Check.Eq(BodyFramingKind.None, HttpParser.RequestFraming(connect.Headers).Kind, "sans corps");
        }

        private static void Http_HeadLimitsAndErrors()
        {
            HttpProtocolException ex = Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET /\r\n\r\n"), CancellationToken.None)); }, "ligne de requête à deux éléments");
            Check.Eq(400, ex.Status, "400");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nNoColon\r\n\r\n"), CancellationToken.None)); }, "en-tête sans deux-points");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nBad Name: x\r\n\r\n"), CancellationToken.None)); }, "espace dans le nom");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn("GET / HTTP/1.1\r\nHost: a\r\n"), CancellationToken.None)); }, "tête tronquée");
            StringBuilder many = new StringBuilder("GET / HTTP/1.1\r\n");
            for (int i = 0; i < 101; i++) many.Append("X-").Append(i).Append(": v\r\n");
            many.Append("\r\n");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn(many.ToString()), CancellationToken.None)); }, "plus de 100 en-têtes");
            string big = "GET / HTTP/1.1\r\nX: " + new string('a', 70 * 1024) + "\r\n\r\n";
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadRequestHeadAsync(Conn(big), CancellationToken.None)); }, "tête > 64 KiB");
            Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Content-Length: abc")); }, "Content-Length non numérique");
            Check.Throws<HttpProtocolException>(delegate { HttpParser.RequestFraming(HeadersOf("Content-Length: -1")); }, "Content-Length négatif");
        }

        private static HttpHeaders HeadersOf(params string[] lines)
        {
            HttpHeaders h = new HttpHeaders();
            foreach (string line in lines)
            {
                int colon = line.IndexOf(':');
                h.Add(line.Substring(0, colon), line.Substring(colon + 1).Trim());
            }
            return h;
        }

        private static void Http_ResponseHeadAndFraming()
        {
            HttpResponseHead r = Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n"), CancellationToken.None));
            Check.Eq(200, r.Status, "statut");
            Check.Eq("OK", r.Reason, "raison");
            Check.Eq(BodyFramingKind.Chunked, HttpParser.ResponseFraming(r.Headers, "GET", 200).Kind, "chunked");
            Check.Eq(BodyFramingKind.None, HttpParser.ResponseFraming(r.Headers, "HEAD", 200).Kind, "HEAD : pas de corps");
            Check.Eq(BodyFramingKind.None, HttpParser.ResponseFraming(HeadersOf("Content-Length: 5"), "GET", 204).Kind, "204 : pas de corps");
            Check.Eq(BodyFramingKind.UntilClose, HttpParser.ResponseFraming(HeadersOf("Content-Type: text/plain"), "GET", 200).Kind, "ni longueur ni chunked → jusqu'à la fermeture");
            Check.Eq(5L, HttpParser.ResponseFraming(HeadersOf("Content-Length: 5"), "GET", 200).Length, "Content-Length");
            HttpResponseHead noReason = Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 502 \r\n\r\n"), CancellationToken.None));
            Check.Eq(502, noReason.Status, "raison vide acceptée");
            Check.Eq("", noReason.Reason, "raison vide");
            HttpProtocolException ex = Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadResponseHeadAsync(Conn("HTTP/1.1 2x0 OK\r\n\r\n"), CancellationToken.None)); }, "statut invalide");
            Check.Eq(502, ex.Status, "une réponse amont invalide vaut 502 pour le client");
            Check.True(Wait(HttpParser.ReadResponseHeadAsync(Conn(""), CancellationToken.None)) == null, "EOF → null");
            Check.True(HttpParser.WantsClose("HTTP/1.1", HeadersOf("Connection: keep-alive, Close")), "Connection: close (jeton, insensible à la casse)");
            Check.True(!HttpParser.WantsClose("HTTP/1.1", HeadersOf("Connection: keep-alive")), "keep-alive explicite");
            Check.True(HttpParser.WantsClose("HTTP/1.0", new HttpHeaders()), "HTTP/1.0 sans keep-alive ferme");
            Check.True(!HttpParser.WantsClose("HTTP/1.0", HeadersOf("Connection: keep-alive")), "HTTP/1.0 + keep-alive garde");
            Check.True(HttpParser.ExpectsContinue(HeadersOf("Expect: 100-Continue")), "Expect: 100-continue");
        }

        private static void Http_EncodeHeads()
        {
            HttpHeaders h = new HttpHeaders();
            h.Add("Host", "api.example");
            h.Add("X-Api-Key", "sk-é");
            string req = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpRequestHead("POST", "/v1", "HTTP/1.1", h)));
            Check.Eq("POST /v1 HTTP/1.1\r\nHost: api.example\r\nX-Api-Key: sk-é\r\n\r\n", req, "tête de requête (octets Latin-1 transparents)");
            string resp = HttpParser.Latin1.GetString(HttpParser.Encode(new HttpResponseHead("HTTP/1.1", 502, "Bad Gateway", HeadersOf("Content-Length: 0"))));
            Check.Eq("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", resp, "tête de réponse");
            Check.Eq("405 Method Not Allowed", HttpParser.StatusLine(405), "libellé 405");
            Check.Eq("100 Continue", HttpParser.StatusLine(100), "libellé 100");
            HttpHeaders clone = h.Clone();
            clone.Set("host", "other");
            clone.Remove("x-api-key");
            Check.Eq("api.example", h.First("Host"), "Clone est indépendant");
            Check.Eq("other", clone.First("Host"), "Set remplace la valeur en gardant la casse du nom d'origine");
            Check.Eq("Host", System.Linq.Enumerable.First(clone).Name, "nom d'origine conservé par Set");
            Check.Eq(1, clone.Count, "Remove retire toutes les occurrences");
            clone.Add("Via", "a");
            clone.Add("via", "b");
            Check.Eq("a,b", string.Join(",", clone.All("VIA")), "All rend toutes les occurrences dans l'ordre");
            clone.Set("Via", "c");
            Check.Eq(1, clone.All("via").Count, "Set ne laisse qu'une occurrence");
        }

        private static void Http_ReadBodyContentLengthAndChunked()
        {
            BufferedBody b = Wait(HttpParser.ReadBodyAsync(Conn("hello world!"), BodyFraming.OfLength(5), 4096, CancellationToken.None));
            Check.Eq("hello", HttpParser.Latin1.GetString(b.Bytes), "Content-Length : exactement N octets");
            Check.True(b.Complete && b.Remaining == 0, "complet");
            b = Wait(HttpParser.ReadBodyAsync(Conn("0123456789"), BodyFraming.OfLength(10), 4, CancellationToken.None));
            Check.Eq("0123", HttpParser.Latin1.GetString(b.Bytes), "tronqué à la limite");
            Check.True(!b.Complete && b.Remaining == 6, "6 octets restent sur le fil");
            b = Wait(HttpParser.ReadBodyAsync(Conn("4\r\nWiki\r\n5;ext=1\r\npedia\r\n0\r\nTrailer: x\r\n\r\nNEXT"), BodyFraming.Chunked, 4096, CancellationToken.None));
            Check.Eq("Wikipedia", HttpParser.Latin1.GetString(b.Bytes), "chunked décodé, extension ignorée, trailers consommés");
            Check.True(b.Complete, "complet");
            HttpConnection c = Conn("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
            b = Wait(HttpParser.ReadBodyAsync(c, BodyFraming.Chunked, 6, CancellationToken.None));
            Check.Eq("Wikipe", HttpParser.Latin1.GetString(b.Bytes), "arrêt au milieu d'un chunk à la limite");
            Check.True(!b.Complete && b.ChunkRemaining == 3, "3 octets du chunk courant restent");
            MemoryStream outStream = new MemoryStream();
            Wait(HttpParser.RelayRemainderAsync(c, new HttpConnection(outStream), BodyFraming.Chunked, b, CancellationToken.None));
            Check.Eq("3\r\ndia\r\n0\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "le reste est réémis en chunks");
            Check.Throws<HttpProtocolException>(delegate { Wait(HttpParser.ReadBodyAsync(Conn("zz\r\n"), BodyFraming.Chunked, 4096, CancellationToken.None)); }, "taille de chunk invalide");
            Check.Throws<EndOfStreamException>(delegate { Wait(HttpParser.ReadBodyAsync(Conn("abc"), BodyFraming.OfLength(5), 4096, CancellationToken.None)); }, "corps tronqué");
            b = Wait(HttpParser.ReadBodyAsync(Conn("x"), BodyFraming.None, 4096, CancellationToken.None));
            Check.Eq(0, b.Bytes.Length, "sans corps → vide");
        }

        private static void Http_RelayBodyStreaming()
        {
            MemoryStream outStream = new MemoryStream();
            HttpConnection to = new HttpConnection(outStream);
            long n = Wait(HttpParser.RelayBodyAsync(Conn("4\r\nWiki\r\n5\r\npedia\r\n0\r\nX: y\r\n\r\n"), to, BodyFraming.Chunked, CancellationToken.None));
            Check.Eq("4\r\nWiki\r\n5\r\npedia\r\n0\r\nX: y\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "chunked relayé octet pour octet, trailers compris");
            Check.Eq(9L, n, "octets utiles comptés");
            outStream = new MemoryStream();
            byte[] big = new byte[40000];
            for (int i = 0; i < big.Length; i++) big[i] = (byte)(i % 251);
            n = Wait(HttpParser.RelayBodyAsync(new HttpConnection(new MemoryStream(big)), new HttpConnection(outStream), BodyFraming.OfLength(40000), CancellationToken.None));
            Check.True(n == 40000 && outStream.Length == 40000, "Content-Length relayé par blocs de 16 KiB");
            Check.Eq(Convert.ToBase64String(big), Convert.ToBase64String(outStream.ToArray()), "octets identiques");
            outStream = new MemoryStream();
            n = Wait(HttpParser.RelayBodyAsync(Conn("until the end"), new HttpConnection(outStream), BodyFraming.UntilClose, CancellationToken.None));
            Check.Eq("until the end", HttpParser.Latin1.GetString(outStream.ToArray()), "jusqu'à EOF");
            outStream = new MemoryStream();
            Wait(HttpParser.WriteChunkAsync(new HttpConnection(outStream), HttpParser.Latin1.GetBytes("abc"), 0, 3, CancellationToken.None));
            Wait(HttpParser.WriteLastChunkAsync(new HttpConnection(outStream), CancellationToken.None));
            Check.Eq("3\r\nabc\r\n0\r\n\r\n", HttpParser.Latin1.GetString(outStream.ToArray()), "écriture de chunks");
        }

        private static void Http_ConnectionLeftoverAndTimeout()
        {
            HttpConnection c = Conn("CONNECT h:443 HTTP/1.1\r\n\r\n\x16\x03\x01TLS");
            HttpRequestHead h = Wait(HttpParser.ReadRequestHeadAsync(c, CancellationToken.None));
            Check.Eq("CONNECT", h.Method, "CONNECT lu");
            byte[] left = c.TakeBuffered();
            Check.Eq("\x16\x03\x01TLS", HttpParser.Latin1.GetString(left), "les octets TLS arrivés dans le même segment sont rendus");
            Check.Eq(0, c.TakeBuffered().Length, "une seule fois");
            PrefixedStream p = new PrefixedStream(left, new MemoryStream(HttpParser.Latin1.GetBytes("more")));
            byte[] buf = new byte[32];
            int n1 = p.Read(buf, 0, 4);
            int n2 = p.Read(buf, 4, 28);
            Check.Eq(4, n1, "première lecture bornée à count");
            Check.Eq(2, n2, "le reste du préfixe avant le flux interne");
            Check.Eq("\x16\x03\x01TLS", HttpParser.Latin1.GetString(buf, 0, 6), "le préfixe est servi d'abord");
            int n3 = p.Read(buf, 6, 26);
            Check.Eq("\x16\x03\x01TLSmore", HttpParser.Latin1.GetString(buf, 0, 6 + n3), "puis le flux interne");
            HttpConnection slow = new HttpConnection(new BlockingStream());
            slow.ReadTimeout = TimeSpan.FromMilliseconds(200);
            Check.Throws<TimeoutException>(delegate { Wait(slow.ReadLineAsync(100, CancellationToken.None)); }, "inactivité → TimeoutException");
            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel();
            Check.Throws<OperationCanceledException>(delegate { Wait(new HttpConnection(new BlockingStream()).ReadLineAsync(100, cts.Token)); }, "annulation → OperationCanceledException");
            Check.Throws<HttpProtocolException>(delegate { Wait(Conn(new string('a', 70000) + "\r\n").ReadLineAsync(65536, CancellationToken.None)); }, "ligne trop longue");
            Check.Eq("ab", Wait(Conn("ab\n").ReadLineAsync(10, CancellationToken.None)), "LF seul toléré");
        }

        /// <summary>Flux dont la lecture ne rend jamais (simule un pair silencieux).</summary>
        private sealed class BlockingStream : Stream
        {
            public override bool CanRead { get { return true; } }
            public override bool CanSeek { get { return false; } }
            public override bool CanWrite { get { return false; } }
            public override long Length { get { throw new NotSupportedException(); } }
            public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
            public override void Flush() { }
            public override int Read(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
            public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            {
                TaskCompletionSource<int> tcs = new TaskCompletionSource<int>();
                cancellationToken.Register(delegate { tcs.TrySetCanceled(); });
                return tcs.Task;
            }
            public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
            public override void SetLength(long value) { throw new NotSupportedException(); }
            public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
        }
    }
}
