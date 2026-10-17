using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Tête HTTP malformée ou hors limites. Status = réponse à rendre au client (400 côté requête, 502 côté amont).</summary>
    public sealed class HttpProtocolException : Exception
    {
        public int Status { get; private set; }
        public HttpProtocolException(int status, string message) : base(message) { Status = status; }
    }

    public enum BodyFramingKind { None, ContentLength, Chunked, UntilClose }

    public sealed class BodyFraming
    {
        public BodyFramingKind Kind { get; private set; }
        public long Length { get; private set; }

        private BodyFraming(BodyFramingKind kind, long length) { Kind = kind; Length = length; }

        public static readonly BodyFraming None = new BodyFraming(BodyFramingKind.None, 0);
        public static readonly BodyFraming Chunked = new BodyFraming(BodyFramingKind.Chunked, 0);
        public static readonly BodyFraming UntilClose = new BodyFraming(BodyFramingKind.UntilClose, 0);
        public static BodyFraming OfLength(long length) { return new BodyFraming(BodyFramingKind.ContentLength, length); }
    }

    /// <summary>Corps lu en mémoire jusqu'à une limite. Complete = false : le reste est encore sur le fil (Remaining octets, ou ChunkRemaining dans le chunk courant).</summary>
    public sealed class BufferedBody
    {
        public byte[] Bytes { get; private set; }
        public bool Complete { get; private set; }
        public long Remaining { get; private set; }
        public long ChunkRemaining { get; private set; }

        public BufferedBody(byte[] bytes, bool complete, long remaining, long chunkRemaining)
        {
            Bytes = bytes; Complete = complete; Remaining = remaining; ChunkRemaining = chunkRemaining;
        }
    }

    /// <summary>HTTP/1.1 minimal et strict (spec §6.1) : têtes (≤ 64 KiB, ≤ 100 en-têtes), corps Content-Length ou chunked, relais par blocs.</summary>
    public static class HttpParser
    {
        public const int MaxHeadBytes = 64 * 1024;
        public const int MaxHeaders = 100;
        public const int MaxBufferedBody = 4 * 1024 * 1024;
        public const int RelayBlock = 16 * 1024;

        /// <summary>Les octets d'en-tête sont transportés tels quels (ISO-8859-1 : un octet ↔ un caractère).</summary>
        public static readonly Encoding Latin1 = Encoding.GetEncoding(28591);
        private static readonly byte[] CrLf = { 13, 10 };

        // ---- Têtes ------------------------------------------------------

        public static async Task<HttpRequestHead> ReadRequestHeadAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
            if (line == null) return null;
            if (line.Length == 0) line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false); // RFC 7230 §3.5 : un CRLF de trop toléré
            if (line == null) return null;
            string[] parts = line.Split(' ');
            if (parts.Length != 3 || parts[0].Length == 0 || parts[1].Length == 0 || !parts[2].StartsWith("HTTP/1.", StringComparison.Ordinal))
                throw new HttpProtocolException(400, "ligne de requête invalide");
            HttpHeaders headers = await ReadHeadersAsync(c, line.Length + 2, 400, cancel).ConfigureAwait(false);
            return new HttpRequestHead(parts[0], parts[1], parts[2], headers);
        }

        public static async Task<HttpResponseHead> ReadResponseHeadAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
            if (line == null) return null;
            int sp1 = line.IndexOf(' ');
            if (sp1 < 0 || !line.StartsWith("HTTP/1.", StringComparison.Ordinal)) throw new HttpProtocolException(502, "ligne de statut amont invalide");
            int sp2 = line.IndexOf(' ', sp1 + 1);
            string code = sp2 < 0 ? line.Substring(sp1 + 1) : line.Substring(sp1 + 1, sp2 - sp1 - 1);
            int status;
            if (code.Length != 3 || !int.TryParse(code, NumberStyles.None, CultureInfo.InvariantCulture, out status))
                throw new HttpProtocolException(502, "statut amont invalide : " + code);
            string reason = sp2 < 0 ? "" : line.Substring(sp2 + 1);
            HttpHeaders headers = await ReadHeadersAsync(c, line.Length + 2, 502, cancel).ConfigureAwait(false);
            return new HttpResponseHead(line.Substring(0, sp1), status, reason, headers);
        }

        private static async Task<HttpHeaders> ReadHeadersAsync(HttpConnection c, int consumed, int errorStatus, CancellationToken cancel)
        {
            HttpHeaders headers = new HttpHeaders();
            while (true)
            {
                string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                if (line == null) throw new HttpProtocolException(errorStatus, "tête HTTP tronquée");
                consumed += line.Length + 2;
                if (consumed > MaxHeadBytes) throw new HttpProtocolException(errorStatus, "tête HTTP trop grande (plus de " + MaxHeadBytes + " octets)");
                if (line.Length == 0) return headers;
                if (headers.Count >= MaxHeaders) throw new HttpProtocolException(errorStatus, "plus de " + MaxHeaders + " en-têtes");
                int colon = line.IndexOf(':');
                if (colon <= 0) throw new HttpProtocolException(errorStatus, "en-tête invalide");
                string name = line.Substring(0, colon);
                if (name.IndexOf(' ') >= 0 || name.IndexOf('\t') >= 0) throw new HttpProtocolException(errorStatus, "nom d'en-tête invalide");
                headers.Add(name, line.Substring(colon + 1).Trim(' ', '\t'));
            }
        }

        public static byte[] Encode(HttpRequestHead head)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(head.Method).Append(' ').Append(head.Target).Append(' ').Append(head.Version).Append("\r\n");
            AppendHeaders(sb, head.Headers);
            return Latin1.GetBytes(sb.ToString());
        }

        public static byte[] Encode(HttpResponseHead head)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(head.Version).Append(' ').Append(head.Status.ToString(CultureInfo.InvariantCulture)).Append(' ').Append(head.Reason).Append("\r\n");
            AppendHeaders(sb, head.Headers);
            return Latin1.GetBytes(sb.ToString());
        }

        private static void AppendHeaders(StringBuilder sb, HttpHeaders headers)
        {
            foreach (HttpHeader h in headers) sb.Append(h.Name).Append(": ").Append(h.Value).Append("\r\n");
            sb.Append("\r\n");
        }

        public static async Task WriteAsync(HttpConnection c, HttpRequestHead head, CancellationToken cancel)
        {
            byte[] bytes = Encode(head);
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }

        public static async Task WriteAsync(HttpConnection c, HttpResponseHead head, CancellationToken cancel)
        {
            byte[] bytes = Encode(head);
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }

        public static string StatusLine(int status)
        {
            switch (status)
            {
                case 100: return "100 Continue";
                case 200: return "200 OK";
                case 400: return "400 Bad Request";
                case 405: return "405 Method Not Allowed";
                case 502: return "502 Bad Gateway";
                default: return status.ToString(CultureInfo.InvariantCulture) + " Status";
            }
        }

        // ---- Cadrage ----------------------------------------------------

        /// <summary>Requête : chunked prime, puis Content-Length, sinon pas de corps.</summary>
        public static BodyFraming RequestFraming(HttpHeaders headers)
        {
            if (IsChunked(headers)) return BodyFraming.Chunked;
            string cl = headers.First("Content-Length");
            if (cl == null) return BodyFraming.None;
            return BodyFraming.OfLength(ParseLength(cl, 400));
        }

        /// <summary>Réponse : HEAD, 1xx, 204, 304 → aucun corps ; chunked ; Content-Length ; sinon jusqu'à la fermeture.</summary>
        public static BodyFraming ResponseFraming(HttpHeaders headers, string requestMethod, int status)
        {
            if (string.Equals(requestMethod, "HEAD", StringComparison.OrdinalIgnoreCase) || status / 100 == 1 || status == 204 || status == 304) return BodyFraming.None;
            if (IsChunked(headers)) return BodyFraming.Chunked;
            string cl = headers.First("Content-Length");
            if (cl == null) return BodyFraming.UntilClose;
            return BodyFraming.OfLength(ParseLength(cl, 502));
        }

        private static bool IsChunked(HttpHeaders headers)
        {
            string te = headers.First("Transfer-Encoding");
            return te != null && te.Trim().EndsWith("chunked", StringComparison.OrdinalIgnoreCase);
        }

        private static long ParseLength(string text, int errorStatus)
        {
            long length;
            if (!long.TryParse(text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out length) || length < 0)
                throw new HttpProtocolException(errorStatus, "Content-Length invalide : " + text);
            return length;
        }

        /// <summary>`Connection: close` (jeton, insensible à la casse) ou HTTP/1.0 sans `keep-alive`.</summary>
        public static bool WantsClose(string version, HttpHeaders headers)
        {
            bool close = false, keepAlive = false;
            foreach (string value in headers.All("Connection"))
                foreach (string token in value.Split(','))
                {
                    string t = token.Trim();
                    if (string.Equals(t, "close", StringComparison.OrdinalIgnoreCase)) close = true;
                    if (string.Equals(t, "keep-alive", StringComparison.OrdinalIgnoreCase)) keepAlive = true;
                }
            if (close) return true;
            return string.Equals(version, "HTTP/1.0", StringComparison.Ordinal) && !keepAlive;
        }

        public static bool ExpectsContinue(HttpHeaders headers)
        {
            string e = headers.First("Expect");
            return e != null && string.Equals(e.Trim(), "100-continue", StringComparison.OrdinalIgnoreCase);
        }

        // ---- Corps bufferisé ---------------------------------------------

        public static async Task<BufferedBody> ReadBodyAsync(HttpConnection c, BodyFraming framing, int maxBuffered, CancellationToken cancel)
        {
            switch (framing.Kind)
            {
                case BodyFramingKind.ContentLength:
                    {
                        int take = (int)Math.Min(framing.Length, maxBuffered);
                        byte[] bytes = new byte[take];
                        await c.ReadExactAsync(bytes, 0, take, cancel).ConfigureAwait(false);
                        long remaining = framing.Length - take;
                        return new BufferedBody(bytes, remaining == 0, remaining, 0);
                    }
                case BodyFramingKind.Chunked:
                    return await ReadChunkedAsync(c, maxBuffered, cancel).ConfigureAwait(false);
                default:
                    return new BufferedBody(new byte[0], true, 0, 0);
            }
        }

        private static async Task<BufferedBody> ReadChunkedAsync(HttpConnection c, int maxBuffered, CancellationToken cancel)
        {
            MemoryStream ms = new MemoryStream();
            while (true)
            {
                long size = await ReadChunkSizeAsync(c, cancel).ConfigureAwait(false);
                if (size == 0)
                {
                    await SkipTrailersAsync(c, cancel).ConfigureAwait(false);
                    return new BufferedBody(ms.ToArray(), true, 0, 0);
                }
                long room = maxBuffered - ms.Length;
                if (size > room)
                {
                    if (room > 0) await CopyExactAsync(c, ms, room, cancel).ConfigureAwait(false);
                    return new BufferedBody(ms.ToArray(), false, 0, size - room);
                }
                await CopyExactAsync(c, ms, size, cancel).ConfigureAwait(false);
                await ReadChunkEndAsync(c, cancel).ConfigureAwait(false);
            }
        }

        private static async Task<long> ReadChunkSizeAsync(HttpConnection c, CancellationToken cancel)
        {
            string line = await c.ReadLineAsync(1024, cancel).ConfigureAwait(false);
            if (line == null) throw new EndOfStreamException("flux fermé avant la fin du corps chunked");
            int semi = line.IndexOf(';');
            string hex = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
            long size;
            if (hex.Length == 0 || hex.Length > 15 || !long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out size))
                throw new HttpProtocolException(400, "taille de chunk invalide");
            return size;
        }

        private static async Task ReadChunkEndAsync(HttpConnection c, CancellationToken cancel)
        {
            string crlf = await c.ReadLineAsync(16, cancel).ConfigureAwait(false);
            if (crlf == null) throw new EndOfStreamException("flux fermé dans un chunk");
            if (crlf.Length != 0) throw new HttpProtocolException(400, "fin de chunk invalide");
        }

        private static async Task SkipTrailersAsync(HttpConnection c, CancellationToken cancel)
        {
            while (true)
            {
                string line = await c.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                if (line == null) throw new EndOfStreamException("flux fermé dans les trailers");
                if (line.Length == 0) return;
            }
        }

        private static async Task CopyExactAsync(HttpConnection from, Stream to, long count, CancellationToken cancel)
        {
            byte[] block = new byte[RelayBlock];
            long left = count;
            while (left > 0)
            {
                int n = await from.ReadAsync(block, 0, (int)Math.Min(block.Length, left), cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("flux fermé, " + left + " octet(s) manquant(s)");
                await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                left -= n;
            }
        }

        // ---- Relais streaming ---------------------------------------------

        /// <summary>Relaie un corps entier sans le modifier, flush après chaque bloc ou chunk (SSE). Rend le nombre d'octets utiles.</summary>
        public static async Task<long> RelayBodyAsync(HttpConnection from, HttpConnection to, BodyFraming framing, CancellationToken cancel)
        {
            switch (framing.Kind)
            {
                case BodyFramingKind.ContentLength:
                    return await CopyBlocksAsync(from, to, framing.Length, true, cancel).ConfigureAwait(false);
                case BodyFramingKind.Chunked:
                    return await RelayChunkedVerbatimAsync(from, to, cancel).ConfigureAwait(false);
                case BodyFramingKind.UntilClose:
                    return await CopyBlocksAsync(from, to, long.MaxValue, false, cancel).ConfigureAwait(false);
                default:
                    return 0;
            }
        }

        private static async Task<long> CopyBlocksAsync(HttpConnection from, HttpConnection to, long count, bool exact, CancellationToken cancel)
        {
            byte[] block = new byte[RelayBlock];
            long done = 0;
            while (done < count)
            {
                int n = await from.ReadAsync(block, 0, (int)Math.Min(block.Length, count - done), cancel).ConfigureAwait(false);
                if (n == 0)
                {
                    if (exact) throw new EndOfStreamException("flux fermé après " + done + " octet(s) sur " + count);
                    break;
                }
                await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                await to.FlushAsync(cancel).ConfigureAwait(false);
                done += n;
            }
            return done;
        }

        private static async Task<long> RelayChunkedVerbatimAsync(HttpConnection from, HttpConnection to, CancellationToken cancel)
        {
            long total = 0;
            while (true)
            {
                string line = await from.ReadLineAsync(1024, cancel).ConfigureAwait(false);
                if (line == null) throw new EndOfStreamException("flux fermé avant la fin du corps chunked");
                int semi = line.IndexOf(';');
                string hex = (semi >= 0 ? line.Substring(0, semi) : line).Trim();
                long size;
                if (hex.Length == 0 || hex.Length > 15 || !long.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out size))
                    throw new HttpProtocolException(502, "taille de chunk amont invalide");
                await WriteLineAsync(to, line, cancel).ConfigureAwait(false);
                if (size == 0)
                {
                    while (true)
                    {
                        string trailer = await from.ReadLineAsync(MaxHeadBytes, cancel).ConfigureAwait(false);
                        if (trailer == null) throw new EndOfStreamException("flux fermé dans les trailers");
                        await WriteLineAsync(to, trailer, cancel).ConfigureAwait(false);
                        if (trailer.Length == 0) break;
                    }
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                    return total;
                }
                total += await CopyBlocksAsync(from, to, size, true, cancel).ConfigureAwait(false);
                string end = await from.ReadLineAsync(16, cancel).ConfigureAwait(false);
                if (end == null) throw new EndOfStreamException("flux fermé dans un chunk");
                if (end.Length != 0) throw new HttpProtocolException(502, "fin de chunk amont invalide");
                await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
                await to.FlushAsync(cancel).ConfigureAwait(false);
            }
        }

        /// <summary>Après un ReadBodyAsync incomplet : relaie le reste (Content-Length brut, ou chunks réémis), sans jamais le bufferiser.</summary>
        public static async Task RelayRemainderAsync(HttpConnection from, HttpConnection to, BodyFraming framing, BufferedBody partial, CancellationToken cancel)
        {
            if (framing.Kind == BodyFramingKind.ContentLength)
            {
                await CopyBlocksAsync(from, to, partial.Remaining, true, cancel).ConfigureAwait(false);
                return;
            }
            if (framing.Kind != BodyFramingKind.Chunked) return;
            long pending = partial.ChunkRemaining;
            while (true)
            {
                if (pending > 0)
                {
                    await WriteLineAsync(to, pending.ToString("x", CultureInfo.InvariantCulture), cancel).ConfigureAwait(false);
                    await CopyBlocksAsync(from, to, pending, true, cancel).ConfigureAwait(false);
                    await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                    await ReadChunkEndAsync(from, cancel).ConfigureAwait(false);
                }
                pending = await ReadChunkSizeAsync(from, cancel).ConfigureAwait(false);
                if (pending == 0)
                {
                    await SkipTrailersAsync(from, cancel).ConfigureAwait(false);
                    await WriteLastChunkAsync(to, cancel).ConfigureAwait(false);
                    return;
                }
            }
        }

        public static async Task WriteChunkAsync(HttpConnection to, byte[] data, int offset, int count, CancellationToken cancel)
        {
            if (count == 0) return;
            await WriteLineAsync(to, count.ToString("x", CultureInfo.InvariantCulture), cancel).ConfigureAwait(false);
            await to.WriteAsync(data, offset, count, cancel).ConfigureAwait(false);
            await to.WriteAsync(CrLf, 0, 2, cancel).ConfigureAwait(false);
        }

        public static async Task WriteLastChunkAsync(HttpConnection to, CancellationToken cancel)
        {
            byte[] last = Latin1.GetBytes("0\r\n\r\n");
            await to.WriteAsync(last, 0, last.Length, cancel).ConfigureAwait(false);
            await to.FlushAsync(cancel).ConfigureAwait(false);
        }

        private static async Task WriteLineAsync(HttpConnection to, string line, CancellationToken cancel)
        {
            byte[] bytes = Latin1.GetBytes(line + "\r\n");
            await to.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
        }
    }
}
