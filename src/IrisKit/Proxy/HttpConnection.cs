using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Lecteur bufferisé asynchrone sur un Stream (NetworkStream, SslStream, MemoryStream) : lignes, lecture exacte,
    /// restes non consommés (TakeBuffered, pour la bascule TLS après CONNECT), délai d'inactivité par lecture.
    /// Les écritures passent directement au flux interne.
    /// </summary>
    public sealed class HttpConnection : IDisposable
    {
        private readonly Stream inner;
        private byte[] buffer = new byte[16 * 1024];
        private int start;
        private int end;

        /// <summary>Délai maximal d'attente d'une lecture ; TimeSpan.Zero = illimité. Dépassement → TimeoutException.</summary>
        public TimeSpan ReadTimeout { get; set; }

        public Stream Inner { get { return inner; } }

        public HttpConnection(Stream inner)
        {
            if (inner == null) throw new ArgumentNullException("inner");
            this.inner = inner;
        }

        // ---- Lecture ----------------------------------------------------

        /// <summary>Ligne terminée par LF (CR final retiré), sans le terminateur ; null si EOF sans octet lu.</summary>
        public async Task<string> ReadLineAsync(int maxLength, CancellationToken cancel)
        {
            int scanned = 0;
            while (true)
            {
                for (int i = start + scanned; i < end; i++)
                {
                    if (buffer[i] == (byte)'\n')
                    {
                        int length = i - start;
                        if (length > 0 && buffer[i - 1] == (byte)'\r') length--;
                        if (length > maxLength) throw new HttpProtocolException(400, "ligne HTTP trop longue (plus de " + maxLength + " octets)");
                        string line = HttpParser.Latin1.GetString(buffer, start, length);
                        start = i + 1;
                        return line;
                    }
                }
                scanned = end - start;
                if (scanned > maxLength) throw new HttpProtocolException(400, "ligne HTTP trop longue (plus de " + maxLength + " octets)");
                if (!await FillAsync(cancel).ConfigureAwait(false))
                {
                    if (scanned == 0) return null;
                    throw new HttpProtocolException(400, "ligne HTTP tronquée");
                }
            }
        }

        /// <summary>Au plus count octets, d'abord depuis le tampon ; 0 à EOF.</summary>
        public async Task<int> ReadAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            if (count == 0) return 0;
            if (start == end && !await FillAsync(cancel).ConfigureAwait(false)) return 0;
            int n = Math.Min(count, end - start);
            Buffer.BlockCopy(buffer, start, dst, offset, n);
            start += n;
            return n;
        }

        public async Task ReadExactAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            int done = 0;
            while (done < count)
            {
                int n = await ReadAsync(dst, offset + done, count - done, cancel).ConfigureAwait(false);
                if (n == 0) throw new EndOfStreamException("flux fermé après " + done + " octet(s) sur " + count);
                done += n;
            }
        }

        /// <summary>Rend et vide les octets déjà reçus mais non consommés (ex. ClientHello TLS arrivé avec le CONNECT).</summary>
        public byte[] TakeBuffered()
        {
            byte[] rest = new byte[end - start];
            Buffer.BlockCopy(buffer, start, rest, 0, rest.Length);
            start = end = 0;
            return rest;
        }

        private async Task<bool> FillAsync(CancellationToken cancel)
        {
            if (start > 0)
            {
                Buffer.BlockCopy(buffer, start, buffer, 0, end - start);
                end -= start;
                start = 0;
            }
            if (end == buffer.Length) Array.Resize(ref buffer, buffer.Length * 2);
            int n = await ReadInnerAsync(buffer, end, buffer.Length - end, cancel).ConfigureAwait(false);
            if (n <= 0) return false;
            end += n;
            return true;
        }

        private async Task<int> ReadInnerAsync(byte[] dst, int offset, int count, CancellationToken cancel)
        {
            cancel.ThrowIfCancellationRequested();
            Task<int> read = inner.ReadAsync(dst, offset, count, cancel);
            if (ReadTimeout <= TimeSpan.Zero) return await read.ConfigureAwait(false);
            using (CancellationTokenSource delayCts = CancellationTokenSource.CreateLinkedTokenSource(cancel))
            {
                Task delay = Task.Delay(ReadTimeout, delayCts.Token);
                Task first = await Task.WhenAny(read, delay).ConfigureAwait(false);
                if (first == delay)
                {
                    cancel.ThrowIfCancellationRequested();
                    Observe(read);
                    throw new TimeoutException("aucune donnée reçue pendant " + (int)ReadTimeout.TotalSeconds + " s");
                }
                delayCts.Cancel();
                return await read.ConfigureAwait(false);
            }
        }

        /// <summary>Une lecture abandonnée (délai dépassé) finira par échouer à la fermeture du flux : on observe son exception.</summary>
        private static void Observe(Task task)
        {
            task.ContinueWith(delegate(Task t) { Exception ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
        }

        // ---- Écriture ---------------------------------------------------

        public Task WriteAsync(byte[] data, int offset, int count, CancellationToken cancel)
        {
            return inner.WriteAsync(data, offset, count, cancel);
        }

        public Task FlushAsync(CancellationToken cancel)
        {
            return inner.FlushAsync(cancel);
        }

        public void Dispose()
        {
            inner.Dispose();
        }
    }

    /// <summary>Flux qui sert d'abord un préfixe (octets déjà lus) puis délègue au flux interne. Sert à poser un SslStream après un CONNECT.</summary>
    public sealed class PrefixedStream : Stream
    {
        private readonly byte[] prefix;
        private int position;
        private readonly Stream inner;

        public PrefixedStream(byte[] prefix, Stream inner)
        {
            this.prefix = prefix ?? new byte[0];
            this.inner = inner;
        }

        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return inner.CanWrite; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }

        public override int Read(byte[] buffer, int offset, int count)
        {
            int n = FromPrefix(buffer, offset, count);
            return n > 0 ? n : inner.Read(buffer, offset, count);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            int n = FromPrefix(buffer, offset, count);
            return n > 0 ? Task.FromResult(n) : inner.ReadAsync(buffer, offset, count, cancellationToken);
        }

        private int FromPrefix(byte[] buffer, int offset, int count)
        {
            int n = Math.Min(count, prefix.Length - position);
            if (n <= 0) return 0;
            Buffer.BlockCopy(prefix, position, buffer, offset, n);
            position += n;
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) { inner.Write(buffer, offset, count); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) { return inner.WriteAsync(buffer, offset, count, cancellationToken); }
        public override void Flush() { inner.Flush(); }
        public override Task FlushAsync(CancellationToken cancellationToken) { return inner.FlushAsync(cancellationToken); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }

        protected override void Dispose(bool disposing)
        {
            if (disposing) inner.Dispose();
            base.Dispose(disposing);
        }
    }
}
