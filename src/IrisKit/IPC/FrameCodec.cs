using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Trame annonçant plus que le plafond autorisé : la connexion doit être fermée sans réponse.</summary>
    public sealed class FrameTooLargeException : IOException
    {
        public long Declared { get; private set; }
        public int Maximum { get; private set; }

        public FrameTooLargeException(long declared, int maximum)
            : base("trame de " + declared + " octets refusée (maximum " + maximum + ")")
        {
            Declared = declared;
            Maximum = maximum;
        }
    }

    /// <summary>Trames du pipe admin (SPECS §13.1) : 4 octets big-endian (longueur du JSON) puis le JSON UTF-8.</summary>
    public static class FrameCodec
    {
        public const int MaxRequestBytes = 1 << 20;
        public const int MaxResponseBytes = 16 << 20;

        /// <summary>Une trame complète ; null si le flux se ferme avant tout octet ; EndOfStreamException si elle est tronquée.</summary>
        public static async Task<byte[]> ReadAsync(Stream stream, int maxBytes, CancellationToken cancel)
        {
            byte[] header = new byte[4];
            int got = await FillAsync(stream, header, 0, 4, cancel).ConfigureAwait(false);
            if (got == 0) return null;
            if (got < 4) throw new EndOfStreamException("en-tête de trame tronqué");
            long length = ((long)header[0] << 24) | ((long)header[1] << 16) | ((long)header[2] << 8) | header[3];
            if (length > maxBytes) throw new FrameTooLargeException(length, maxBytes);
            byte[] payload = new byte[length];
            int read = await FillAsync(stream, payload, 0, (int)length, cancel).ConfigureAwait(false);
            if (read < length)
            {
                Array.Clear(payload, 0, read);
                throw new EndOfStreamException("trame tronquée : " + read + "/" + length + " octets");
            }
            return payload;
        }

        /// <summary>Écrit une trame et vide le flux ; la copie locale (qui peut porter une valeur de secret) est effacée.</summary>
        public static async Task WriteAsync(Stream stream, byte[] payload, CancellationToken cancel)
        {
            byte[] frame = new byte[4 + payload.Length];
            frame[0] = (byte)(payload.Length >> 24);
            frame[1] = (byte)(payload.Length >> 16);
            frame[2] = (byte)(payload.Length >> 8);
            frame[3] = (byte)payload.Length;
            Buffer.BlockCopy(payload, 0, frame, 4, payload.Length);
            try
            {
                await stream.WriteAsync(frame, 0, frame.Length, cancel).ConfigureAwait(false);
                await stream.FlushAsync(cancel).ConfigureAwait(false);
            }
            finally { Array.Clear(frame, 0, frame.Length); }
        }

        private static async Task<int> FillAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancel)
        {
            int total = 0;
            while (total < count)
            {
                int n = await stream.ReadAsync(buffer, offset + total, count - total, cancel).ConfigureAwait(false);
                if (n == 0) break;
                total += n;
            }
            return total;
        }
    }
}
