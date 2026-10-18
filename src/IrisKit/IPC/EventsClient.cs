using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Le flux d'events a répondu autre chose que 200 (400, 404, 405, 503).</summary>
    public sealed class EventsClientException : Exception
    {
        public int Status { get; private set; }

        public EventsClientException(int status, string body)
            : base("flux d'events refusé : HTTP " + status + (string.IsNullOrEmpty(body) ? "" : " (" + body + ")"))
        {
            Status = status;
        }
    }

    /// <summary>Un message SSE : soit un commentaire (`: connected`, `: ping`), soit un event (`event`, `id`, `data`).</summary>
    public sealed class SseMessage
    {
        public string Comment { get; internal set; }
        public string EventName { get; internal set; }
        public string Id { get; internal set; }
        public string Data { get; internal set; }
        public bool IsComment { get { return Comment != null; } }

        public Event ToEvent() { return Event.FromJson(Json.ParseObject(Data)); }
    }

    /// <summary>Client SSE (tests, puis app) : `GET /events`, puis messages un par un, commentaires compris.</summary>
    public sealed class EventsClient : IDisposable
    {
        private readonly TcpClient tcp;
        private readonly HttpConnection http;

        public HttpResponseHead Head { get; private set; }

        private EventsClient(TcpClient tcp, HttpConnection http, HttpResponseHead head)
        {
            this.tcp = tcp;
            this.http = http;
            Head = head;
        }

        public static async Task<EventsClient> ConnectAsync(int port, string query, TimeSpan readTimeout)
        {
            TcpClient tcp = new TcpClient();
            try
            {
                await tcp.ConnectAsync(IPAddress.Loopback, port).ConfigureAwait(false);
                HttpConnection http = new HttpConnection(tcp.GetStream());
                http.ReadTimeout = readTimeout;
                string target = "/events" + (string.IsNullOrEmpty(query) ? "" : "?" + query);
                byte[] request = HttpParser.Latin1.GetBytes("GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/event-stream\r\n\r\n");
                await http.WriteAsync(request, 0, request.Length, CancellationToken.None).ConfigureAwait(false);
                await http.FlushAsync(CancellationToken.None).ConfigureAwait(false);
                HttpResponseHead head = await HttpParser.ReadResponseHeadAsync(http, CancellationToken.None).ConfigureAwait(false);
                if (head == null) throw new IOException("le flux d'events a fermé la connexion sans répondre");
                if (head.Status != 200)
                {
                    BufferedBody body = await HttpParser.ReadBodyAsync(http, HttpParser.ResponseFraming(head.Headers, "GET", head.Status), 65536, CancellationToken.None).ConfigureAwait(false);
                    throw new EventsClientException(head.Status, Encoding.UTF8.GetString(body.Bytes).Trim());
                }
                return new EventsClient(tcp, http, head);
            }
            catch
            {
                tcp.Close();
                throw;
            }
        }

        /// <summary>Message suivant ; null quand le serveur ferme le flux.</summary>
        public async Task<SseMessage> ReadAsync()
        {
            SseMessage m = new SseMessage();
            bool any = false;
            while (true)
            {
                string raw = await http.ReadLineAsync(1 << 20, CancellationToken.None).ConfigureAwait(false);
                if (raw == null) return any ? m : null;
                string line = Encoding.UTF8.GetString(HttpParser.Latin1.GetBytes(raw));
                if (line.Length == 0)
                {
                    if (any) return m;
                    continue;
                }
                if (line[0] == ':')
                {
                    m.Comment = line.Substring(1).Trim();
                    return m;
                }
                any = true;
                int colon = line.IndexOf(':');
                string field = colon < 0 ? line : line.Substring(0, colon);
                string value = colon < 0 ? "" : line.Substring(colon + 1);
                if (value.StartsWith(" ", StringComparison.Ordinal)) value = value.Substring(1);
                if (field == "event") m.EventName = value;
                else if (field == "id") m.Id = value;
                else if (field == "data") m.Data = m.Data == null ? value : m.Data + "\n" + value;
            }
        }

        public void Dispose() { tcp.Close(); }
    }
}
