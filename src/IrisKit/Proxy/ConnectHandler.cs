using System;
using System.Globalization;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`GET /__iris_ping` → `200 ok\n` sans event ni substitution (utilisé par `iris doctor`).</summary>
    public static class PingResponder
    {
        public static bool Matches(HttpRequestHead head)
        {
            return head.Method == "GET" && head.Target == "/__iris_ping";
        }

        public static async Task RespondAsync(HttpConnection c, CancellationToken cancel)
        {
            byte[] bytes = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nCache-Control: no-store\r\n\r\nok\n");
            await c.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
            await c.FlushAsync(cancel).ConfigureAwait(false);
        }
    }

    /// <summary>Première requête d'une connexion (spec §6.1) : ping, non-CONNECT → 405, autorité illisible → 400, whitelist → MITM, sinon tunnel.</summary>
    public static class ConnectHandler
    {
        public static async Task HandleAsync(ProxyServer server, ClientConnection conn, CancellationToken cancel)
        {
            HttpConnection http = conn.Http;
            http.ReadTimeout = server.Options.IdleTimeout;
            HttpRequestHead head = null;
            HttpProtocolException protocolError = null;
            try { head = await HttpParser.ReadRequestHeadAsync(http, cancel).ConfigureAwait(false); }
            catch (HttpProtocolException ex) { protocolError = ex; }
            catch (TimeoutException) { return; }
            catch (IOException) { return; }
            if (protocolError != null)
            {
                // C# 5 : pas d'await dans un catch.
                Log.Debug("proxy", conn.Remote + " : " + protocolError.Message);
                await WriteSimpleResponseAsync(http, 400, protocolError.Message, cancel).ConfigureAwait(false);
                return;
            }
            if (head == null) return;

            if (PingResponder.Matches(head))
            {
                await PingResponder.RespondAsync(http, cancel).ConfigureAwait(false);
                return;
            }
            if (head.Method != "CONNECT")
            {
                Log.Warn("proxy", "requête " + head.Method + " reçue hors tunnel depuis " + conn.Remote + " : le proxy n'accepte que CONNECT (HTTPS_PROXY)");
                await WriteSimpleResponseAsync(http, 405, "irispc n'accepte que CONNECT (configurez HTTPS_PROXY)", cancel).ConfigureAwait(false);
                return;
            }
            string host; int port;
            if (!ParseAuthority(head.Target, out host, out port))
            {
                await WriteSimpleResponseAsync(http, 400, "autorité CONNECT invalide", cancel).ConfigureAwait(false);
                return;
            }
            if (server.IsAllowed(host)) await MITMHandler.RunAsync(server, conn, host, port, cancel).ConfigureAwait(false);
            else await TunnelHandler.RunAsync(server, conn, host, port, cancel).ConfigureAwait(false);
        }

        /// <summary>`host:port`, hôte non vide, port 1–65535.</summary>
        public static bool ParseAuthority(string target, out string host, out int port)
        {
            host = null; port = 0;
            if (string.IsNullOrEmpty(target)) return false;
            int colon = target.LastIndexOf(':');
            if (colon <= 0 || colon == target.Length - 1) return false;
            if (!int.TryParse(target.Substring(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535) return false;
            host = target.Substring(0, colon);
            return host.Length > 0 && host.IndexOf('/') < 0 && host.IndexOf(' ') < 0;
        }

        /// <summary>Réponse courte en texte (400, 405, 502) puis Connection: close ; l'appelant ferme.</summary>
        public static async Task WriteSimpleResponseAsync(HttpConnection c, int status, string body, CancellationToken cancel)
        {
            byte[] text = System.Text.Encoding.UTF8.GetBytes((body ?? "") + "\n");
            HttpHeaders h = new HttpHeaders();
            h.Add("Content-Type", "text/plain; charset=utf-8");
            h.Add("Content-Length", text.Length.ToString(CultureInfo.InvariantCulture));
            h.Add("Connection", "close");
            string line = HttpParser.StatusLine(status);
            int sp = line.IndexOf(' ');
            try
            {
                await HttpParser.WriteAsync(c, new HttpResponseHead("HTTP/1.1", status, line.Substring(sp + 1), h), cancel).ConfigureAwait(false);
                await c.WriteAsync(text, 0, text.Length, cancel).ConfigureAwait(false);
                await c.FlushAsync(cancel).ConfigureAwait(false);
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
        }
    }

    /// <summary>Bouchon remplacé par la tâche 7 : un hôte whitelisté reçoit 502 tant que le MITM n'existe pas.</summary>
    public static class MITMHandler
    {
        public static Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            return ConnectHandler.WriteSimpleResponseAsync(conn.Http, 502, "MITM non disponible (phase 2, tâche 7)", cancel);
        }
    }
}
