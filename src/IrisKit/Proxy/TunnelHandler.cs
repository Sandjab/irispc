using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Hôte hors whitelist (SPECS §8.3) : TCP vers l'autorité du CONNECT, 200, pompe bidirectionnelle, event passThrough à la fermeture.</summary>
    public static class TunnelHandler
    {
        public static async Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            DateTime started = server.Clock();
            Stopwatch watch = Stopwatch.StartNew();
            string path = host + ":" + port;
            TcpClient upstream = null;
            UpstreamException connectError = null;
            try { upstream = await UpstreamClient.ConnectTcpAsync(host, port, server.Options.ConnectTimeout, cancel).ConfigureAwait(false); }
            catch (UpstreamException ex) { connectError = ex; }
            if (connectError != null)
            {
                // C# 5 : pas d'await dans un catch.
                Log.Warn("proxy", "tunnel vers " + path + " impossible : " + connectError.Message);
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", path, 502, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                await ConnectHandler.WriteSimpleResponseAsync(conn.Http, 502, "amont injoignable : " + connectError.Message, cancel).ConfigureAwait(false);
                return;
            }
            using (upstream)
            {
                HttpConnection up = new HttpConnection(upstream.GetStream());
                up.ReadTimeout = server.Options.IdleTimeout;
                HttpConnection client = conn.Http;
                try
                {
                    byte[] ok = HttpParser.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await client.WriteAsync(ok, 0, ok.Length, cancel).ConfigureAwait(false);
                    await client.FlushAsync(cancel).ConfigureAwait(false);
                    byte[] early = client.TakeBuffered();
                    if (early.Length > 0) await up.WriteAsync(early, 0, early.Length, cancel).ConfigureAwait(false);
                    Log.Debug("proxy", "tunnel " + conn.Remote + " → " + path);
                    Task a = PumpAsync(client, up, cancel);
                    Task b = PumpAsync(up, client, cancel);
                    await Task.WhenAny(a, b).ConfigureAwait(false);
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                finally
                {
                    conn.Close();
                    upstream.Close();
                }
            }
            server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.PassThrough, host, "CONNECT", path, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
            Log.Info("proxy", "tunnel fermé " + path + " (" + watch.ElapsedMilliseconds + " ms)");
        }

        /// <summary>Copie jusqu'à EOF, erreur, annulation ou inactivité ; l'appelant ferme les deux côtés.</summary>
        private static async Task PumpAsync(HttpConnection from, HttpConnection to, CancellationToken cancel)
        {
            byte[] block = new byte[HttpParser.RelayBlock];
            try
            {
                while (true)
                {
                    int n = await from.ReadAsync(block, 0, block.Length, cancel).ConfigureAwait(false);
                    if (n == 0) return;
                    await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (TimeoutException) { }
            catch (OperationCanceledException) { }
        }
    }
}
