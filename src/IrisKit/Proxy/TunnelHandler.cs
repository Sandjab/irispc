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
        /// <summary>Horodatage partagé de la dernière activité du tunnel, dans une direction ou l'autre.</summary>
        private sealed class Activity
        {
            private long lastTicks = Stopwatch.GetTimestamp();
            public void Touch() { Interlocked.Exchange(ref lastTicks, Stopwatch.GetTimestamp()); }
            public TimeSpan SinceLast()
            {
                long last = Interlocked.Read(ref lastTicks);
                return TimeSpan.FromSeconds((Stopwatch.GetTimestamp() - last) / (double)Stopwatch.Frequency);
            }
        }

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
            using (CancellationTokenSource watchdogCts = CancellationTokenSource.CreateLinkedTokenSource(cancel))
            {
                HttpConnection up = new HttpConnection(upstream.GetStream());
                HttpConnection client = conn.Http;
                // L'inactivité est celle du tunnel entier, pas d'une direction : pendant un long téléchargement le client
                // ne dit rien. Les pompes lisent sans délai propre ; un chien de garde ferme les deux côtés quand ni l'une
                // ni l'autre n'a transporté d'octet depuis IdleTimeout (spec §6.3).
                client.ReadTimeout = TimeSpan.Zero;
                up.ReadTimeout = TimeSpan.Zero;
                Activity activity = new Activity();
                try
                {
                    byte[] ok = HttpParser.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
                    await client.WriteAsync(ok, 0, ok.Length, cancel).ConfigureAwait(false);
                    await client.FlushAsync(cancel).ConfigureAwait(false);
                    byte[] early = client.TakeBuffered();
                    if (early.Length > 0) await up.WriteAsync(early, 0, early.Length, cancel).ConfigureAwait(false);
                    Log.Debug("proxy", "tunnel " + conn.Remote + " → " + path);
                    Task a = PumpAsync(client, up, activity, cancel);
                    Task b = PumpAsync(up, client, activity, cancel);
                    Task idle = WatchIdleAsync(activity, server.Options.IdleTimeout, watchdogCts.Token);
                    Task first = await Task.WhenAny(a, b, idle).ConfigureAwait(false);
                    if (first == idle) Log.Debug("proxy", "tunnel " + path + " fermé pour inactivité");
                }
                catch (IOException) { }
                catch (ObjectDisposedException) { }
                finally
                {
                    watchdogCts.Cancel();
                    conn.Close();
                    upstream.Close();
                }
            }
            server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.PassThrough, host, "CONNECT", path, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
            Log.Info("proxy", "tunnel fermé " + path + " (" + watch.ElapsedMilliseconds + " ms)");
        }

        /// <summary>Copie jusqu'à EOF, erreur ou annulation, en notant chaque bloc transporté ; l'appelant ferme les deux côtés.</summary>
        private static async Task PumpAsync(HttpConnection from, HttpConnection to, Activity activity, CancellationToken cancel)
        {
            byte[] block = new byte[HttpParser.RelayBlock];
            try
            {
                while (true)
                {
                    int n = await from.ReadAsync(block, 0, block.Length, cancel).ConfigureAwait(false);
                    if (n == 0) return;
                    activity.Touch();
                    await to.WriteAsync(block, 0, n, cancel).ConfigureAwait(false);
                    await to.FlushAsync(cancel).ConfigureAwait(false);
                }
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (TimeoutException) { }
            catch (OperationCanceledException) { }
        }

        /// <summary>Rend quand le tunnel n'a rien transporté depuis `idle` (TimeSpan.Zero = jamais) ; annulé par l'appelant sinon.</summary>
        private static async Task WatchIdleAsync(Activity activity, TimeSpan idle, CancellationToken cancel)
        {
            if (idle <= TimeSpan.Zero) { await Task.Delay(Timeout.Infinite, cancel).ConfigureAwait(false); return; }
            while (true)
            {
                TimeSpan remaining = idle - activity.SinceLast();
                if (remaining <= TimeSpan.Zero) return;
                await Task.Delay(remaining, cancel).ConfigureAwait(false);
            }
        }
    }
}
