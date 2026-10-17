using System;
using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Hôte whitelisté (spec §6.1–6.3) : 200, SslStream serveur avec la feuille de l'hôte, puis boucle keep-alive :
    /// tête → 100 Continue → corps (≤ 4 MiB, sinon streaming) → RequestProcessor → amont (connexion réutilisée) →
    /// relais de la réponse par blocs avec flush → Event. 502 si l'amont ne répond pas avant la tête ; fermeture si après.
    /// </summary>
    public static class MITMHandler
    {
        public static async Task RunAsync(ProxyServer server, ClientConnection conn, string host, int port, CancellationToken cancel)
        {
            DateTime started = server.Clock();
            Stopwatch watch = Stopwatch.StartNew();
            HttpConnection plain = conn.Http;
            byte[] ok = HttpParser.Latin1.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await plain.WriteAsync(ok, 0, ok.Length, cancel).ConfigureAwait(false);
            await plain.FlushAsync(cancel).ConfigureAwait(false);

            X509Certificate2 leaf;
            try { leaf = server.Leaves.Get(host); }
            catch (CryptographicException ex)
            {
                Log.Error("proxy", "feuille impossible pour " + host + " : " + ex.Message);
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", host + ":" + port, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                return;
            }

            SslStream tls = new SslStream(new PrefixedStream(plain.TakeBuffered(), conn.Client.GetStream()), false);
            try { await tls.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false).ConfigureAwait(false); }
            catch (Exception ex)
            {
                if (!(ex is IOException || ex is AuthenticationException || ex is ObjectDisposedException)) throw;
                Log.Warn("proxy", "poignée de main TLS refusée par le client pour " + host + " : le client ne fait pas confiance à data\\ca.pem ? (" + ex.Message + ")");
                server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", host + ":" + port, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                tls.Dispose();
                return;
            }
            using (tls)
            {
                HttpConnection http = new HttpConnection(tls);
                http.ReadTimeout = server.Options.IdleTimeout;
                int served = await ServeAsync(server, http, host, port, cancel).ConfigureAwait(false);
                if (served == 0)
                {
                    // Un client .NET/Schannel valide le certificat après la poignée de main et ferme sans rien envoyer :
                    // même diagnostic qu'une poignée de main refusée (spec §6.3).
                    Log.Warn("proxy", "connexion fermée sans requête après la poignée de main pour " + host + " : le client ne fait pas confiance à data\\ca.pem ?");
                    server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, "CONNECT", host + ":" + port, null, watch.ElapsedMilliseconds, null, null, null, EventFlags.None));
                }
            }
        }

        private static async Task<int> ServeAsync(ProxyServer server, HttpConnection http, string host, int port, CancellationToken cancel)
        {
            int served = 0;
            UpstreamConnection upstream = null;
            try
            {
                while (!cancel.IsCancellationRequested)
                {
                    // C# 5 : pas d'await dans un catch ; les erreurs de protocole sont capturées puis traitées après le try.
                    HttpRequestHead head = null;
                    HttpProtocolException protocolError = null;
                    try { head = await HttpParser.ReadRequestHeadAsync(http, cancel).ConfigureAwait(false); }
                    catch (HttpProtocolException ex) { protocolError = ex; }
                    if (protocolError != null)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, protocolError.Message, cancel).ConfigureAwait(false);
                        return served;
                    }
                    if (head == null) return served;
                    served++;
                    if (PingResponder.Matches(head))
                    {
                        await PingResponder.RespondAsync(http, cancel).ConfigureAwait(false);
                        continue;
                    }

                    DateTime started = server.Clock();
                    Stopwatch watch = Stopwatch.StartNew();
                    string originalTarget = head.Target;
                    string method = head.Method;
                    bool clientWantsClose = HttpParser.WantsClose(head.Version, head.Headers);
                    BodyFraming framing = null;
                    try { framing = HttpParser.RequestFraming(head.Headers); }
                    catch (HttpProtocolException ex) { protocolError = ex; }
                    if (protocolError != null)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, protocolError.Message, cancel).ConfigureAwait(false);
                        return served;
                    }
                    if (HttpParser.ExpectsContinue(head.Headers) && framing.Kind != BodyFramingKind.None)
                    {
                        byte[] cont = HttpParser.Latin1.GetBytes("HTTP/1.1 100 Continue\r\n\r\n");
                        await http.WriteAsync(cont, 0, cont.Length, cancel).ConfigureAwait(false);
                        await http.FlushAsync(cancel).ConfigureAwait(false);
                    }
                    BufferedBody body = null;
                    try { body = await HttpParser.ReadBodyAsync(http, framing, HttpParser.MaxBufferedBody, cancel).ConfigureAwait(false); }
                    catch (HttpProtocolException ex) { protocolError = ex; }
                    if (protocolError != null)
                    {
                        await ConnectHandler.WriteSimpleResponseAsync(http, 400, protocolError.Message, cancel).ConfigureAwait(false);
                        return served;
                    }

                    ProcessedRequest processed = await server.Processor.ProcessAsync(head, body.Bytes, !body.Complete, host, server.Paused).ConfigureAwait(false);
                    HttpHeaders outHeaders = processed.Head.Headers;
                    if (body.Complete && framing.Kind != BodyFramingKind.None)
                    {
                        // Corps entièrement bufferisé : toujours renvoyé en Content-Length (chunked décodé, substitution comprise).
                        outHeaders.Remove("Transfer-Encoding");
                        outHeaders.Set("Content-Length", processed.Body.Length.ToString(System.Globalization.CultureInfo.InvariantCulture));
                    }

                    HttpResponseHead response = null;
                    Exception upstreamError = null;
                    try
                    {
                        if (upstream == null)
                        {
                            upstream = await server.Upstream.ConnectTlsAsync(host, port, cancel).ConfigureAwait(false);
                            upstream.Http.ReadTimeout = server.Options.IdleTimeout;
                        }
                        HttpConnection up = upstream.Http;
                        await HttpParser.WriteAsync(up, new HttpRequestHead(method, processed.Head.Target, "HTTP/1.1", outHeaders), cancel).ConfigureAwait(false);
                        if (body.Complete)
                        {
                            if (processed.Body.Length > 0) await up.WriteAsync(processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                        }
                        else
                        {
                            if (framing.Kind == BodyFramingKind.Chunked) await HttpParser.WriteChunkAsync(up, processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                            else await up.WriteAsync(processed.Body, 0, processed.Body.Length, cancel).ConfigureAwait(false);
                            await up.FlushAsync(cancel).ConfigureAwait(false);
                            await HttpParser.RelayRemainderAsync(http, up, framing, body, cancel).ConfigureAwait(false);
                        }
                        await up.FlushAsync(cancel).ConfigureAwait(false);
                        response = await HttpParser.ReadResponseHeadAsync(up, cancel).ConfigureAwait(false);
                        if (response == null) throw new UpstreamException("l'amont " + host + " a fermé la connexion sans répondre", null);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is UpstreamException || ex is IOException || ex is HttpProtocolException || ex is TimeoutException || ex is ObjectDisposedException)) throw;
                        upstreamError = ex;
                    }
                    if (upstreamError != null)
                    {
                        if (upstream != null) { upstream.Dispose(); upstream = null; }
                        Log.Warn("proxy", "amont " + host + ":" + port + " en échec pour " + method + " " + originalTarget + " : " + upstreamError.Message);
                        server.Events.Emit(new Event(Guid.NewGuid(), started, EventKind.Error, host, method, originalTarget, 502, watch.ElapsedMilliseconds, null, null, null, processed.Flags));
                        await ConnectHandler.WriteSimpleResponseAsync(http, 502, "amont injoignable : " + upstreamError.Message, cancel).ConfigureAwait(false);
                        return served;
                    }

                    bool upstreamWantsClose = HttpParser.WantsClose(response.Version, response.Headers);
                    BodyFraming responseFraming;
                    bool relayFailed = false;
                    try
                    {
                        responseFraming = HttpParser.ResponseFraming(response.Headers, method, response.Status);
                        await HttpParser.WriteAsync(http, response, cancel).ConfigureAwait(false);
                        await http.FlushAsync(cancel).ConfigureAwait(false);
                        await HttpParser.RelayBodyAsync(upstream.Http, http, responseFraming, cancel).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        if (!(ex is IOException || ex is HttpProtocolException || ex is TimeoutException || ex is ObjectDisposedException)) throw;
                        relayFailed = true;
                        responseFraming = BodyFraming.UntilClose;
                        Log.Warn("proxy", "réponse amont interrompue pour " + method + " " + originalTarget + " (" + host + ") : " + ex.Message);
                    }
                    server.Events.Emit(new Event(Guid.NewGuid(), started, relayFailed ? EventKind.Error : processed.EventKind, host, method, originalTarget,
                        response.Status, watch.ElapsedMilliseconds, processed.Substituted, processed.Alert, null, processed.Flags));
                    if (relayFailed) return served; // tête déjà sur le fil : on tronque en fermant (spec §6.3)
                    if (upstreamWantsClose || responseFraming.Kind == BodyFramingKind.UntilClose) { upstream.Dispose(); upstream = null; }
                    if (clientWantsClose || responseFraming.Kind == BodyFramingKind.UntilClose) return served;
                }
            }
            catch (IOException) { }
            catch (TimeoutException) { Log.Debug("proxy", "connexion déchiffrée vers " + host + " fermée pour inactivité"); }
            catch (ObjectDisposedException) { }
            finally
            {
                if (upstream != null) upstream.Dispose();
            }
            return served;
        }
    }
}
