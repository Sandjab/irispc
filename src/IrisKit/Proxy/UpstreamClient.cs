using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Connexion amont impossible (DNS, TCP, délai, TLS). Message sans valeur de secret.</summary>
    public sealed class UpstreamException : Exception
    {
        public UpstreamException(string message, Exception inner) : base(message, inner) { }
    }

    public sealed class UpstreamConnection : IDisposable
    {
        private readonly TcpClient client;
        private readonly SslStream tls;
        public HttpConnection Http { get; private set; }
        public string Host { get; private set; }
        public int Port { get; private set; }

        internal UpstreamConnection(TcpClient client, SslStream tls, string host, int port)
        {
            this.client = client; this.tls = tls; Host = host; Port = port;
            Http = new HttpConnection(tls);
        }

        public void Dispose()
        {
            try { tls.Dispose(); } catch (IOException) { }
            client.Close();
        }
    }

    /// <summary>TCP avec délai de connexion puis SslStream client : TLS 1.2 minimum, SNI = hôte, validation par IUpstreamTrust (spec §6.1).</summary>
    public sealed class UpstreamClient
    {
        private readonly IUpstreamTrust trust;
        private readonly TimeSpan connectTimeout;

        public UpstreamClient(IUpstreamTrust trust, TimeSpan connectTimeout)
        {
            if (trust == null) throw new ArgumentNullException("trust");
            this.trust = trust;
            this.connectTimeout = connectTimeout;
        }

        /// <summary>Connexion TCP bornée dans le temps ; lève UpstreamException (SocketException ou délai).</summary>
        public static async Task<TcpClient> ConnectTcpAsync(string host, int port, TimeSpan timeout, CancellationToken cancel)
        {
            TcpClient client = new TcpClient();
            try
            {
                Task connect = client.ConnectAsync(host, port);
                using (CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(cancel))
                {
                    Task delay = Task.Delay(timeout, cts.Token);
                    Task first = await Task.WhenAny(connect, delay).ConfigureAwait(false);
                    if (first == delay)
                    {
                        Task observed = connect.ContinueWith(delegate(Task t) { Exception ignored = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
                        cancel.ThrowIfCancellationRequested();
                        throw new UpstreamException("connexion à " + host + ":" + port + " sans réponse après " + (int)timeout.TotalSeconds + " s", null);
                    }
                    cts.Cancel();
                    await connect.ConfigureAwait(false);
                }
                client.NoDelay = true;
                return client;
            }
            catch (SocketException ex)
            {
                client.Close();
                throw new UpstreamException("connexion à " + host + ":" + port + " impossible : " + ex.Message, ex);
            }
            catch (Exception)
            {
                client.Close();
                throw;
            }
        }

        public async Task<UpstreamConnection> ConnectTlsAsync(string host, int port, CancellationToken cancel)
        {
            TcpClient client = await ConnectTcpAsync(host, port, connectTimeout, cancel).ConfigureAwait(false);
            SslStream tls = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(trust));
            try
            {
                await tls.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false).ConfigureAwait(false);
                return new UpstreamConnection(client, tls, host, port);
            }
            catch (AuthenticationException ex)
            {
                tls.Dispose(); client.Close();
                throw new UpstreamException("TLS vers " + host + ":" + port + " refusé (" + trust.Describe() + ") : " + ex.Message, ex);
            }
            catch (IOException ex)
            {
                tls.Dispose(); client.Close();
                throw new UpstreamException("TLS vers " + host + ":" + port + " interrompu : " + ex.Message, ex);
            }
        }
    }
}
