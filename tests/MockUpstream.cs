using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>
    /// Serveur HTTPS de test en process (cf. ../Iris/Tests/IntegrationTests/MockUpstream.swift) : son propre CA, une feuille
    /// pour `host`, enregistre chaque requête complète, répond `200 OK` (corps `OK`) ou suit un plan de streaming.
    /// </summary>
    public sealed class MockUpstream : IDisposable
    {
        public sealed class ReceivedRequest { public HttpRequestHead Head; public byte[] Body; }

        public sealed class StreamingPlan
        {
            public byte[] FirstChunk;
            public IList<byte[]> RemainingChunks = new List<byte[]>();
            public TaskCompletionSource<bool> ReleaseRest = new TaskCompletionSource<bool>();
            public bool DropAfterFirstChunk;
        }

        public int Port { get; private set; }
        public X509Certificate2 CACertificate { get { return ca.Certificate; } }
        public StreamingPlan Streaming;
        public int Connections;

        private readonly CAManager ca;
        private readonly LeafCertCache leaves;
        private readonly X509Certificate2 leaf;
        private readonly TcpListener listener;
        private readonly List<ReceivedRequest> received = new List<ReceivedRequest>();
        private readonly SemaphoreSlim arrived = new SemaphoreSlim(0);
        private readonly CancellationTokenSource stopping = new CancellationTokenSource();

        private MockUpstream(string host)
        {
            ca = new CAManager(new InMemoryCAKeyStore(), null, delegate { return DateTime.UtcNow; });
            ca.EnsureCA();
            leaves = new LeafCertCache(ca, delegate { return DateTime.UtcNow; });
            leaf = leaves.Get(host);
            listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        }

        public static MockUpstream Start(string host)
        {
            MockUpstream mock = new MockUpstream(host);
            Task.Run(new Func<Task>(mock.AcceptLoopAsync));
            return mock;
        }

        public IList<ReceivedRequest> Received { get { lock (received) { return new List<ReceivedRequest>(received); } } }

        public async Task<ReceivedRequest> WaitForRequestAsync(TimeSpan timeout)
        {
            if (!await arrived.WaitAsync(timeout)) throw new TimeoutException("aucune requête reçue par MockUpstream en " + timeout.TotalSeconds + " s");
            lock (received) { return received[received.Count - 1]; }
        }

        private async Task AcceptLoopAsync()
        {
            while (!stopping.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(); }
                catch (ObjectDisposedException) { return; }
                catch (SocketException) { return; }
                Interlocked.Increment(ref Connections);
                Task ignored = ServeAsync(client);
            }
        }

        private async Task ServeAsync(TcpClient client)
        {
            using (client)
            using (SslStream ssl = new SslStream(client.GetStream(), false))
            {
                try
                {
                    await ssl.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false);
                    HttpConnection http = new HttpConnection(ssl);
                    while (true)
                    {
                        HttpRequestHead head = await HttpParser.ReadRequestHeadAsync(http, stopping.Token);
                        if (head == null) return;
                        BufferedBody body = await HttpParser.ReadBodyAsync(http, HttpParser.RequestFraming(head.Headers), 64 * 1024 * 1024, stopping.Token);
                        ReceivedRequest r = new ReceivedRequest();
                        r.Head = head;
                        r.Body = body.Bytes;
                        lock (received) received.Add(r);
                        arrived.Release();
                        StreamingPlan plan = Streaming;
                        if (plan != null) { await StreamAsync(http, plan); return; }
                        byte[] reply = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK");
                        await http.WriteAsync(reply, 0, reply.Length, stopping.Token);
                        await http.FlushAsync(stopping.Token);
                        if (HttpParser.WantsClose(head.Version, head.Headers)) return;
                    }
                }
                catch (IOException) { }
                catch (AuthenticationException) { }
                catch (HttpProtocolException) { }
                catch (OperationCanceledException) { }
                catch (ObjectDisposedException) { }
            }
        }

        private async Task StreamAsync(HttpConnection http, StreamingPlan plan)
        {
            byte[] head = HttpParser.Latin1.GetBytes("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n");
            await http.WriteAsync(head, 0, head.Length, stopping.Token);
            await HttpParser.WriteChunkAsync(http, plan.FirstChunk, 0, plan.FirstChunk.Length, stopping.Token);
            await http.FlushAsync(stopping.Token);
            if (plan.DropAfterFirstChunk) return; // fermeture sans dernier chunk : amont coupé en plein flux
            await plan.ReleaseRest.Task;
            foreach (byte[] chunk in plan.RemainingChunks) await HttpParser.WriteChunkAsync(http, chunk, 0, chunk.Length, stopping.Token);
            await HttpParser.WriteLastChunkAsync(http, stopping.Token);
        }

        public void Stop()
        {
            stopping.Cancel();
            listener.Stop();
            leaves.Dispose();
            ca.Dispose();
        }

        public void Dispose() { Stop(); }
    }
}
