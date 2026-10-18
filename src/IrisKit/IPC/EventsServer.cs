using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>
    /// Flux d'events SSE (SPECS §14, spec phase 3 §8) : TcpListener en bouclage, `GET /events`, backlog `since` depuis le ring,
    /// ping périodique, file bornée par abonné (débordement → `event: dropped` puis fermeture), 32 abonnés au plus.
    /// Un abonné qui ne lit plus est coupé après WriteTimeout. Jamais de valeur de secret : les events n'en portent pas.
    /// </summary>
    public sealed class EventsServer : IDisposable
    {
        public const int MaxSubscribers = 32;
        public const int MaxQueued = 1000;
        public const string Role = "flux d'events";

        private readonly EventPipeline events;
        private readonly string host;
        private readonly int port;
        private readonly object gate = new object();
        private readonly HashSet<TcpClient> clients = new HashSet<TcpClient>();
        private readonly List<Task> tasks = new List<Task>();
        private TcpListener listener;
        private CancellationTokenSource stopping;
        private Task acceptLoop;
        private int subscribers;

        public TimeSpan PingInterval = TimeSpan.FromSeconds(15);
        public TimeSpan WriteTimeout = TimeSpan.FromSeconds(10);

        public IPEndPoint ListenEndPoint { get; private set; }
        public int SubscriberCount { get { return Volatile.Read(ref subscribers); } }

        /// <summary>`listen` : `ip:port` (validé par BrokerConfig.ValidateListen ; port 0 accepté pour les tests).</summary>
        public EventsServer(string listen, EventPipeline events)
        {
            if (events == null) throw new ArgumentNullException("events");
            int colon = listen.LastIndexOf(':');
            host = listen.Substring(0, colon);
            port = int.Parse(listen.Substring(colon + 1), CultureInfo.InvariantCulture);
            this.events = events;
        }

        public IPEndPoint Start()
        {
            IPAddress ip;
            if (!IPAddress.TryParse(host, out ip) || !IPAddress.IsLoopback(ip))
                throw new ProxyException("le flux d'events n'écoute que sur une adresse de bouclage (127.0.0.1 ou ::1), pas sur " + host);
            if (listener != null) throw new ProxyException("flux d'events déjà démarré");
            TcpListener l = new TcpListener(ip, port);
            PortBinding.Start(l, 16, Role, port);
            listener = l;
            ListenEndPoint = (IPEndPoint)l.LocalEndpoint;
            stopping = new CancellationTokenSource();
            acceptLoop = AcceptLoopAsync(l, stopping.Token);
            Log.Info("events", "flux SSE à l'écoute : http://" + ListenEndPoint + "/events");
            return ListenEndPoint;
        }

        private async Task AcceptLoopAsync(TcpListener l, CancellationToken cancel)
        {
            while (!cancel.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await l.AcceptTcpClientAsync().ConfigureAwait(false); }
                catch (ObjectDisposedException) { return; }
                catch (InvalidOperationException) { return; }
                catch (SocketException) { if (cancel.IsCancellationRequested) return; continue; }
                client.NoDelay = true;
                Task t = ServeAsync(client, cancel);
                lock (gate) { tasks.Add(t); tasks.RemoveAll(delegate(Task x) { return x.IsCompleted; }); }
            }
        }

        private async Task ServeAsync(TcpClient client, CancellationToken cancel)
        {
            lock (gate) { clients.Add(client); }
            bool counted = false;
            IDisposable subscription = null;
            try
            {
                HttpConnection http = new HttpConnection(client.GetStream());
                http.ReadTimeout = TimeSpan.FromSeconds(10);
                HttpRequestHead head = null;
                bool unreadable = false;
                try { head = await HttpParser.ReadRequestHeadAsync(http, cancel).ConfigureAwait(false); }
                catch (HttpProtocolException) { unreadable = true; }
                if (unreadable) { await ConnectHandler.WriteSimpleResponseAsync(http, 400, "requête illisible", cancel).ConfigureAwait(false); return; }
                if (head == null) return;
                string path = head.Target;
                int q = path.IndexOf('?');
                if (q >= 0) path = path.Substring(0, q);
                if (path != "/events") { await ConnectHandler.WriteSimpleResponseAsync(http, 404, "seul /events est servi", cancel).ConfigureAwait(false); return; }
                if (head.Method != "GET") { await ConnectHandler.WriteSimpleResponseAsync(http, 405, "seul GET est accepté sur /events", cancel).ConfigureAwait(false); return; }
                SseFilters filters = null;
                string invalid = null;
                try { filters = SseFilters.Parse(head.Target); }
                catch (FormatException ex) { invalid = ex.Message; }
                if (filters == null) { await ConnectHandler.WriteSimpleResponseAsync(http, 400, invalid, cancel).ConfigureAwait(false); return; }
                if (Interlocked.Increment(ref subscribers) > MaxSubscribers)
                {
                    Interlocked.Decrement(ref subscribers);
                    await ConnectHandler.WriteSimpleResponseAsync(http, 503, "trop d'abonnés au flux d'events (" + MaxSubscribers + " au plus)", cancel).ConfigureAwait(false);
                    return;
                }
                counted = true;
                SseSubscriber sub = new SseSubscriber(MaxQueued);
                subscription = events.Bus.Subscribe(sub.Offer);
                await StreamAsync(http, sub, filters, cancel).ConfigureAwait(false);
            }
            catch (IOException) { }
            catch (ObjectDisposedException) { }
            catch (TimeoutException ex) { Log.Debug("events", "abonné SSE coupé : " + ex.Message); }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log.Debug("events", "abonné SSE terminé sur " + ex.GetType().Name + " : " + ex.Message); }
            finally
            {
                if (subscription != null) subscription.Dispose();
                if (counted) Interlocked.Decrement(ref subscribers);
                lock (gate) { clients.Remove(client); }
                client.Close();
            }
        }

        private async Task StreamAsync(HttpConnection http, SseSubscriber sub, SseFilters filters, CancellationToken cancel)
        {
            await WriteTextAsync(http, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n: connected\n\n", cancel).ConfigureAwait(false);
            HashSet<Guid> sent = new HashSet<Guid>();
            if (filters.Since.HasValue)
                foreach (Event e in events.Ring.Since(filters.Since.Value))
                    if (filters.Matches(e))
                    {
                        sent.Add(e.Id);
                        await WriteTextAsync(http, SseFilters.Format(e), cancel).ConfigureAwait(false);
                    }
            while (!cancel.IsCancellationRequested)
            {
                bool signaled = await sub.WaitAsync(PingInterval, cancel).ConfigureAwait(false);
                if (!signaled && !sub.Overflowed)
                {
                    await WriteTextAsync(http, ": ping\n\n", cancel).ConfigureAwait(false);
                    continue;
                }
                Event next;
                while (!sub.Overflowed && sub.TryTake(out next))
                {
                    if (sent.Count > 0 && sent.Remove(next.Id)) continue;
                    if (filters.Matches(next)) await WriteTextAsync(http, SseFilters.Format(next), cancel).ConfigureAwait(false);
                }
                if (sub.Overflowed)
                {
                    int dropped = sub.TakeDropped();
                    Log.Warn("events", "abonné SSE en retard de plus de " + MaxQueued + " events : " + dropped + " event(s) non livré(s), connexion fermée");
                    await WriteTextAsync(http, "event: dropped\ndata: {\"count\":" + dropped + "}\n\n", cancel).ConfigureAwait(false);
                    return;
                }
            }
        }

        /// <summary>Écrit puis vide ; un abonné qui ne lit plus depuis WriteTimeout est coupé (TimeoutException).</summary>
        private async Task WriteTextAsync(HttpConnection http, string text, CancellationToken cancel)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            Task write = WriteAndFlushAsync(http, bytes, cancel);
            Task done = await Task.WhenAny(write, Task.Delay(WriteTimeout)).ConfigureAwait(false);
            if (done != write) throw new TimeoutException("abonné SSE bloqué depuis " + (int)WriteTimeout.TotalSeconds + " s");
            await write.ConfigureAwait(false);
        }

        private static async Task WriteAndFlushAsync(HttpConnection http, byte[] bytes, CancellationToken cancel)
        {
            await http.WriteAsync(bytes, 0, bytes.Length, cancel).ConfigureAwait(false);
            await http.FlushAsync(cancel).ConfigureAwait(false);
        }

        /// <summary>Ferme l'écoute et tous les abonnés ; attend la fin des tâches, 2 s au plus.</summary>
        public void Stop()
        {
            if (listener == null) return;
            stopping.Cancel();
            try { listener.Stop(); }
            catch (SocketException) { }
            List<TcpClient> open;
            List<Task> pending;
            lock (gate)
            {
                open = new List<TcpClient>(clients);
                pending = new List<Task>(tasks);
            }
            foreach (TcpClient c in open) c.Close();
            try { Task.WaitAll(pending.ToArray(), TimeSpan.FromSeconds(2)); }
            catch (AggregateException) { }
            try { acceptLoop.Wait(TimeSpan.FromSeconds(2)); }
            catch (AggregateException) { }
            listener = null;
            Log.Info("events", "flux SSE fermé");
        }

        public void Dispose() { Stop(); }
    }
}
