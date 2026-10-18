using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Flux SSE (SPECS §14, spec phase 3 §8) --------------------------------------

        private static EventPipeline SsePipeline() { return new EventPipeline(new EventRing(5000), null, new EventsBus()); }

        private static EventsServer StartSse(EventPipeline events)
        {
            EventsServer s = new EventsServer("127.0.0.1:0", events);
            s.PingInterval = TimeSpan.FromMilliseconds(200);
            s.Start();
            return s;
        }

        /// <summary>Message suivant qui n'est pas un commentaire (ping) ; null à la fermeture.</summary>
        private static SseMessage NextEvent(EventsClient c)
        {
            SseMessage m;
            do { m = Wait(c.ReadAsync()); } while (m != null && m.IsComment);
            return m;
        }

        private static void Sse_StreamsLiveEventsWithHeaders()
        {
            EventPipeline events = SsePipeline();
            using (EventsServer server = StartSse(events))
            using (EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, null, TimeSpan.FromSeconds(10))))
            {
                Check.True(c.Head.Headers.First("Content-Type") == "text/event-stream" && c.Head.Headers.First("Cache-Control") == "no-cache" && c.Head.Headers.First("Connection") == "close", "en-têtes SSE");
                Check.Eq("connected", Wait(c.ReadAsync()).Comment, "commentaire d'ouverture");
                Event e = IpcEvent(EventKind.Substituted, "api.example.com", DateTime.UtcNow);
                events.Emit(e);
                SseMessage m = NextEvent(c);
                Check.True(m.EventName == "substituted" && m.Id == e.Id.ToString("D"), "event: <kind> et id: <uuid>");
                Check.Eq("api.example.com", m.ToEvent().Host, "data: JSON de l'Event");
                Check.Eq(1, server.SubscriberCount, "un abonné");
            }
        }

        private static void Sse_SinceBacklogNoDuplicates()
        {
            EventPipeline events = SsePipeline();
            DateTime t = DateTime.UtcNow;
            List<Event> early = new List<Event>();
            for (int i = 0; i < 3; i++) { Event e = IpcEvent(EventKind.NoMatch, "h" + i + ".example", t.AddSeconds(i)); early.Add(e); events.Emit(e); }
            using (EventsServer server = StartSse(events))
            using (EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, "since=" + Uri.EscapeDataString(Json.FormatDate(t.AddMinutes(-1))), TimeSpan.FromSeconds(10))))
            {
                for (int i = 0; i < 3; i++) Check.Eq(early[i].Id.ToString("D"), NextEvent(c).Id, "backlog dans l'ordre (" + i + ")");
                Event live = IpcEvent(EventKind.Error, "live.example", t.AddSeconds(10));
                events.Emit(live);
                Check.Eq(live.Id.ToString("D"), NextEvent(c).Id, "puis le direct, sans doublon du backlog");
            }
        }

        private static void Sse_FiltersKindAndHost()
        {
            EventPipeline events = SsePipeline();
            using (EventsServer server = StartSse(events))
            using (EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, "kind=error,exfilBlocked&host=api.x.example", TimeSpan.FromSeconds(10))))
            {
                Wait(c.ReadAsync());
                events.Emit(IpcEvent(EventKind.Substituted, "api.x.example", DateTime.UtcNow));
                events.Emit(IpcEvent(EventKind.Error, "other.example", DateTime.UtcNow));
                Event wanted = IpcEvent(EventKind.Error, "api.x.example", DateTime.UtcNow);
                events.Emit(wanted);
                Check.Eq(wanted.Id.ToString("D"), NextEvent(c).Id, "seul l'event qui passe kind et host est livré");
            }
        }

        private static void Sse_Ping()
        {
            using (EventsServer server = StartSse(SsePipeline()))
            using (EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, null, TimeSpan.FromSeconds(5))))
            {
                Wait(c.ReadAsync());
                Check.Eq("ping", Wait(c.ReadAsync()).Comment, "ping périodique");
            }
        }

        private static void Sse_Errors()
        {
            using (EventsServer server = StartSse(SsePipeline()))
            {
                int port = server.ListenEndPoint.Port;
                Check.True(Wait(TestProxyClient.RawAsync(port, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")).StartsWith("HTTP/1.1 404 Not Found\r\n"), "chemin inconnu → 404");
                Check.True(Wait(TestProxyClient.RawAsync(port, "POST /events HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")).StartsWith("HTTP/1.1 405 "), "méthode → 405");
                Check.True(Wait(TestProxyClient.RawAsync(port, "GARBAGE\r\n\r\n")).StartsWith("HTTP/1.1 400 "), "requête illisible → 400");
                Check.Eq(400, Check.Throws<EventsClientException>(delegate { Wait(EventsClient.ConnectAsync(port, "since=hier", TimeSpan.FromSeconds(5))); }, "since invalide").Status, "since invalide → 400");
                Check.Eq(400, Check.Throws<EventsClientException>(delegate { Wait(EventsClient.ConnectAsync(port, "kind=bogus", TimeSpan.FromSeconds(5))); }, "kind inconnu").Status, "kind inconnu → 400");
                Check.Eq(0, server.SubscriberCount, "aucun abonné compté pour ces refus");
            }
        }

        private static void Sse_SubscriberLimit()
        {
            using (EventsServer server = StartSse(SsePipeline()))
            {
                int port = server.ListenEndPoint.Port;
                List<EventsClient> clients = new List<EventsClient>();
                try
                {
                    for (int i = 0; i < EventsServer.MaxSubscribers; i++) clients.Add(Wait(EventsClient.ConnectAsync(port, null, TimeSpan.FromSeconds(5))));
                    Check.Eq(32, server.SubscriberCount, "32 abonnés");
                    Check.Eq(503, Check.Throws<EventsClientException>(delegate { Wait(EventsClient.ConnectAsync(port, null, TimeSpan.FromSeconds(5))); }, "33e abonné").Status, "au-delà de 32 → 503");
                    clients[0].Dispose();
                    clients.RemoveAt(0);
                    Check.True(WaitFor(delegate { return server.SubscriberCount <= 31; }, 5000), "un départ libère une place (détecté au ping)");
                    clients.Add(Wait(EventsClient.ConnectAsync(port, null, TimeSpan.FromSeconds(5))));
                }
                finally { foreach (EventsClient c in clients) c.Dispose(); }
            }
        }

        private static void Sse_SlowConsumerDropped()
        {
            EventPipeline events = SsePipeline();
            using (EventsServer server = StartSse(events))
            using (EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, null, TimeSpan.FromSeconds(10))))
            {
                Wait(c.ReadAsync());
                Stopwatch watch = Stopwatch.StartNew();
                for (int i = 0; i < 5000; i++) events.Emit(IpcEvent(EventKind.NoMatch, "burst-" + i + ".example", DateTime.UtcNow));
                Check.True(watch.Elapsed < TimeSpan.FromSeconds(2), "Emit ne bloque jamais sur un abonné qui ne lit pas (" + watch.ElapsedMilliseconds + " ms)");
                SseMessage m;
                int delivered = 0;
                while ((m = NextEvent(c)) != null && m.EventName != "dropped") delivered++;
                Check.True(m != null && m.EventName == "dropped", "event: dropped reçu après " + delivered + " events");
                long count = Json.ParseObject(m.Data).Int("count");
                Check.True(count > 0 && delivered + count <= 5000, "count = events non livrés (" + count + ")");
                Check.True(Wait(c.ReadAsync()) == null, "puis fermeture");
            }
        }

        private static void Sse_LoopbackAndPortInUse()
        {
            EventPipeline events = SsePipeline();
            using (EventsServer open = new EventsServer("0.0.0.0:0", events))
                Check.True(Check.Throws<ProxyException>(delegate { open.Start(); }, "hors bouclage refusé").Message.Contains("bouclage"), "message explicite");
            TcpListener squatter = new TcpListener(IPAddress.Loopback, 0);
            squatter.Start();
            try
            {
                int port = ((IPEndPoint)squatter.LocalEndpoint).Port;
                using (EventsServer busy = new EventsServer("127.0.0.1:" + port, events))
                {
                    PortBindException ex = Check.Throws<PortBindException>(delegate { busy.Start(); }, "port occupé");
                    Check.True(ex.Failure == PortBindFailure.InUse && ex.Role == "flux d'events" && ex.Port == port, "rôle et port");
                }
            }
            finally { squatter.Stop(); }
        }

        private static void Sse_StopClosesSubscribers()
        {
            EventsServer server = StartSse(SsePipeline());
            EventsClient c = Wait(EventsClient.ConnectAsync(server.ListenEndPoint.Port, null, TimeSpan.FromSeconds(5)));
            Wait(c.ReadAsync());
            Stopwatch watch = Stopwatch.StartNew();
            server.Stop();
            Check.True(watch.Elapsed < TimeSpan.FromSeconds(5), "Stop rend la main");
            bool closed;
            try { SseMessage m; do { m = Wait(c.ReadAsync()); } while (m != null && m.IsComment); closed = m == null; }
            catch (System.IO.IOException) { closed = true; }
            Check.True(closed, "l'abonné voit la fermeture");
            c.Dispose();
        }
    }
}
