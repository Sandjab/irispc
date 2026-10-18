using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Daemon avec proxy ---------------------------------------------------

        private sealed class LiveDaemon
        {
            public Task<int> Exit;
            public CapturingWriter Out = new CapturingWriter();
            public CapturingWriter Err = new CapturingWriter();
            public CancellationTokenSource Cts = new CancellationTokenSource();

            public int WaitExit()
            {
                if (!Exit.Wait(TimeSpan.FromSeconds(20))) throw new TimeoutException("le daemon ne s'est pas arrêté : " + Out.Snapshot() + Err.Snapshot());
                return Exit.Result;
            }
        }

        private static LiveDaemon StartDaemon(ScriptedConsoleInput console, params string[] args)
        {
            LiveDaemon d = new LiveDaemon();
            Log.Reset();
            d.Exit = Task.Run(delegate { return Entry.Run(args, d.Out, d.Err, console, d.Cts.Token); });
            return d;
        }

        private static bool WaitFor(Func<bool> condition, int ms)
        {
            DateTime limit = DateTime.UtcNow.AddMilliseconds(ms);
            while (DateTime.UtcNow < limit)
            {
                if (condition()) return true;
                Wait(Task.Delay(25));
            }
            return condition();
        }

        private static void WriteListenPort(string data, int port)
        {
            DataDir.Prepare(data);
            ConfigStore store = ConfigStore.Open(data, T0);
            Config c = store.Current;
            BrokerConfig b = new BrokerConfig("127.0.0.1:" + port, c.Broker.EventsListen, c.Broker.AdminPipe, c.Broker.LogLevel, c.Broker.EventRetentionDays, c.Broker.EventRingSize);
            store.Save(new Config(c.Version, b, c.Security, c.Backups, c.Hosts, c.Plugins), T0);
        }

        private static void Entry_StartsProxyAndAnswersPing()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                int port = FreePort();
                WriteListenPort(data, port);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                try
                {
                    Check.True(WaitFor(delegate { return d.Out.Snapshot().Contains("irisd ready on 127.0.0.1:" + port); }, 10000), "log « irisd ready on <ip:port> » : " + d.Out.Snapshot() + d.Err.Snapshot());
                    Check.True(d.Out.Snapshot().Contains("ca=" + Path.Combine(data, "ca.pem")), "le log cite ca.pem");
                    string ping = Wait(TestProxyClient.RawAsync(port, "GET /__iris_ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"));
                    Check.True(ping.StartsWith("HTTP/1.1 200 OK"), "le proxy répond au ping");
                    Check.True(!d.Exit.IsCompleted, "le daemon attend Ctrl+C");
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre → 0 : " + d.Err.Snapshot());
                Check.True(d.Out.Snapshot().Contains("arrêt demandé"), "log d'arrêt");
                TcpListener free = new TcpListener(IPAddress.Loopback, port);
                free.Start(); free.Stop();
                Check.True(true, "le port est libéré après l'arrêt");
                Check.Eq("", d.Err.Snapshot(), "rien sur stderr");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Entry_PortInUse_Exit3()
        {
            string dir = TestDir.Create();
            TcpListener squatter = new TcpListener(IPAddress.Loopback, 0);
            squatter.Start();
            try
            {
                int port = ((IPEndPoint)squatter.LocalEndpoint).Port;
                string data = Path.Combine(dir, "data");
                WriteListenPort(data, port);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Port, d.WaitExit(), "port occupé → 3");
                string err = d.Err.Snapshot();
                Check.True(err.StartsWith("irisd : ") && err.Contains(port.ToString()) && err.Contains("déjà utilisé"), "message avec le port : " + err);
                Check.True(!err.Contains("   at ") && !err.Contains("   à "), "aucune trace de pile");
            }
            finally { squatter.Stop(); Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Entry_CtrlC_DuringPrompt_Exit0()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                ScriptedConsoleInput console = new ScriptedConsoleInput();
                console.BlockWhenExhausted = true;
                LiveDaemon d = StartDaemon(console, "--foreground", "--data", data);
                Check.True(WaitFor(delegate { return console.PromptCount >= 1; }, 10000), "le daemon attend le mot de passe du nouveau coffre");
                Check.True(!d.Exit.IsCompleted, "bloqué sur l'invite");
                d.Cts.Cancel();
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "Ctrl+C pendant la saisie → arrêt normal, code 0");
                Check.True(d.Err.Snapshot().Contains("arrêt demandé"), "message d'arrêt sur stderr");
                Check.True(!File.Exists(Path.Combine(data, "iris.kdbx")), "aucun coffre créé");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void PurgeScheduler_NextMidnightAndRunNow()
        {
            string dir = TestDir.Create();
            try
            {
                DateTime clock = new DateTime(2026, 10, 17, 23, 59, 59, DateTimeKind.Utc);
                Check.Eq(new DateTime(2026, 10, 18, 0, 0, 1, DateTimeKind.Utc), PurgeScheduler.NextMidnight(clock), "minuit UTC + 1 s");
                using (JsonlEventStore store = new JsonlEventStore(dir, 1, delegate { return clock; }))
                {
                    File.WriteAllText(Path.Combine(dir, "events-2026-10-10.jsonl"), "{}\n");
                    File.WriteAllText(Path.Combine(dir, "events-2026-10-17.jsonl"), "{}\n");
                    using (PurgeScheduler scheduler = new PurgeScheduler(store, delegate { return clock; }))
                    {
                        Check.Eq(new DateTime(2026, 10, 18, 0, 0, 1, DateTimeKind.Utc), scheduler.NextRunUtc, "prochaine purge planifiée à minuit");
                        Check.True(scheduler.RunNow() >= 1, "RunNow purge le fichier hors rétention");
                        Check.True(!File.Exists(Path.Combine(dir, "events-2026-10-10.jsonl")) && File.Exists(Path.Combine(dir, "events-2026-10-17.jsonl")), "vieux fichier supprimé, celui du jour gardé");
                        clock = new DateTime(2026, 10, 18, 0, 0, 2, DateTimeKind.Utc);
                        scheduler.RunNow();
                        Check.Eq(new DateTime(2026, 10, 19, 0, 0, 1, DateTimeKind.Utc), scheduler.NextRunUtc, "replanifiée au minuit suivant");
                    }
                }
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
