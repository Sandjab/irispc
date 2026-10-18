using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- irisd avec pipe et SSE (spec phase 3 §9) ------------------------------------

        private static bool WaitReady(LiveDaemon d)
        {
            return WaitFor(delegate { return d.Exit.IsCompleted || d.Out.Snapshot().Contains("irisd ready on"); }, 15000) && !d.Exit.IsCompleted;
        }

        private static void Arguments_Locked()
        {
            Check.True(Arguments.Parse(new[] { "--foreground", "--locked" }).Locked, "--locked");
            Check.True(!Arguments.Parse(new[] { "--foreground" }).Locked, "par défaut : invite console");
            ArgumentsException ex = Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--locked", "--in-memory-secrets" }); }, "incompatibles");
            Check.True(ex.Message.Contains("incompatibles"), "message : " + ex.Message);
            Check.True(Arguments.Usage().Contains("--locked"), "usage cite --locked");
        }

        private static void Daemon_LockedThenPipeUnlock_EnablesMITM()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                Check.Eq(ExitCodes.Ok, RunLive(new ScriptedConsoleInput("pw-é", "pw-é"), data).Code, "coffre créé à la console");
                TestEndpoints t = WriteTestConfig(data);
                ScriptedConsoleInput console = new ScriptedConsoleInput();
                LiveDaemon d = StartDaemon(console, "--foreground", "--data", data, "--locked");
                try
                {
                    Check.True(WaitReady(d), "prêt : " + d.Out.Snapshot() + d.Err.Snapshot());
                    string ready = d.Out.Snapshot();
                    Check.True(ready.Contains("coffre verrouillé") && ready.Contains("events 127.0.0.1:" + t.Events) && ready.Contains("\\\\.\\pipe\\" + t.Pipe), "log ready complet : " + ready);
                    Check.Eq(0, console.PromptCount, "--locked : aucune invite");
                    using (EventsClient sse = Wait(EventsClient.ConnectAsync(t.Events, "kind=error", TimeSpan.FromSeconds(10))))
                    {
                        Check.Eq("connected", Wait(sse.ReadAsync()).Comment, "flux SSE ouvert");
                        using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                        {
                            Check.Eq(503, Wait(c.ConnectTunnelAsync("api.anthropic.com", 443)), "coffre fermé : 503 pour l'hôte semé");
                            Check.True(c.LastErrorBody.Contains("coffre verrouillé"), "message 503");
                        }
                        SseMessage m = NextEvent(sse);
                        Check.True(m != null && m.EventName == "error" && m.ToEvent().StatusCode == 503, "event error 503 sur le flux SSE");
                    }
                    using (AdminClient admin = AdminClient.Connect(t.Pipe, SelfPath(), TimeSpan.FromSeconds(5)))
                    {
                        Check.Eq("locked", R(admin.Call("daemon.status", null)).String("vault"), "daemon.status : locked");
                        Check.Eq(RpcErrors.BadPassword, Check.Throws<RpcException>(delegate { admin.Call("vault.unlock", P("password", "faux")); }, "mauvais mot de passe").Code, "-32021");
                        Wait(Task.Delay(1100));
                        Check.Eq("unlocked", R(admin.Call("vault.unlock", P("password", "pw-é"))).String("state"), "vault.unlock par le pipe");
                        Check.Eq("unlocked", R(admin.Call("daemon.status", null)).String("vault"), "daemon.status : unlocked");
                    }
                    Check.True(d.Out.Snapshot().Contains("coffre déverrouillé"), "log de déverrouillage");
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("api.anthropic.com", 443)), "MITM actif après vault.unlock, sans redémarrage (aucun contact amont)");
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre : " + d.Err.Snapshot());
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Daemon_PipeUnlockCancelsConsolePrompt()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                RunLive(new ScriptedConsoleInput("bon", "bon"), data);
                TestEndpoints t = WriteTestConfig(data);
                ScriptedConsoleInput console = new ScriptedConsoleInput();
                console.BlockWhenExhausted = true;
                LiveDaemon d = StartDaemon(console, "--foreground", "--data", data);
                try
                {
                    Check.True(WaitFor(delegate { return console.PromptCount >= 1; }, 15000), "invite console affichée");
                    using (AdminClient admin = AdminClient.Connect(t.Pipe, SelfPath(), TimeSpan.FromSeconds(5)))
                        admin.Call("vault.unlock", P("password", "bon"));
                    Check.True(WaitFor(delegate { return d.Out.Snapshot().Contains("invite console abandonnée"); }, 5000), "invite annulée proprement : " + d.Out.Snapshot());
                    Check.True(!d.Exit.IsCompleted, "le daemon continue");
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Daemon_PipeInUse_Exit3()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                TestEndpoints t = WriteTestConfig(data);
                using (AdminServer squatter = new AdminServer(t.Pipe, delegate(byte[] request) { return Task.FromResult(new byte[0]); }))
                {
                    squatter.Start();
                    LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                    Check.Eq(ExitCodes.Port, d.WaitExit(), "pipe déjà existant → 3");
                    Check.True(d.Err.Snapshot().Contains("existe déjà") && d.Err.Snapshot().Contains(t.Pipe), "message : " + d.Err.Snapshot());
                }
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Daemon_SsePortInUse_Exit3()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                TestEndpoints t = WriteTestConfig(data);
                TcpListener squatter = new TcpListener(IPAddress.Loopback, t.Events);
                squatter.Start();
                try
                {
                    LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                    Check.Eq(ExitCodes.Port, d.WaitExit(), "port SSE occupé → 3");
                    string err = d.Err.Snapshot();
                    Check.True(err.Contains(t.Events.ToString()) && err.Contains("déjà utilisé") && err.Contains("flux d'events"), "message : " + err);
                }
                finally { squatter.Stop(); }
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Daemon_HotRulesViaPipe()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                TestEndpoints t = WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                try
                {
                    Check.True(WaitReady(d), "prêt : " + d.Err.Snapshot());
                    Check.True(d.Out.Snapshot().Contains("coffre ouvert"), "--in-memory-secrets : coffre ouvert d'emblée");
                    int closed = FreePort();
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                        Check.Eq(502, Wait(c.ConnectTunnelAsync("localhost", closed)), "hors whitelist : tunnel vers un port fermé → 502");
                    using (AdminClient admin = AdminClient.Connect(t.Pipe, SelfPath(), TimeSpan.FromSeconds(5)))
                    {
                        Check.Eq("localhost", R(admin.Call("rule.add", P("host", "localhost"))).String("host"), "rule.add");
                        JsonObject set = R(admin.Call("config.set", P("updates", new object[] { P("key", "security.on_exfil_attempt", "value", "block_notify_pause") })));
                        Check.Eq("security.on_exfil_attempt", string.Join(",", set.StringArray("applied")), "config.set à chaud");
                        Check.Eq("block_notify_pause", R(admin.Call("config.get", null)).Object("security").String("on_exfil_attempt"), "config.get");
                    }
                    using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                        Check.Eq(200, Wait(c.ConnectTunnelAsync("localhost", closed)), "whitelisté à chaud : MITM (200 avant tout contact amont)");
                    Check.True(d.Out.Snapshot().Contains("whitelist MITM mise à jour") && d.Out.Snapshot().Contains("sécurité mise à jour"), "application à chaud journalisée");
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre");
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Daemon_StopWithIdlePipeClient()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                TestEndpoints t = WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.True(WaitReady(d), "prêt");
                AdminClient idle = AdminClient.Connect(t.Pipe, SelfPath(), TimeSpan.FromSeconds(5));
                try
                {
                    Stopwatch watch = Stopwatch.StartNew();
                    d.Cts.Cancel();
                    Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt malgré un client du pipe inactif");
                    Check.True(watch.Elapsed < TimeSpan.FromSeconds(10), "en moins de 10 s (" + watch.ElapsedMilliseconds + " ms)");
                }
                finally { idle.Dispose(); }
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Security_NoValueOrPasswordAnywhere()
        {
            const string password = "PW-maître-SECRET-77";
            const string value = "sk-live-VALUE-0042";
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                RunLive(new ScriptedConsoleInput(password, password), data);
                TestEndpoints t = WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--locked", "--log-level", "trace");
                StringBuilder seen = new StringBuilder();
                try
                {
                    Check.True(WaitReady(d), "prêt");
                    using (EventsClient sse = Wait(EventsClient.ConnectAsync(t.Events, null, TimeSpan.FromSeconds(10))))
                    using (AdminClient admin = AdminClient.Connect(t.Pipe, SelfPath(), TimeSpan.FromSeconds(5)))
                    {
                        seen.Append(Json.EmitCompact(admin.Call("vault.unlock", P("password", password))));
                        seen.Append(Json.EmitCompact(admin.Call("secret.add", P("name", "leak_probe", "allowed_hosts", new[] { "api.anthropic.com" }, "value", B64(value)))));
                        seen.Append(Json.EmitCompact(admin.Call("secret.list", null)));
                        seen.Append(Json.EmitCompact(admin.Call("secret.get", P("name", "leak_probe"))));
                        seen.Append(Json.EmitCompact(admin.Call("daemon.status", null)));
                        try { admin.Call("secret.add", P("name", "leak_probe", "allowed_hosts", new[] { "x.example" }, "value", B64(value))); }
                        catch (RpcException ex) { seen.Append(ex.Message); }
                        using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                            Wait(c.ConnectTunnelAsync("api.anthropic.com", 443));
                        SseMessage m = NextEvent(sse);
                        if (m != null) seen.Append(m.Data);
                        seen.Append(Json.EmitCompact(admin.Call("events.query", P("since", Json.FormatDate(DateTime.UtcNow.AddHours(-1))))));
                    }
                }
                finally { d.Cts.Cancel(); }
                Check.Eq(ExitCodes.Ok, d.WaitExit(), "arrêt propre");
                string all = d.Out.Snapshot() + d.Err.Snapshot() + seen;
                Check.True(all.Contains("leak_probe"), "le nom du secret apparaît (sanity)");
                Check.True(!all.Contains(value) && !all.Contains(B64(value)), "aucune valeur dans les logs, réponses, erreurs ni le flux SSE");
                Check.True(!all.Contains(password), "aucun mot de passe maître");
                foreach (string f in Directory.GetFiles(data, "*", SearchOption.AllDirectories))
                {
                    string text = Encoding.UTF8.GetString(File.ReadAllBytes(f));
                    Check.True(!text.Contains(value) && !text.Contains(password), "fichier sans valeur ni mot de passe : " + Path.GetFileName(f));
                }
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }
    }
}
