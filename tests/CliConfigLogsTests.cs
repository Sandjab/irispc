using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- iris config / iris ca / iris logs (spec phase 5 §4, §5) ------------------------

        /// <summary>Produit un event `error` : tunnel CONNECT vers un port local fermé (502), sans réseau externe.</summary>
        private static void EmitTunnelError(TestEndpoints t)
        {
            using (TestProxyClient c = Wait(TestProxyClient.ConnectAsync(t.Proxy)))
                Check.Eq(502, Wait(c.ConnectTunnelAsync("127.0.0.1", FreePort())), "tunnel vers un port fermé : 502");
        }

        private static void RelativeTime_Parse()
        {
            DateTime now = new DateTime(2026, 10, 18, 12, 0, 0, DateTimeKind.Utc);
            Check.Eq(now.AddSeconds(-30), RelativeTime.Parse("30s", now), "30s");
            Check.Eq(now.AddMinutes(-5), RelativeTime.Parse("5m", now), "5m");
            Check.Eq(now.AddHours(-1), RelativeTime.Parse("1h", now), "1h");
            Check.Eq(now.AddDays(-2), RelativeTime.Parse("2d", now), "2d");
            Check.Eq(new DateTime(2026, 10, 18, 7, 0, 0, DateTimeKind.Utc), RelativeTime.Parse("2026-10-18T07:00:00Z", now), "ISO-8601");
            foreach (string bad in new[] { "5x", "", "-5m", "1.5h", "m5", "demain" })
                Check.Throws<UsageException>(delegate { RelativeTime.Parse(bad, now); }, "refusé : " + bad);
        }

        private static void Cli_ConfigGetSetReload()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliRun r = RunIris(d.Data, "config", "get");
                Check.True(r.Code == 0 && r.Out.Contains("[broker]") && r.Out.Contains("admin_pipe = \"" + d.T.Pipe + "\"") && r.Out.Contains("[[hosts]]") && r.Out.Contains("host = \"api.anthropic.com\""), "config get lisible : " + r.Out);
                r = RunIris(d.Data, "config", "get", "--json");
                Check.Eq(d.T.Pipe, Json.ParseObject(r.Out).Object("broker").String("admin_pipe"), "config get --json");
                r = RunIris(d.Data, "config", "set", "security.max_substitutions_per_minute", "30");
                Check.True(r.Code == 0 && r.Out.Contains("appliqué : security.max_substitutions_per_minute"), "set à chaud : " + r.All);
                r = RunIris(d.Data, "config", "reload");
                Check.True(r.Code == 0 && r.Out.Trim() == "configuration rechargée" && r.Err.Length == 0, "reload sans changement : " + r.All);
                r = RunIris(d.Data, "config", "set", "broker.log_level", "debug");
                Check.True(r.Code == 0 && r.Out.Contains("redémarrage requis : broker.log_level"), "set structurel : " + r.All);
                r = RunIris(d.Data, "config", "set", "bogus.key", "1");
                Check.True(r.Code == 1 && r.Err.StartsWith("erreur : "), "clé inconnue → 1 : " + r.All);
                Check.Eq(64, RunIris(d.Data, "config", "set", "security.max_substitutions_per_minute").Code, "valeur manquante → 64");
                string path = Path.Combine(d.Data, "config.json");
                File.WriteAllText(path, File.ReadAllText(path).Replace("127.0.0.1:" + d.T.Proxy, "127.0.0.1:" + FreePort()));
                r = RunIris(d.Data, "config", "reload");
                Check.True(r.Code == 0 && r.Err.Contains("avertissement") && r.Err.Contains("broker.listen"), "reload : clé structurelle ignorée signalée : " + r.All);
            }
        }

        private static void Cli_Ca()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                string pem = Path.Combine(d.Data, "ca.pem");
                CliRun r = RunIris(d.Data, "ca", "export");
                Check.True(r.Code == 0 && string.Equals(r.Out.Trim(), pem, StringComparison.OrdinalIgnoreCase), "ca export : chemin : " + r.Out);
                Check.Eq(pem, Json.ParseObject(RunIris(d.Data, "ca", "export", "--json").Out).String("path"), "ca export --json");
                r = RunIris(d.Data, "ca", "export", "--print");
                Check.True(r.Code == 0 && r.Out.StartsWith("-----BEGIN CERTIFICATE-----"), "ca export --print");
                string dest = Path.Combine(d.Dir, "copie.pem");
                r = RunIris(d.Data, "ca", "export", "--path", dest);
                Check.True(r.Code == 0 && File.ReadAllText(dest) == File.ReadAllText(pem), "ca export --path : " + r.All);
                r = RunIris(d.Data, "ca", "export", "--path", Path.Combine(d.Dir, "absent", "x.pem"));
                Check.True(r.Code == 3 && r.Err.Contains("copie"), "copie impossible → 3 : " + r.All);
                Check.Eq(64, RunIris(d.Data, "ca", "export", "--path", dest, "--print").Code, "--path et --print → 64");
                r = RunIris(d.Data, "ca", "fingerprint");
                Check.True(r.Code == 0 && r.Out.StartsWith("sha256 : "), "ca fingerprint : " + r.Out);
                Check.True(Json.ParseObject(RunIris(d.Data, "ca", "fingerprint", "--json").Out).Has("sha256"), "ca fingerprint --json");
                r = RunIris(d.Data, "ca", "is-trusted");
                Check.True(r.Code == 1 && r.Out.Trim() == "non approuvé", "CA de test non approuvé → 1 : " + r.All);
            }
        }

        private static void Cli_LogsOneShot()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                EmitTunnelError(d.T);
                Check.True(WaitFor(delegate { return RunIris(d.Data, "logs").Out.Contains("error"); }, 5000), "event visible");
                CliRun r = RunIris(d.Data, "logs");
                Check.True(r.Code == 0 && r.Out.Contains("  error  127.0.0.1  CONNECT 127.0.0.1:") && r.Out.Contains("sub=- dur="), "ligne d'event : " + r.Out);
                r = RunIris(d.Data, "logs", "--kind", "error", "--json");
                IList<object> events = (IList<object>)Json.Parse(r.Out);
                Check.True(r.Code == 0 && events.Count >= 1, "logs --json");
                foreach (object e in events) Check.Eq("error", new JsonObject((IDictionary<string, object>)e).String("kind"), "filtre kind");
                Check.True(RunIris(d.Data, "logs", "--since", "5m", "--host", "127.0.0.1").Out.Contains("127.0.0.1"), "--since relatif et --host");
                Check.Eq("aucun event", RunIris(d.Data, "logs", "--until", "2000-01-01T00:00:00Z").Out.Trim(), "--until passé : aucun event");
                Check.Eq("aucun event", RunIris(d.Data, "logs", "--kind", "substituted").Out.Trim(), "kind sans event");
                Check.Eq(64, RunIris(d.Data, "logs", "--kind", "bogus").Code, "kind inconnu → 64");
                Check.Eq(64, RunIris(d.Data, "logs", "--limit", "0").Code, "--limit 0 → 64");
                Check.Eq(64, RunIris(d.Data, "logs", "--since", "hier").Code, "--since invalide → 64");
                Check.Eq(64, RunIris(d.Data, "logs", "--follow", "--since", "5m").Code, "--follow et --since → 64");
            }
        }

        private static void Cli_LogsFollow()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CancellationTokenSource cts = new CancellationTokenSource();
                CliContext c = CliCtx(d.Data);
                c.Cancel = cts.Token;
                Task<int> follow = Task.Run(delegate { return Cli.Run(new[] { "logs", "--follow", "--kind", "error", "--json" }, c); });
                bool seen = WaitFor(delegate
                {
                    EmitTunnelError(d.T);
                    return c.Out.ToString().Contains("\"kind\":\"error\"");
                }, 10000);
                Check.True(seen, "event reçu en ndjson : " + c.Out + c.Err);
                cts.Cancel();
                Check.True(follow.Wait(TimeSpan.FromSeconds(5)) && follow.Result == 0, "Ctrl+C (annulation) → 0");
                Check.True(c.Interruptible, "commande longue marquée interruptible");
            }
        }

        /// <summary>Review Focus 4 : le daemon s'arrête pendant le suivi → code 3, sans attendre le délai de lecture.</summary>
        private static void Cli_LogsFollowEndsWhenDaemonStops()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliContext c = CliCtx(d.Data);
                Task<int> follow = Task.Run(delegate { return Cli.Run(new[] { "logs", "--follow" }, c); });
                Check.True(WaitFor(delegate
                {
                    EmitTunnelError(d.T);
                    return c.Out.ToString().Contains("error");
                }, 10000), "suivi actif : " + c.Out + c.Err);
                d.Stop();
                Check.True(follow.Wait(TimeSpan.FromSeconds(15)), "le suivi se termine à l'arrêt du daemon");
                Check.True(follow.Result == 3 && c.Err.ToString().Contains("flux d'events interrompu"), "code 3 : " + c.Err);
            }
        }
    }
}
