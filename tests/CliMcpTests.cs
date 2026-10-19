using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- iris mcp wrap / unwrap / --watch (spec phase 5 §6.2 à §6.4) ----------------------

        private static int Count(string text, string part)
        {
            int n = 0;
            for (int i = text.IndexOf(part, StringComparison.Ordinal); i >= 0; i = text.IndexOf(part, i + part.Length, StringComparison.Ordinal)) n++;
            return n;
        }

        private static void Cli_McpWrapUnwrap()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                string path = Path.Combine(d.Dir, ".mcp.json");
                File.WriteAllText(path, McpSample);
                CliRun r = RunIris(d.Data, "mcp", "wrap", path);
                Check.True(r.Code == 0 && r.Out.Contains("patché : " + path) && r.Out.Contains(".iris.bak"), "wrap : " + r.All);
                OrderedJsonValue env = OrderedJsonParser.Parse(File.ReadAllText(path), false).Root.Get("mcpServers").Get("gh").Get("env");
                Check.Eq("http://127.0.0.1:" + d.T.Proxy, env.Get("HTTPS_PROXY").Text, "proxy du daemon");
                Check.Eq(Path.Combine(d.Data, "ca.pem"), env.Get("NODE_EXTRA_CA_CERTS").Text, "ca.pem du daemon");
                Check.True(File.ReadAllText(Path.Combine(d.Data, "wrapped-paths.json")).Contains(".mcp.json"), "registre mis à jour");
                r = RunIris(d.Data, "mcp", "wrap", path);
                Check.True(r.Code == 0 && r.Out.Trim() == "déjà conforme : " + path, "second wrap : " + r.All);
                r = RunIris(d.Data, "mcp", "wrap", path, "--json");
                JsonObject summary = Json.ParseObject(r.Out);
                Check.True(summary.Int("patched") == 0 && summary.Int("already_compliant") == 1 && summary.Int("skipped") == 0 && summary.Int("errors") == 0, "--json : " + r.Out);

                string fresh = Path.Combine(d.Dir, "frais.json");
                File.WriteAllText(fresh, McpSample);
                r = RunIris(d.Data, "mcp", "wrap", fresh, "--dry-run");
                Check.True(r.Code == 0 && r.Out.Contains("+ mcpServers.gh.env.CURL_CA_BUNDLE = ") && File.ReadAllText(fresh) == McpSample, "--dry-run : diff sémantique, rien d'écrit : " + r.Out);

                Check.Eq(1, RunIris(d.Data, "mcp", "wrap", path + ".iris.bak").Code, "wrap d'un backup → 1");
                Check.Eq(1, RunIris(d.Data, "mcp", "wrap", Path.Combine(d.Dir, "absent.json")).Code, "fichier absent → 1");
                Check.Eq(64, RunIris(d.Data, "mcp", "wrap", path, "--watch", "--dry-run").Code, "--watch et --dry-run → 64");
                Check.Eq(64, RunIris(d.Data, "mcp", "wrap", path, "--log-level", "debug").Code, "--log-level sans --watch → 64");
                File.WriteAllText(fresh, "{\n  // c\n  \"mcpServers\": {}\n}\n");
                r = RunIris(d.Data, "mcp", "wrap", fresh);
                Check.True(r.Code == 1 && r.Err.Contains("commentaires détectés en L2:3"), "commentaires → 1 : " + r.All);

                r = RunIris(d.Data, "mcp", "unwrap", path);
                Check.True(r.Code == 0 && r.Out.Trim() == "restauré : " + path && File.ReadAllText(path) == McpSample, "unwrap : " + r.All);
                Check.True(!File.ReadAllText(Path.Combine(d.Data, "wrapped-paths.json")).Contains(".mcp.json"), "retiré du registre");
                Check.Eq(1, RunIris(d.Data, "mcp", "unwrap", path).Code, "unwrap sans backup → 1");
            }
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                WriteTestConfig(data);
                string path = Path.Combine(dir, ".mcp.json");
                File.WriteAllText(path, McpSample);
                CliContext c = CliCtx(data);
                c.ConnectTimeout = TimeSpan.FromMilliseconds(300);
                Check.Eq(2, RunIris(c, "mcp", "wrap", path).Code, "daemon injoignable → 2");
                Check.Eq(McpSample, File.ReadAllText(path), "rien d'écrit sans daemon");
            }
            finally { TestDir.Delete(dir); }
        }

        /// <summary>Review Focus 5 : chemin avec espaces et accents, donné avec ~.</summary>
        private static void Cli_McpWrapPathWithSpacesAndAccents()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliContext probe = CliCtx(d.Data);
                string folder = Path.Combine(probe.UserProfile, "Mes Projets é");
                Directory.CreateDirectory(folder);
                string path = Path.Combine(folder, ".mcp.json");
                File.WriteAllText(path, McpSample);
                CliRun r = RunIris(d.Data, "mcp", "wrap", "~\\Mes Projets é\\.mcp.json");
                Check.True(r.Code == 0 && File.ReadAllText(path).Contains("HTTPS_PROXY"), "wrap via ~ : " + r.All);
                r = RunIris(d.Data, "mcp", "unwrap", "~\\Mes Projets é\\.mcp.json");
                Check.True(r.Code == 0 && File.ReadAllText(path) == McpSample, "unwrap via ~ : " + r.All);
            }
        }

        private static void Cli_McpWatch()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                string path = Path.Combine(d.Dir, ".mcp.json");
                File.WriteAllText(path, McpSample);
                CancellationTokenSource cts = new CancellationTokenSource();
                CliContext c = CliCtx(d.Data);
                c.Cancel = cts.Token;
                Task<int> watch = Task.Run(delegate { return Cli.Run(new[] { "mcp", "wrap", path, "--watch", "--log-level", "debug" }, c); });
                Check.True(WaitFor(delegate { return File.ReadAllText(path).Contains("HTTPS_PROXY"); }, 10000), "premier cycle : patché : " + c.Err);
                File.WriteAllText(path, "{\"mcpServers\": {\"gh\": {\"command\": \"npx\"}, \"late\": {\"command\": \"uvx\"}}}\n");
                Check.True(WaitFor(delegate { return Count(File.ReadAllText(path), "NODE_EXTRA_CA_CERTS") == 2; }, 10000), "modification externe : re-patché : " + c.Err);
                Wait(Task.Delay(1500));
                Check.Eq(2, Count(c.Err.ToString(), " patché "), "écriture d'iris ignorée (pas de boucle) : " + c.Err);

                d.Stop();
                File.WriteAllText(path, "{\"mcpServers\": {\"later\": {\"command\": \"x\"}}}\n");
                Check.True(WaitFor(delegate { return c.Err.ToString().Contains("daemon injoignable"); }, 10000), "daemon arrêté : avertissement, la surveillance continue : " + c.Err);
                Check.True(!watch.IsCompleted, "la surveillance survit à l'arrêt du daemon");
                d.Restart();
                File.WriteAllText(path, "{\"mcpServers\": {\"later\": {\"command\": \"x\"}, \"later2\": {\"command\": \"y\"}}}\n");
                Check.True(WaitFor(delegate { return Count(File.ReadAllText(path), "NODE_EXTRA_CA_CERTS") == 2; }, 10000), "daemon relancé : re-patché : " + c.Err);

                cts.Cancel();
                Check.True(watch.Wait(TimeSpan.FromSeconds(5)) && watch.Result == 0, "annulation → 0");
                Check.True(c.Err.ToString().Contains("arrêt de la surveillance"), "message d'arrêt");
            }
        }
    }
}
