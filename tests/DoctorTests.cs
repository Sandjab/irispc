using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- iris doctor (SPECS §16, spec phase 5 §7) -----------------------------------------

        private static Dictionary<string, string> Env(params string[] kv)
        {
            Dictionary<string, string> env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < kv.Length; i += 2) env[kv[i]] = kv[i + 1];
            return env;
        }

        private static void Doctor_PureChecks()
        {
            Check.True(DoctorChecks.AdminPipe("p", null).Severity == DoctorSeverity.Ok && DoctorChecks.AdminPipe("p", null).Detail.Contains("\\\\.\\pipe\\p"), "admin-pipe ok");
            Check.Eq(DoctorSeverity.Fail, DoctorChecks.AdminPipe("p", "absent").Severity, "admin-pipe fail");
            Check.Eq(DoctorSeverity.Ok, DoctorChecks.DaemonAlive(42, 330, delegate(int pid) { return pid == 42; }).Severity, "daemon-alive ok");
            Check.Eq(DoctorSeverity.Fail, DoctorChecks.DaemonAlive(42, 330, delegate(int pid) { return false; }).Severity, "daemon-alive fail");
            Check.True(DoctorChecks.IsProcessAlive(System.Diagnostics.Process.GetCurrentProcess().Id), "IsProcessAlive : ce processus");
            Check.Eq(DoctorSeverity.Ok, DoctorChecks.VaultUnlocked("unlocked").Severity, "vault ok");
            DoctorResult locked = DoctorChecks.VaultUnlocked("locked");
            Check.True(locked.Severity == DoctorSeverity.Fail && locked.Detail.Contains("iris vault unlock"), "vault locked : " + locked.Detail);
            Check.True(DoctorChecks.VaultUnlocked("absent").Detail.Contains("iris vault create"), "vault absent");
            Check.Eq(DoctorSeverity.Fail, DoctorChecks.CaCertPresent("").Severity, "CA absent (chemin vide)");
            Check.Eq(DoctorSeverity.Fail, DoctorChecks.CaCertPresent("C:\\absent\\ca.pem").Severity, "CA absent (fichier)");

            string listen = "127.0.0.1:8888";
            string pem = "D:\\x\\data\\ca.pem";
            DoctorResult env = DoctorChecks.ShellEnvVars(Env(), listen, pem);
            Check.True(env.Severity == DoctorSeverity.Warn && env.Detail.Contains("HTTPS_PROXY") && env.Detail.Contains("NODE_EXTRA_CA_CERTS"), "variables absentes : warn : " + env.Detail);
            Check.Eq(DoctorSeverity.Ok, DoctorChecks.ShellEnvVars(Env("https_proxy", "HTTP://127.0.0.1:8888/", "NODE_EXTRA_CA_CERTS", "d:\\X\\data\\ca.pem"), listen, pem).Severity, "valeurs correctes (casse, / final)");
            env = DoctorChecks.ShellEnvVars(Env("HTTPS_PROXY", "http://autre:3128", "NODE_EXTRA_CA_CERTS", pem), listen, pem);
            Check.True(env.Severity == DoctorSeverity.Warn && env.Detail.Contains("attendu http://127.0.0.1:8888"), "valeur divergente : warn : " + env.Detail);

            string dir = TestDir.Create();
            try
            {
                Check.Eq(DoctorSeverity.Ok, DoctorChecks.ClaudeApiKeyHelper(dir).Severity, "pas de settings.json : ok");
                string settings = Path.Combine(dir, ".claude", "settings.json");
                Directory.CreateDirectory(Path.GetDirectoryName(settings));
                File.WriteAllText(settings, "{\n  // commentaire\n  \"model\": \"x\",\n}\n");
                Check.Eq(DoctorSeverity.Ok, DoctorChecks.ClaudeApiKeyHelper(dir).Severity, "JSONC sans apiKeyHelper : ok");
                File.WriteAllText(settings, "{\"apiKeyHelper\": \"/bin/key\"}");
                DoctorResult helper = DoctorChecks.ClaudeApiKeyHelper(dir);
                Check.True(helper.Severity == DoctorSeverity.Fail && helper.Detail.Contains("A.11"), "apiKeyHelper : fail : " + helper.Detail);
                File.WriteAllText(settings, "{ cassé");
                Check.Eq(DoctorSeverity.Warn, DoctorChecks.ClaudeApiKeyHelper(dir).Severity, "settings.json illisible : warn");
            }
            finally { TestDir.Delete(dir); }

            Check.Eq(DoctorSeverity.Fail, DoctorChecks.ProxyPing("pas-un-listen", TimeSpan.FromSeconds(1)).Severity, "listen invalide");
            Check.Eq(DoctorSeverity.Fail, DoctorChecks.ProxyPing("127.0.0.1:" + FreePort(), TimeSpan.FromSeconds(1)).Severity, "port fermé");
            TcpListener liar = new TcpListener(IPAddress.Loopback, 0);
            liar.Start();
            try
            {
                Task.Run(delegate
                {
                    using (TcpClient client = liar.AcceptTcpClient())
                    {
                        // Lire la requête avant de répondre : fermer avec des octets non lus provoque un RST sous Windows,
                        // qui peut faire perdre la réponse au client (le test mesurerait alors le reset, pas le 404).
                        NetworkStream ns = client.GetStream();
                        StringBuilder seen = new StringBuilder();
                        byte[] buf = new byte[1024];
                        int got;
                        while (seen.ToString().IndexOf("\r\n\r\n", StringComparison.Ordinal) < 0 && (got = ns.Read(buf, 0, buf.Length)) > 0)
                            seen.Append(Encoding.ASCII.GetString(buf, 0, got));
                        byte[] answer = Encoding.ASCII.GetBytes("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                        ns.Write(answer, 0, answer.Length);
                    }
                });
                DoctorResult ping = DoctorChecks.ProxyPing("127.0.0.1:" + ((IPEndPoint)liar.LocalEndpoint).Port, TimeSpan.FromSeconds(2));
                Check.True(ping.Severity == DoctorSeverity.Fail && ping.Detail.Contains("404"), "réponse inattendue : fail : " + ping.Detail);
            }
            finally { liar.Stop(); }
            Check.True(DoctorChecks.AdminPipe("p", null).ToJson().Contains("severity"), "ToJson");
        }

        private static void Cli_Doctor()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                string pem = Path.Combine(d.Data, "ca.pem");
                List<string> thumbprints = new List<string>();
                CliContext c = CliCtx(d.Data);
                c.EnvironmentVariables = Env("HTTPS_PROXY", "http://127.0.0.1:" + d.T.Proxy, "NODE_EXTRA_CA_CERTS", pem);
                c.IsCaTrusted = delegate(string thumbprint) { thumbprints.Add(thumbprint); return true; };
                CliRun r = RunIris(c, "doctor");
                Check.True(r.Code == 0, "tout ok → 0 : " + r.All);
                foreach (string name in new[] { "admin-pipe", "daemon-alive", "vault-unlocked", "ca-cert-present", "ca-trusted", "shell-env-vars", "proxy-ping", "claude-apikeyhelper-absent" })
                    Check.True(r.Out.Contains("[ok]") && r.Out.Contains(name), "contrôle présent : " + name);
                Check.True(thumbprints.Count == 1 && thumbprints[0].Length == 40, "empreinte SHA-1 du ca.pem passée au magasin");
                c = CliCtx(d.Data);
                c.EnvironmentVariables = Env();
                c.IsCaTrusted = delegate(string thumbprint) { return false; };
                r = RunIris(c, "doctor", "--json");
                IList<object> results = (IList<object>)Json.Parse(r.Out);
                JsonObject trusted = new JsonObject((IDictionary<string, object>)results[4]);
                JsonObject envVars = new JsonObject((IDictionary<string, object>)results[5]);
                Check.True(r.Code == 1 && results.Count == 8, "un fail → 1, huit résultats : " + r.Out);
                Check.True(trusted.String("name") == "ca-trusted" && trusted.String("severity") == "fail", "ca-trusted fail");
                Check.True(envVars.String("name") == "shell-env-vars" && envVars.String("severity") == "warn", "variables absentes : warn (n'échoue pas seul)");
            }
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                WriteTestConfig(data);
                CliContext c = CliCtx(data);
                c.ConnectTimeout = TimeSpan.FromMilliseconds(300);
                CliRun r = RunIris(c, "doctor");
                Check.True(r.Code == 2 && r.Out.Contains("[fail]") && r.Out.Contains("admin-pipe"), "sans daemon → 2, admin-pipe en échec : " + r.All);
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
