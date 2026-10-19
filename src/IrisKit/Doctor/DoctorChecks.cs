using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IrisKit
{
    public enum DoctorSeverity { Ok, Warn, Fail }

    public sealed class DoctorResult
    {
        public string Name { get; private set; }
        public DoctorSeverity Severity { get; private set; }
        public string Detail { get; private set; }

        public DoctorResult(string name, DoctorSeverity severity, string detail)
        {
            Name = name;
            Severity = severity;
            Detail = detail;
        }

        public static string SeverityWire(DoctorSeverity s)
        {
            return s == DoctorSeverity.Ok ? "ok" : s == DoctorSeverity.Warn ? "warn" : "fail";
        }

        public OrderedDictionary ToJson()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["name"] = Name;
            o["severity"] = SeverityWire(Severity);
            o["detail"] = Detail;
            return o;
        }
    }

    /// <summary>
    /// Contrôles de `iris doctor` (SPECS §16, spec phase 5 §7), sans pipe : la CLI leur passe ce qu'elle a lu du daemon ; environnement,
    /// profil, magasins et processus sont injectés pour les tests. Noms identiques à IRIS quand le contrôle y existe.
    /// </summary>
    public static class DoctorChecks
    {
        private static DoctorResult Ok(string name, string detail) { return new DoctorResult(name, DoctorSeverity.Ok, detail); }
        private static DoctorResult Warn(string name, string detail) { return new DoctorResult(name, DoctorSeverity.Warn, detail); }
        private static DoctorResult Fail(string name, string detail) { return new DoctorResult(name, DoctorSeverity.Fail, detail); }

        public static DoctorResult AdminPipe(string pipeName, string error)
        {
            if (error == null) return Ok("admin-pipe", "\\\\.\\pipe\\" + pipeName);
            return Fail("admin-pipe", error);
        }

        public static DoctorResult DaemonAlive(long pid, long uptimeS, Func<int, bool> isAlive)
        {
            string detail = "pid=" + pid + " uptime_s=" + uptimeS;
            return isAlive((int)pid) ? Ok("daemon-alive", detail) : Fail("daemon-alive", detail + " : processus introuvable");
        }

        public static bool IsProcessAlive(int pid)
        {
            try
            {
                using (Process p = Process.GetProcessById(pid)) return !p.HasExited;
            }
            catch (ArgumentException) { return false; }
            catch (InvalidOperationException) { return false; }
        }

        public static DoctorResult VaultUnlocked(string state)
        {
            if (state == "unlocked") return Ok("vault-unlocked", "coffre déverrouillé, MITM actif");
            if (state == "absent") return Fail("vault-unlocked", "aucun coffre : iris vault create");
            return Fail("vault-unlocked", "MITM inactif : iris vault unlock");
        }

        public static DoctorResult CaCertPresent(string pemPath)
        {
            if (string.IsNullOrEmpty(pemPath)) return Fail("ca-cert-present", "ca.pem absent : déverrouillez ou créez le coffre");
            return File.Exists(pemPath) ? Ok("ca-cert-present", pemPath) : Fail("ca-cert-present", "absent : " + pemPath);
        }

        /// <summary>Empreinte calculée localement depuis ca.pem (fichier public) : répond même coffre verrouillé.</summary>
        public static DoctorResult CaTrusted(string pemPath, Func<string, bool> isTrusted)
        {
            try
            {
                using (X509Certificate2 cert = new X509Certificate2(pemPath))
                {
                    if (isTrusted(cert.Thumbprint)) return Ok("ca-trusted", "dans les autorités racines de confiance");
                    return Fail("ca-trusted", "non approuvé : importez " + pemPath + " dans les autorités de certification racines de confiance de l'utilisateur (certmgr.msc)");
                }
            }
            catch (CryptographicException ex) { return Fail("ca-trusted", "certificat illisible : " + ex.Message); }
        }

        public static DoctorResult ShellEnvVars(IDictionary<string, string> env, string brokerListen, string pemPath)
        {
            string expectedProxy = "http://" + brokerListen;
            List<string> missing = new List<string>();
            List<string> wrong = new List<string>();
            string proxy = Get(env, "HTTPS_PROXY");
            if (proxy == null) missing.Add("HTTPS_PROXY");
            else if (!string.Equals(proxy.TrimEnd('/'), expectedProxy, StringComparison.OrdinalIgnoreCase))
                wrong.Add("HTTPS_PROXY = " + proxy + " (attendu " + expectedProxy + ")");
            string ca = Get(env, "NODE_EXTRA_CA_CERTS");
            if (ca == null) missing.Add("NODE_EXTRA_CA_CERTS");
            else if (!string.IsNullOrEmpty(pemPath) && !SamePath(ca, pemPath))
                wrong.Add("NODE_EXTRA_CA_CERTS = " + ca + " (attendu " + pemPath + ")");
            if (missing.Count == 0 && wrong.Count == 0) return Ok("shell-env-vars", "HTTPS_PROXY et NODE_EXTRA_CA_CERTS définies");
            List<string> parts = new List<string>();
            if (missing.Count > 0) parts.Add("absentes : " + string.Join(",", missing));
            parts.AddRange(wrong);
            return Warn("shell-env-vars", string.Join(" ; ", parts));
        }

        private static string Get(IDictionary<string, string> env, string key)
        {
            string value;
            if (env == null || !env.TryGetValue(key, out value) || string.IsNullOrEmpty(value)) return null;
            return value;
        }

        private static bool SamePath(string a, string b)
        {
            try { return string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase); }
            catch (ArgumentException) { return false; }
            catch (NotSupportedException) { return false; }
        }

        /// <summary>`GET /__iris_ping` en TCP brut (ni proxy système ni HTTPS_PROXY) ; attendu `200` et corps `ok\n`.</summary>
        public static DoctorResult ProxyPing(string brokerListen, TimeSpan timeout)
        {
            const string name = "proxy-ping";
            int colon = brokerListen.LastIndexOf(':');
            int port;
            if (colon <= 0 || !int.TryParse(brokerListen.Substring(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port <= 0 || port > 65535)
                return Fail(name, "broker.listen invalide : " + brokerListen);
            string host = brokerListen.Substring(0, colon);
            try
            {
                using (TcpClient tcp = new TcpClient())
                {
                    if (!tcp.ConnectAsync(host, port).Wait(timeout)) return Fail(name, "pas de réponse de " + brokerListen + " en " + (int)timeout.TotalMilliseconds + " ms");
                    tcp.ReceiveTimeout = (int)timeout.TotalMilliseconds;
                    tcp.SendTimeout = (int)timeout.TotalMilliseconds;
                    NetworkStream s = tcp.GetStream();
                    byte[] request = Encoding.ASCII.GetBytes("GET /__iris_ping HTTP/1.1\r\nHost: " + brokerListen + "\r\nConnection: close\r\n\r\n");
                    s.Write(request, 0, request.Length);
                    MemoryStream response = new MemoryStream();
                    byte[] buffer = new byte[1024];
                    int n;
                    while (response.Length < 8192 && (n = s.Read(buffer, 0, buffer.Length)) > 0) response.Write(buffer, 0, n);
                    string text = Encoding.ASCII.GetString(response.ToArray());
                    if (text.StartsWith("HTTP/1.1 200", StringComparison.Ordinal) && text.EndsWith("\r\n\r\nok\n", StringComparison.Ordinal)) return Ok(name, "200 ok");
                    int eol = text.IndexOf('\r');
                    return Fail(name, "réponse inattendue : " + (eol > 0 ? text.Substring(0, eol) : text));
                }
            }
            catch (AggregateException ex) { return Fail(name, brokerListen + " injoignable : " + ex.InnerException.Message); }
            catch (SocketException ex) { return Fail(name, brokerListen + " injoignable : " + ex.Message); }
            catch (IOException ex) { return Fail(name, brokerListen + " : " + ex.Message); }
        }

        /// <summary>`apiKeyHelper` dans %USERPROFILE%\.claude\settings.json est incompatible avec iris (SPECS Annexe A.11).</summary>
        public static DoctorResult ClaudeApiKeyHelper(string userProfile)
        {
            const string name = "claude-apikeyhelper-absent";
            string path = Path.Combine(userProfile, ".claude", "settings.json");
            if (!File.Exists(path)) return Ok(name, "pas de " + path);
            try
            {
                OrderedJsonDocument doc = OrderedJsonParser.Parse(File.ReadAllText(path, Encoding.UTF8), true);
                if (doc.Root.IsObject && doc.Root.Get("apiKeyHelper") != null)
                    return Fail(name, "apiKeyHelper défini dans " + path + " : incompatible avec iris (SPECS Annexe A.11)");
                return Ok(name, "apiKeyHelper absent");
            }
            catch (OrderedJsonException ex) { return Warn(name, path + " illisible : " + ex.Message); }
            catch (IOException ex) { return Warn(name, path + " illisible : " + ex.Message); }
            catch (UnauthorizedAccessException ex) { return Warn(name, path + " illisible : " + ex.Message); }
        }
    }
}
