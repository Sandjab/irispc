using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Pipe admin (spec phase 3 §4) ----------------------------------------

        private static string TestPipeName() { return "iris-admin-test-" + Guid.NewGuid().ToString("N"); }

        /// <summary>Chemin de l'exécutable de tests : le serveur du pipe tourne dans ce processus.</summary>
        private static string SelfPath() { return Process.GetCurrentProcess().MainModule.FileName; }

        private sealed class EchoHandler
        {
            public int Calls;
            public byte[] LastRequest;
            public Task<byte[]> Handle(byte[] request)
            {
                Interlocked.Increment(ref Calls);
                LastRequest = request;
                object id;
                RpcRequest r = JsonRpc.ParseRequest(request, out id);
                OrderedDictionary result = new OrderedDictionary();
                result["method"] = r.Method;
                result["x"] = r.Params == null ? null : r.Params.Raw("x");
                return Task.FromResult(JsonRpc.Success(id, result));
            }
        }

        private static OrderedDictionary X(object value) { OrderedDictionary p = new OrderedDictionary(); p["x"] = value; return p; }

        private static void AdminPipe_RoundTripSequentialAndConcurrent()
        {
            string name = TestPipeName();
            EchoHandler echo = new EchoHandler();
            using (AdminServer server = new AdminServer(name, echo.Handle))
            {
                server.Start();
                using (AdminClient client = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5)))
                {
                    for (int i = 0; i < 3; i++)
                    {
                        IDictionary<string, object> r = (IDictionary<string, object>)client.Call("daemon.status", X((long)i));
                        Check.True((string)r["method"] == "daemon.status" && (long)r["x"] == i, "réponse " + i + " sur la même connexion");
                    }
                    Check.True(Array.TrueForAll(echo.LastRequest, delegate(byte b) { return b == 0; }), "tampon de la trame effacé après traitement");
                }
                List<Task<bool>> workers = new List<Task<bool>>();
                for (int w = 0; w < 4; w++)
                {
                    int worker = w;
                    workers.Add(Task.Run(delegate
                    {
                        using (AdminClient c = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(10)))
                            for (int i = 0; i < 10; i++)
                            {
                                IDictionary<string, object> r = (IDictionary<string, object>)c.Call("w" + worker, X((long)i));
                                if ((string)r["method"] != "w" + worker || (long)r["x"] != i) return false;
                            }
                        return true;
                    }));
                }
                foreach (Task<bool> t in workers) Check.True(Wait(t), "client concurrent servi sans mélange");
                Check.Eq(43, echo.Calls, "3 + 4 × 10 requêtes traitées");
            }
        }

        private static void AdminPipe_SecondServerRefused()
        {
            string name = TestPipeName();
            using (AdminServer first = new AdminServer(name, new EchoHandler().Handle))
            {
                first.Start();
                using (AdminServer second = new AdminServer(name, new EchoHandler().Handle))
                {
                    AdminPipeInUseException ex = Check.Throws<AdminPipeInUseException>(delegate { second.Start(); }, "second serveur sur le même nom");
                    Check.True(ex.PipeName == name && ex.Message.Contains("existe déjà"), "message : " + ex.Message);
                }
                using (AdminClient c = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5)))
                    Check.True(c.Call("ping", null) != null, "le premier serveur sert toujours");
            }
        }

        private static void AdminPipe_IdentityChecked()
        {
            string name = TestPipeName();
            EchoHandler echo = new EchoHandler();
            string dir = TestDir.Create();
            try
            {
                using (AdminServer server = new AdminServer(name, echo.Handle))
                {
                    server.Start();
                    string fake = Path.Combine(dir, "irisd.exe");
                    AdminServerIdentityException ex = Check.Throws<AdminServerIdentityException>(delegate { AdminClient.Connect(name, fake, TimeSpan.FromSeconds(5)); }, "serveur inattendu");
                    Check.True(ex.Expected == fake && string.Equals(ex.Actual, SelfPath(), StringComparison.OrdinalIgnoreCase), "attendu et réel cités");
                    Check.Eq(0, echo.Calls, "rien n'a été envoyé au serveur refusé");
                    using (AdminClient ok = AdminClient.Connect(name, SelfPath().ToUpperInvariant(), TimeSpan.FromSeconds(5)))
                        Check.True(ok.Call("ping", null) != null, "chemin attendu : comparaison insensible à la casse");
                    Check.True(AdminClient.DefaultServerPath().EndsWith("\\irisd.exe"), "par défaut : irisd.exe du dossier de l'exécutable");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void AdminPipe_OversizeAndTruncatedFrames()
        {
            string name = TestPipeName();
            using (AdminServer server = new AdminServer(name, new EchoHandler().Handle))
            {
                server.Start();
                using (NamedPipeClientStream raw = new NamedPipeClientStream(".", name, PipeDirection.InOut))
                {
                    raw.Connect(5000);
                    raw.Write(new byte[] { 0x00, 0x20, 0x00, 0x00 }, 0, 4); // 2 Mio annoncés
                    raw.Flush();
                    int n;
                    try { n = raw.Read(new byte[16], 0, 16); }
                    catch (IOException) { n = 0; }
                    Check.Eq(0, n, "trame > 1 Mio : connexion fermée sans réponse");
                }
                using (NamedPipeClientStream raw = new NamedPipeClientStream(".", name, PipeDirection.InOut))
                {
                    raw.Connect(5000);
                    raw.Write(new byte[] { 0, 0, 0, 100, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 }, 0, 14); // trame tronquée
                    raw.Flush();
                }
                using (AdminClient c = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5)))
                    Check.True(c.Call("ping", null) != null, "le serveur continue de servir après les deux incidents");
            }
        }

        private static void AdminPipe_SecurityDescriptor()
        {
            PipeSecurity ps = AdminPipeSecurity.Create();
            Check.True(ps.AreAccessRulesProtected, "héritage coupé");
            AuthorizationRuleCollection rules = ps.GetAccessRules(true, true, typeof(SecurityIdentifier));
            Check.Eq(2, rules.Count, "deux règles exactement");
            SecurityIdentifier me = WindowsIdentity.GetCurrent().User;
            SecurityIdentifier network = new SecurityIdentifier(WellKnownSidType.NetworkSid, null);
            bool allowMe = false, denyNetwork = false;
            foreach (PipeAccessRule r in rules)
            {
                if (r.IdentityReference.Equals(me) && r.AccessControlType == AccessControlType.Allow && r.PipeAccessRights == PipeAccessRights.FullControl) allowMe = true;
                if (r.IdentityReference.Equals(network) && r.AccessControlType == AccessControlType.Deny) denyNetwork = true;
            }
            Check.True(allowMe, "contrôle total pour l'utilisateur courant seul");
            Check.True(denyNetwork, "refus explicite du SID NETWORK");
        }

        private static void AdminPipe_StopReleasesName()
        {
            string name = TestPipeName();
            AdminServer server = new AdminServer(name, new EchoHandler().Handle);
            server.Start();
            AdminClient idle = AdminClient.Connect(name, SelfPath(), TimeSpan.FromSeconds(5));
            Stopwatch watch = Stopwatch.StartNew();
            server.Stop();
            Check.True(watch.Elapsed < TimeSpan.FromSeconds(5), "Stop rend la main malgré un client inactif");
            Check.Throws<IOException>(delegate { idle.Call("ping", null); }, "le client inactif voit la fermeture");
            idle.Dispose();
            using (AdminServer again = new AdminServer(name, new EchoHandler().Handle))
            {
                again.Start();
                Check.True(true, "le nom est libéré après Stop");
            }
        }
    }
}
