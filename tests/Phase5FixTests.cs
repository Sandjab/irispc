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
        // ---- Revue finale phase 5 : chaque correction reproduite d'abord par un test ----------------

        /// <summary>I1 : un changement dont le debounce expire pendant le traitement (avant l'attente suivante) n'est jamais perdu.</summary>
        private static void Final5_WatcherChangeBeforeWaitNotLost()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, ".mcp.json");
                File.WriteAllText(path, "{}");
                using (McpFileWatcher w = new McpFileWatcher(path, TimeSpan.FromMilliseconds(200)))
                {
                    File.WriteAllText(path, "{\"n\": 1}");
                    Task.Delay(1000).Wait(); // le « cycle » dure plus que le debounce : le signal tombe avant l'attente
                    CancellationTokenSource limit = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    bool signalled = true;
                    try { w.WaitForChange(limit.Token); }
                    catch (OperationCanceledException) { signalled = false; }
                    Check.True(signalled, "changement survenu avant l'attente : signalé");
                    CancellationTokenSource quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(600));
                    Check.Throws<OperationCanceledException>(delegate { w.WaitForChange(quiet.Token); }, "signal consommé une seule fois");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        /// <summary>m1 : `secret add --value-from-stdin` à une console interactive lit sans écho (comme `rotate`), jamais en clair.</summary>
        private static void Final5_SecretAddAtConsoleNoEcho()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliContext c = CliCtx(d.Data);
                c.IsStdinRedirected = false;
                ScriptedConsoleInput typed = new ScriptedConsoleInput("sk-typed-add-1");
                c.Passwords = typed;
                CliRun r = RunIris(c, "secret", "add", "demo", "--allowed-hosts", "api.example.com", "--value-from-stdin");
                Check.True(r.Code == 0, "add à la console : " + r.All);
                Check.True(typed.Prompts.Count == 1 && typed.Prompts[0] == "Valeur pour demo : ", "saisie sans écho demandée");
                Check.True(!r.All.Contains("sk-typed-add-1"), "jamais affichée");
            }
        }

        /// <summary>m2 : un BOM UTF-8 en tête (pipe PowerShell 5.1 avec $OutputEncoding UTF-8) n'entre pas dans la valeur.</summary>
        private static void Final5_SecretValueStripsLeadingBom()
        {
            byte[] v = SecretValue.Normalize(new byte[] { 0xEF, 0xBB, 0xBF, (byte)'a', (byte)'b', 13, 10 });
            Check.Eq("ab", Encoding.UTF8.GetString(v), "BOM et CRLF retirés");
            Check.Throws<CliException>(delegate { SecretValue.Normalize(new byte[] { 0xEF, 0xBB, 0xBF, 10 }); }, "BOM seul : vide refusé");
            byte[] binary = SecretValue.Normalize(new byte[] { 0xBB, 0xEF, 0xBF });
            Check.Eq(3, binary.Length, "octets qui ne forment pas un BOM en tête : conservés");
        }

        /// <summary>m3 : une erreur d'usage ne recopie jamais un argument positionnel en trop (souvent une valeur collée par erreur).</summary>
        private static void Final5_UsageNeverEchoesStrayArgument()
        {
            string dir = TestDir.Create();
            try
            {
                CliRun r = RunIris(Path.Combine(dir, "data"), "secret", "add", "demo", "--value-from-stdin", "sk-live-STRAY-42");
                Check.Eq(64, r.Code, "argument en trop → 64");
                Check.True(r.Err.Contains("argument en trop"), "message d'usage : " + r.Err);
                Check.True(!r.All.Contains("sk-live-STRAY-42"), "l'argument n'est pas recopié : " + r.All);
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
