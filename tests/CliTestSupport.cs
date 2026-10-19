using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Harnais de la CLI : Cli.Run en process contre un daemon réel (spec phase 5 §3) ----------

        private sealed class CliRun
        {
            public int Code;
            public string Out;
            public string Err;
            public string All { get { return Out + "\n" + Err; } }
        }

        private static Stream Stdin(string text) { return new MemoryStream(Encoding.UTF8.GetBytes(text ?? "")); }

        /// <summary>Contexte de test : sorties capturées, stdin redirigé vide, serveur attendu = l'exe de tests, profil dans data\profil.</summary>
        private static CliContext CliCtx(string data)
        {
            CliContext c = new CliContext();
            c.Out = new CapturingWriter();
            c.Err = new CapturingWriter();
            c.In = Stdin("");
            c.IsStdinRedirected = true;
            c.Passwords = null;
            c.ExpectedServerPath = SelfPath();
            c.DataDirectory = data;
            c.EnvironmentVariables = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            c.UserProfile = Path.Combine(data, "profil");
            c.Cancel = CancellationToken.None;
            c.Now = delegate { return DateTime.UtcNow; };
            c.ConnectTimeout = TimeSpan.FromSeconds(2);
            c.IsCaTrusted = delegate(string thumbprint) { return false; };
            return c;
        }

        private static CliRun RunIris(CliContext c, params string[] args)
        {
            CliRun r = new CliRun();
            r.Code = Cli.Run(args, c);
            r.Out = c.Out.ToString();
            r.Err = c.Err.ToString();
            return r;
        }

        private static CliRun RunIris(string data, params string[] args) { return RunIris(CliCtx(data), args); }

        /// <summary>Daemon réel en process (secrets et CA en mémoire : coffre ouvert d'emblée), ports libres, pipe unique.</summary>
        private sealed class CliDaemon : IDisposable
        {
            public string Dir;
            public string Data;
            public TestEndpoints T;
            public LiveDaemon D;

            public void Stop()
            {
                if (D == null) return;
                D.Cts.Cancel();
                D.WaitExit();
                D = null;
            }

            public void Restart()
            {
                D = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", Data, "--in-memory-secrets", "--in-memory-ca");
                if (!WaitReady(D)) throw new Exception("daemon de test non prêt : " + D.Out.Snapshot() + D.Err.Snapshot());
            }

            public void Dispose()
            {
                try { Stop(); }
                finally
                {
                    Log.Reset();
                    TestDir.Delete(Dir);
                }
            }
        }

        private static CliDaemon StartCliDaemon()
        {
            CliDaemon d = new CliDaemon();
            d.Dir = TestDir.Create();
            d.Data = Path.Combine(d.Dir, "data");
            d.T = WriteTestConfig(d.Data);
            try { d.Restart(); }
            catch
            {
                d.Dispose();
                throw;
            }
            return d;
        }
    }
}
