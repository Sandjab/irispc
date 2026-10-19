using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Sécurité : aucune valeur ni mot de passe dans les sorties de la CLI (spec phase 5 §10, invariant 1) ----------

        private static void Security_CliNeverPrintsValuesOrPasswords()
        {
            const string value = "VALEUR-SECRÈTE-é-42";
            const string rotated = "ROTATION-SECRÈTE-ü-43";
            const string password = "MOT-DE-PASSE-ç-44";
            const string wrong = "MDP-FAUX-ß-45";
            List<string> outputs = new List<string>();
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                RunLive(new ScriptedConsoleInput(password, password), data);
                TestEndpoints t = WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--locked");
                try
                {
                    Check.True(WaitReady(d), "daemon prêt");
                    CliContext c = CliCtx(data);
                    c.IsStdinRedirected = false;
                    c.Passwords = new ScriptedConsoleInput(wrong);
                    outputs.Add(RunIris(c, "vault", "unlock").All);
                    System.Threading.Tasks.Task.Delay(1100).Wait();
                    c = CliCtx(data);
                    c.IsStdinRedirected = false;
                    c.Passwords = new ScriptedConsoleInput(password);
                    CliRun unlocked = RunIris(c, "vault", "unlock");
                    outputs.Add(unlocked.All);
                    Check.Eq(0, unlocked.Code, "déverrouillé");
                    c = CliCtx(data);
                    c.In = Stdin(value + "\n");
                    outputs.Add(RunIris(c, "secret", "add", "s1", "--allowed-hosts", "api.example.com", "--value-from-stdin").All);
                    c = CliCtx(data);
                    c.In = Stdin(value);
                    outputs.Add(RunIris(c, "secret", "add", "s1", "--allowed-hosts", "api.example.com", "--value-from-stdin").All);
                    c = CliCtx(data);
                    c.IsStdinRedirected = false;
                    c.Passwords = new ScriptedConsoleInput(rotated);
                    outputs.Add(RunIris(c, "secret", "rotate", "s1").All);
                    c = CliCtx(data);
                    c.In = Stdin(rotated);
                    outputs.Add(RunIris(c, "secret", "rotate", "absent").All);
                    EmitTunnelError(t);
                    foreach (string[] args in new[]
                    {
                        new[] { "secret", "show", "s1" }, new[] { "secret", "show", "s1", "--json" }, new[] { "secret", "list" },
                        new[] { "secret", "list", "--json" }, new[] { "logs" }, new[] { "logs", "--json" }, new[] { "status", "--json" },
                        new[] { "config", "get", "--json" }, new[] { "doctor", "--json" }, new[] { "vault", "status", "--json" }
                    })
                        outputs.Add(RunIris(data, args).All);
                    outputs.Add(d.Out.Snapshot() + d.Err.Snapshot());
                }
                finally { d.Cts.Cancel(); }
                d.WaitExit();
                foreach (string file in Directory.GetFiles(data, "*.json*", SearchOption.AllDirectories))
                    outputs.Add(File.ReadAllText(file));
                string all = string.Join("\n", outputs);
                foreach (string secret in new[] { value, rotated, password, wrong })
                {
                    Check.True(!all.Contains(secret), "jamais en clair : " + secret);
                    Check.True(!all.Contains(Convert.ToBase64String(Encoding.UTF8.GetBytes(secret))), "jamais en base64 : " + secret);
                }
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }
    }
}
