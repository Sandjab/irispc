using System;
using System.IO;
using System.Threading.Tasks;
using IrisCli;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- iris vault (spec phase 5 §4, §5) -------------------------------------------------

        private static void Cli_VaultRequiresConsole()
        {
            string dir = TestDir.Create();
            try
            {
                foreach (string sub in new[] { "unlock", "create" })
                {
                    CliRun r = RunIris(dir, "vault", sub);
                    Check.True(r.Code == 64 && r.Err.Contains("exige une console"), "vault " + sub + " stdin redirigé → 64 avant toute connexion : " + r.All);
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static CliContext ConsoleCtx(string data, ScriptedConsoleInput passwords)
        {
            CliContext c = CliCtx(data);
            c.IsStdinRedirected = false;
            c.Passwords = passwords;
            return c;
        }

        private static void Cli_VaultUnlockLocked()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                Check.Eq(ExitCodes.Ok, RunLive(new ScriptedConsoleInput("pw-é", "pw-é"), data).Code, "coffre créé à la console");
                WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--locked");
                try
                {
                    Check.True(WaitReady(d), "daemon prêt : " + d.Out.Snapshot() + d.Err.Snapshot());
                    CliRun r = RunIris(data, "vault", "status");
                    Check.True(r.Code == 0 && r.Out.Contains("verrouillé") && r.Out.Contains("iris.kdbx"), "vault status : " + r.Out);
                    Check.True(RunIris(data, "status").Out.Contains("coffre : verrouillé"), "status : verrouillé");
                    r = RunIris(data, "secret", "list");
                    Check.True(r.Code == 1 && r.Err.Contains("coffre verrouillé : lancez iris vault unlock"), "-32020 → message dédié : " + r.All);
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("faux")), "vault", "unlock");
                    Check.True(r.Code == 1 && r.Err.Contains("mot de passe refusé"), "mauvais mot de passe → 1 : " + r.All);
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("faux")), "vault", "unlock");
                    Check.True(r.Code == 1 && r.Err.Contains("trop d'essais : réessayez dans"), "délai anti-force brute → message : " + r.All);
                    Wait(Task.Delay(1100));
                    ScriptedConsoleInput good = new ScriptedConsoleInput("pw-é");
                    r = RunIris(ConsoleCtx(data, good), "vault", "unlock");
                    Check.True(r.Code == 0 && r.Out.Trim() == "coffre déverrouillé" && good.Prompts[0] == "Mot de passe maître : ", "unlock : " + r.All);
                    ScriptedConsoleInput unused = new ScriptedConsoleInput("x");
                    r = RunIris(ConsoleCtx(data, unused), "vault", "unlock");
                    Check.True(r.Code == 0 && r.Out.Trim() == "déjà déverrouillé" && unused.PromptCount == 0, "déjà ouvert : aucune saisie demandée");
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("a", "a")), "vault", "create");
                    Check.True(r.Code == 1 && r.Err.Contains("existe déjà"), "create sur un coffre existant → 1 : " + r.All);
                    r = RunIris(data, "vault", "status", "--json");
                    JsonObject s = Json.ParseObject(r.Out);
                    Check.True(s.String("state") == "unlocked" && s.String("path").EndsWith("iris.kdbx"), "vault status --json : " + r.Out);
                }
                finally { d.Cts.Cancel(); }
                d.WaitExit();
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }

        private static void Cli_VaultCreateAbsent()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                WriteTestConfig(data);
                LiveDaemon d = StartDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--locked");
                try
                {
                    Check.True(WaitReady(d), "daemon prêt");
                    Check.True(RunIris(data, "vault", "status").Out.Contains("absent"), "état absent");
                    CliRun r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("x")), "vault", "unlock");
                    Check.True(r.Code == 1 && r.Err.Contains("aucun coffre : iris vault create"), "unlock sans coffre → 1 : " + r.All);
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("un", "deux")), "vault", "create");
                    Check.True(r.Code == 1 && r.Err.Contains("diffèrent"), "saisies différentes → 1 : " + r.All);
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput("", "")), "vault", "create");
                    Check.True(r.Code == 1 && r.Err.Contains("vide"), "mot de passe vide → 1 : " + r.All);
                    r = RunIris(ConsoleCtx(data, new ScriptedConsoleInput()), "vault", "create");
                    Check.True(r.Code == 1 && r.Err.Contains("saisie interrompue"), "EOF → 1 : " + r.All);
                    ScriptedConsoleInput twice = new ScriptedConsoleInput("nouveau-ü", "nouveau-ü");
                    r = RunIris(ConsoleCtx(data, twice), "vault", "create");
                    Check.True(r.Code == 0 && r.Out.Trim() == "coffre créé et déverrouillé" && twice.PromptCount == 2, "create : " + r.All);
                    Check.True(File.Exists(Path.Combine(data, "iris.kdbx")), "iris.kdbx créé");
                    Check.True(RunIris(data, "vault", "status").Out.Contains("déverrouillé"), "état déverrouillé");
                }
                finally { d.Cts.Cancel(); }
                d.WaitExit();
            }
            finally { Log.Reset(); TestDir.Delete(dir); }
        }
    }
}
