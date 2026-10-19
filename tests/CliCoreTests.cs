using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Threading.Tasks;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- CLI : analyse, aide, codes de sortie, status/pause/resume (spec phase 5 §3, §4) ----------

        private static CommandSpec SampleSpec()
        {
            CommandSpec s = new CommandSpec();
            s.Path = "secret add";
            s.Usage = "secret add NAME [--allowed-hosts h1,h2] [--json]";
            s.Summary = "exemple";
            s.Positionals = new[] { "NAME" };
            s.Options = new[] { "--allowed-hosts" };
            s.Flags = new[] { "--json" };
            s.UsesDaemon = true;
            return s;
        }

        private static void CliArguments_Parse()
        {
            CommandSpec spec = SampleSpec();
            ParsedArgs p = CliArguments.Parse(spec, new[] { "secret", "add", "demo", "--allowed-hosts", "a,b", "--json", "--pipe-name", "x" }, 2);
            Check.True(p.Positional(0) == "demo" && p.Option("--allowed-hosts") == "a,b" && p.Json && p.Option("--pipe-name") == "x", "positionnel, option, drapeau, option globale");
            Check.True(p.Option("--config-path") == null && !p.HelpRequested, "option absente : null");
            UsageException ex = Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--bogus" }, 0); }, "option inconnue");
            Check.True(ex.Message.Contains("--bogus"), "le message cite l'option : " + ex.Message);
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--JSON" }, 0); }, "sensible à la casse");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--json", "--json" }, 0); }, "drapeau répété");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--allowed-hosts", "a", "--allowed-hosts", "b" }, 0); }, "option répétée");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--allowed-hosts" }, 0); }, "valeur manquante en fin");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--allowed-hosts", "--json" }, 0); }, "valeur manquante avant une option");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--allowed-hosts", " " }, 0); }, "valeur vide");
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "autre" }, 0); }, "positionnel en trop");
            UsageException missing = Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "--json" }, 0); }, "positionnel manquant");
            Check.True(missing.Message.Contains("NAME"), "le message cite l'argument : " + missing.Message);
            Check.True(CliArguments.Parse(spec, new[] { "--help" }, 0).HelpRequested, "--help sans positionnel");
            Check.True(CliArguments.Parse(spec, new[] { "demo", "-h" }, 0).HelpRequested, "-h");
            spec.UsesDaemon = false;
            Check.Throws<UsageException>(delegate { CliArguments.Parse(spec, new[] { "demo", "--pipe-name", "x" }, 0); }, "options globales réservées aux commandes du daemon");
        }

        private static void Cli_HelpVersionAndUsageCodes()
        {
            string dir = TestDir.Create();
            try
            {
                CliRun r = RunIris(dir);
                Check.True(r.Code == 0 && r.Out.Contains("Usage : iris") && r.Out.Contains("status"), "iris seul : aide, code 0");
                r = RunIris(dir, "--version");
                Check.True(r.Code == 0 && r.Out.Trim() == "iris " + IrisVersion.Value, "--version : " + r.Out);
                Check.Eq(0, RunIris(dir, "--help").Code, "--help");
                r = RunIris(dir, "bogus");
                Check.True(r.Code == 64 && r.Err.Contains("commande inconnue : bogus") && r.Err.Contains("iris --help"), "commande inconnue → 64 : " + r.Err);
                r = RunIris(dir, "status", "--bogus");
                Check.True(r.Code == 64 && r.Err.Contains("--bogus") && r.Err.Contains("voir : iris status --help"), "option inconnue → 64 : " + r.Err);
                r = RunIris(dir, "status", "--help");
                Check.True(r.Code == 0 && r.Out.Contains("Usage : iris status") && r.Out.Contains("--pipe-name"), "aide d'une commande : " + r.Out);
            }
            finally { TestDir.Delete(dir); }
        }

        private static void PipeNames_Resolution()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                Check.Eq(PipeNames.Default, PipeNames.Resolve(null, null, data, dir), "sans config : iris-admin");
                TestEndpoints t = WriteTestConfig(data);
                Check.Eq(t.Pipe, PipeNames.Resolve(null, null, data, dir), "data\\config.json voisin");
                Check.Eq("explicite", PipeNames.Resolve("explicite", Path.Combine(data, "config.json"), data, dir), "--pipe-name prime");
                string other = Path.Combine(dir, "autre");
                TestEndpoints t2 = WriteTestConfig(other);
                Check.Eq(t2.Pipe, PipeNames.Resolve(null, Path.Combine(other, "config.json"), data, dir), "--config-path prime sur le voisin");
                Check.Eq(t2.Pipe, PipeNames.Resolve(null, "~\\autre\\config.json", data, dir), "--config-path avec ~");
                CliException bad = Check.Throws<CliException>(delegate { PipeNames.Resolve(null, Path.Combine(dir, "absent.json"), data, dir); }, "--config-path illisible");
                Check.True(bad.Code == 1 && bad.Message.Contains("config illisible"), "code 1 : " + bad.Message);
                File.WriteAllText(Path.Combine(data, "config.json"), "{ cassé");
                Check.Eq(PipeNames.Default, PipeNames.Resolve(null, null, data, dir), "config voisine invalide : repli sur iris-admin");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Cli_DaemonUnreachableAndIdentity()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                TestEndpoints t = WriteTestConfig(data);
                CliContext c = CliCtx(data);
                c.ConnectTimeout = TimeSpan.FromMilliseconds(300);
                CliRun r = RunIris(c, "status");
                Check.True(r.Code == 2, "pipe absent → 2 : " + r.All);
                Check.True(r.Err.Contains("irisd ne tourne pas") && r.Err.Contains("--foreground") && r.Err.Contains(t.Pipe), "message : " + r.Err);
            }
            finally { TestDir.Delete(dir); }
            using (CliDaemon d = StartCliDaemon())
            {
                CliContext c = CliCtx(d.Data);
                c.ExpectedServerPath = Path.Combine(d.Dir, "irisd.exe");
                CliRun r = RunIris(c, "status");
                Check.True(r.Code == 2 && r.Err.Contains("n'est pas"), "identité refusée → 2 : " + r.All);
            }
        }

        /// <summary>Review Focus 2 : le serveur ferme le pipe après avoir reçu la requête, sans répondre.</summary>
        private static void Cli_PipeClosedMidCall_Exit2()
        {
            string pipe = TestPipeName();
            string dir = TestDir.Create();
            try
            {
                using (NamedPipeServerStream raw = new NamedPipeServerStream(pipe, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
                {
                    Task server = Task.Run(delegate
                    {
                        raw.WaitForConnection();
                        byte[] header = new byte[4];
                        raw.Read(header, 0, 4);
                        raw.Disconnect();
                    });
                    CliRun r = RunIris(CliCtx(dir), "status", "--pipe-name", pipe);
                    Check.True(r.Code == 2, "pipe fermé en cours d'appel → 2 : " + r.All);
                    Check.True(r.Err.Contains("connexion au daemon perdue"), "message : " + r.Err);
                    Check.True(!r.Err.Contains("   at "), "jamais de trace de pile");
                    server.Wait(TimeSpan.FromSeconds(5));
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Cli_StatusPauseResume()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliRun r = RunIris(d.Data, "status");
                Check.True(r.Code == 0 && r.Out.Contains("pid ") && r.Out.Contains("version " + IrisVersion.Value) && r.Out.Contains("coffre : déverrouillé") && r.Out.Contains("substitution : active"), "status lisible : " + r.All);
                r = RunIris(d.Data, "status", "--json");
                JsonObject s = Json.ParseObject(r.Out);
                Check.True(r.Code == 0 && s.String("vault") == "unlocked" && s.Has("uptime_s") && s.Object("stats").Has("req_total") && !s.Bool("paused", true), "status --json : " + r.Out);
                r = RunIris(d.Data, "pause");
                Check.True(r.Code == 0 && r.Out.Trim() == "en pause", "pause : " + r.Out);
                Check.True(RunIris(d.Data, "status").Out.Contains("substitution : en pause"), "status après pause");
                r = RunIris(d.Data, "pause", "--json");
                Check.True(r.Code == 0 && Json.ParseObject(r.Out).Bool("paused", false), "pause idempotente, --json");
                r = RunIris(d.Data, "resume");
                Check.True(r.Code == 0 && r.Out.Trim() == "actif", "resume : " + r.Out);
                Check.True(RunIris(d.Data, "status", "--pipe-name", d.T.Pipe).Out.Contains("substitution : active"), "--pipe-name explicite");
            }
        }

        private static void TextFormatter_Durations()
        {
            Check.Eq("0s", TextFormatter.Duration(0), "0");
            Check.Eq("12s", TextFormatter.Duration(12), "secondes");
            Check.Eq("5m30s", TextFormatter.Duration(330), "minutes et secondes");
            Check.Eq("1h", TextFormatter.Duration(3600), "unité nulle omise");
            Check.Eq("1j1h", TextFormatter.Duration(90061), "deux unités au plus");
            Check.Eq("0s", TextFormatter.Duration(-5), "négatif : 0s");
            IList<string> t = TextFormatter.Table(new[] { "A", "LONGUE" }, new List<string[]> { new[] { "valeur", "x" } });
            Check.True(t.Count == 2 && t[0] == "A       LONGUE" && t[1] == "valeur  x", "tableau aligné : [" + string.Join("|", t) + "]");
        }
    }
}
