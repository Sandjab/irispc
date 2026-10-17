using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Threading;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Daemon (Entry.Run) ----------------------------------------

        private sealed class RunResult
        {
            public int Code;
            public string Out;
            public string Err;
            public string All { get { return Out + "\n" + Err; } }
        }

        private static RunResult RunDaemon(ScriptedConsoleInput console, params string[] args)
        {
            StringWriter stdout = new StringWriter();
            StringWriter stderr = new StringWriter();
            CancellationTokenSource cts = new CancellationTokenSource();
            cts.Cancel(); // le daemon démarre tout puis s'arrête aussitôt
            Log.Reset();
            RunResult r = new RunResult();
            try { r.Code = Entry.Run(args, stdout, stderr, console, cts.Token); }
            finally { Log.Reset(); }
            r.Out = stdout.ToString();
            r.Err = stderr.ToString();
            return r;
        }

        private static void Entry_ArgumentsAndExitCodes()
        {
            RunResult r = RunDaemon(new ScriptedConsoleInput(), "--bogus");
            Check.True(r.Code == ExitCodes.Arguments && r.Err.Contains("option inconnue : --bogus") && r.Err.Contains("Usage :"), "option inconnue → 4 + usage sur stderr");
            r = RunDaemon(new ScriptedConsoleInput());
            Check.True(r.Code == 1 && r.Err.Contains("Usage :") && r.Out.Length == 0, "sans --foreground → 1");
            r = RunDaemon(new ScriptedConsoleInput(), "--version");
            Check.True(r.Code == ExitCodes.Ok && r.Out.Trim() == "irisd " + IrisVersion.Value, "--version");
            r = RunDaemon(new ScriptedConsoleInput(), "--help");
            Check.True(r.Code == ExitCodes.Ok && r.Out.StartsWith("Usage :"), "--help");
            r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", "  ");
            Check.Eq(ExitCodes.Arguments, r.Code, "--data blanc → 4");
            string def = DataDir.Resolve(null);
            Check.True(def.EndsWith("\\data") && Path.GetDirectoryName(def) == Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "data\\ à côté de l'exécutable par défaut");
            Check.Eq(Path.GetFullPath("rel\\x"), DataDir.Resolve("rel\\x"), "--data relatif résolu depuis le répertoire courant");
        }

        private static void Entry_UnexpectedException_NoStackTrace()
        {
            RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", "C:\bad|path");
            Check.Eq(ExitCodes.Data, r.Code, "exception inattendue → code 1, pas de plantage : " + r.Err);
            Check.True(r.Err.StartsWith("irisd : "), "message préfixé irisd : sur stderr : " + r.Err);
            Check.True(!r.Err.Contains("   at ") && !r.Err.Contains("   à "), "aucune trace de pile");
        }

        private static void Entry_CreatesVaultAndCA()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                ScriptedConsoleInput console = new ScriptedConsoleInput("maître", "maître");
                RunResult r = RunDaemon(console, "--foreground", "--data", data, "--log-level", "debug");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage puis arrêt propre : " + r.Err);
                Check.Eq(2, console.Prompts.Count, "mot de passe et confirmation demandés");
                Check.True(console.Prompts[0].Contains("nouveau coffre"), "invite de création explicite");
                foreach (string f in new[] { "config.json", "iris.kdbx", "ca.pem", "events", "backups" })
                    Check.True(File.Exists(Path.Combine(data, f)) || Directory.Exists(Path.Combine(data, f)), "créé : " + f);
                Check.True(r.Out.Contains("coffre créé") && r.Out.Contains("CA généré") && r.Out.Contains("prêt"), "journal de démarrage");
                Check.True(!r.All.Contains("maître"), "le mot de passe n'apparaît nulle part");
                string pem = File.ReadAllText(Path.Combine(data, "ca.pem"));

                console = new ScriptedConsoleInput("maître");
                r = RunDaemon(console, "--foreground", "--data", data);
                Check.Eq(ExitCodes.Ok, r.Code, "réouverture");
                Check.True(console.Prompts.Count == 1 && r.Out.Contains("coffre ouvert") && r.Out.Contains("CA chargé"), "coffre et CA rechargés");
                Check.Eq(pem, File.ReadAllText(Path.Combine(data, "ca.pem")), "ca.pem stable entre deux démarrages");
                Check.True(!r.Out.Contains("DEBUG"), "aucun avertissement de mode debug");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_WrongPasswordThreeTimes_Exit2()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                RunDaemon(new ScriptedConsoleInput("bon", "bon"), "--foreground", "--data", data);
                ScriptedConsoleInput console = new ScriptedConsoleInput("mauvais-un", "mauvais-deux", "mauvais-trois");
                RunResult r = RunDaemon(console, "--foreground", "--data", data);
                Check.Eq(ExitCodes.Vault, r.Code, "trois échecs → 2");
                Check.Eq(3, console.Prompts.Count, "trois tentatives");
                Check.True(r.Err.Contains("refusé") && r.Err.Contains("3/3"), "message clair avec le compte");
                Check.True(!r.All.Contains("mauvais-un") && !r.All.Contains("mauvais-deux") && !r.All.Contains("mauvais-trois") && !r.All.Contains("bon"), "aucun mot de passe dans les sorties");
                r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data);
                Check.True(r.Code == ExitCodes.Vault && r.Err.Contains("entrée fermée"), "EOF sur l'invite → 2");
                r = RunDaemon(new ScriptedConsoleInput("mauvais", "bon"), "--foreground", "--data", data);
                Check.Eq(ExitCodes.Ok, r.Code, "réussite à la deuxième tentative");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_PasswordMismatchOnCreate()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                // essai 1 : x/y (différents) ; essai 2 : "" (vide, pas de confirmation demandée) ; essai 3 : x/x
                RunResult r = RunDaemon(new ScriptedConsoleInput("x", "y", "", "x", "x"), "--foreground", "--data", data);
                Check.True(r.Code == ExitCodes.Ok && r.Err.Contains("ne correspondent pas") && r.Err.Contains("vide"), "confirmation différente puis vide : nouvelles tentatives, puis création");
                Check.True(File.Exists(Path.Combine(data, "iris.kdbx")), "coffre créé au troisième essai");
                r = RunDaemon(new ScriptedConsoleInput("a", "b", "c", "d", "e", "f"), "--foreground", "--data", Path.Combine(dir, "data2"));
                Check.Eq(ExitCodes.Vault, r.Code, "trois confirmations ratées → 2");
                Check.True(!File.Exists(Path.Combine(dir, "data2", "iris.kdbx")), "aucun coffre créé");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_DataDirNotWritable_Exit1()
        {
            string dir = TestDir.Create();
            try
            {
                string asFile = Path.Combine(dir, "data");
                File.WriteAllText(asFile, "je suis un fichier");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", asFile, "--in-memory-secrets", "--in-memory-ca");
                Check.True(r.Code == ExitCodes.Data && r.Err.Contains(asFile), "data\\ inutilisable → 1 avec le chemin");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_CorruptedConfig_StillStarts()
        {
            string dir = TestDir.Create();
            try
            {
                string data = Path.Combine(dir, "data");
                Directory.CreateDirectory(data);
                File.WriteAllText(Path.Combine(data, "config.json"), "{ corrompu");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage dégradé, pas d'arrêt");
                Check.Eq(1, Directory.GetFiles(Path.Combine(data, "backups"), "config-corrupted-*.json").Length, "copie du fichier corrompu");
                string[] events = Directory.GetFiles(Path.Combine(data, "events"), "events-*.jsonl");
                Check.True(events.Length == 1 && File.ReadAllText(events[0]).Contains("\"kind\":\"systemAlert\"") && File.ReadAllText(events[0]).Contains("\"severity\":\"high\""), "event systemAlert high journalisé");
                Check.True(r.Out.Contains("corrompu"), "erreur journalisée");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Entry_InMemorySecretsAndCA()
        {
            string dir = TestDir.Create();
            Environment.SetEnvironmentVariable("IRIS_SECRET_test_key", "sk-test-value", EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable("IRIS_SECRET_test_key_HOSTS", "api.example.com", EnvironmentVariableTarget.Process);
            try
            {
                string data = Path.Combine(dir, "data");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca");
                Check.Eq(ExitCodes.Ok, r.Code, "mode debug complet");
                Check.True(r.Out.Contains("DEBUG") && r.Out.Contains("in-memory-secrets") && r.Out.Contains("in-memory-ca") && r.Out.Contains("1 secret(s)"), "avertissements visibles, un secret chargé");
                Check.True(!File.Exists(Path.Combine(data, "iris.kdbx")) && File.Exists(Path.Combine(data, "ca.pem")), "pas de coffre, mais ca.pem exporté");
                RunResult r2 = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets");
                Check.True(r2.Code == ExitCodes.Ok && r2.Out.Contains("aussi éphémère"), "--in-memory-secrets sans --in-memory-ca : CA éphémère, avertissement");
            }
            finally
            {
                Environment.SetEnvironmentVariable("IRIS_SECRET_test_key", null, EnvironmentVariableTarget.Process);
                Environment.SetEnvironmentVariable("IRIS_SECRET_test_key_HOSTS", null, EnvironmentVariableTarget.Process);
                TestDir.Delete(dir);
            }
        }

        private static void Security_NoSecretValueInDumps()
        {
            string dir = TestDir.Create();
            const string value = "sk-ant-TOPSECRET-9f8e7d";
            Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe", value, EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe_HOSTS", "api.example.com", EnvironmentVariableTarget.Process);
            try
            {
                string data = Path.Combine(dir, "data");
                RunResult r = RunDaemon(new ScriptedConsoleInput(), "--foreground", "--data", data, "--in-memory-secrets", "--in-memory-ca", "--log-level", "trace");
                Check.Eq(ExitCodes.Ok, r.Code, "démarrage");
                Check.True(!r.All.Contains(value), "stdout/stderr sans la valeur");
                foreach (string f in Directory.GetFiles(data, "*", SearchOption.AllDirectories))
                    Check.True(!File.ReadAllText(f).Contains(value), "fichier sans la valeur : " + Path.GetFileName(f));

                InMemorySecretStore store = new InMemorySecretStore();
                Wait(store.AddAsync("leak_probe", Bytes(value), new[] { "api.example.com" }, T0));
                Wait(store.RecordUsageAsync("leak_probe", T0));
                EventRing ring = new EventRing(10);
                EventsBus bus = new EventsBus();
                StringWriter log = new StringWriter();
                Log.Reset(); Log.Writer = log; Log.Minimum = LogLevel.Trace;
                using (JsonlEventStore jsonl = new JsonlEventStore(Path.Combine(data, "events2"), 7, delegate { return T0; }))
                {
                    EventPipeline p = new EventPipeline(ring, jsonl, bus);
                    p.Emit(new Event(Guid.NewGuid(), T0, EventKind.Substituted, "api.example.com", "POST", "/v1", 200, 12, new[] { "leak_probe" }, null, null, EventFlags.None));
                    p.Emit(new Event(Guid.NewGuid(), T0, EventKind.ExfilBlocked, "evil.example", "POST", "/", null, null, new string[0],
                        new Alert(AlertSeverity.High, ExfilRule.HostMismatch, "leak_probe", AlertLocation.Header, Redaction.Redact(value)), null, EventFlags.None));
                    Log.Info("proxy", "substitution de leak_probe (" + Redaction.Redact(value) + ")");
                }
                Log.Reset();
                string dump = Json.Emit(new System.Collections.Generic.List<object>(new System.Collections.Generic.List<Event>(ring.All).ConvertAll(delegate(Event e) { return (object)e.ToJson(); })))
                    + File.ReadAllText(Path.Combine(data, "events2", "events-2023-11-14.jsonl")) + log.ToString();
                Check.True(dump.Contains("leak_probe") && dump.Contains("[REDACTED:"), "le nom et la redaction apparaissent");
                Check.True(!dump.Contains(value), "la valeur n'apparaît ni dans le ring, ni dans le journal, ni dans le log");
            }
            finally
            {
                Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe", null, EnvironmentVariableTarget.Process);
                Environment.SetEnvironmentVariable("IRIS_SECRET_leak_probe_HOSTS", null, EnvironmentVariableTarget.Process);
                TestDir.Delete(dir);
            }
        }
    }
}
