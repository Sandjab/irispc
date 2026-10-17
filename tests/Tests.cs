using System;
using System.IO;
using System.Reflection;
using System.Text;
using IrisKit;
using Irisd;

namespace Iris.Tests
{
    /// <summary>
    /// Harnais de tests sans framework : compilé et exécuté par test.bat avec le csc.exe natif.
    /// Remplace src\irisd\Program.cs ; chaque test est une méthode, Summary() donne le code de sortie.
    /// </summary>
    public static partial class TestMain
    {
        public static int Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Check.Run("Check : Eq et Throws signalent les écarts", Check_SelfTest);
            Check.Run("Version : constante, assembly et manifeste cohérents", Version_Consistent);
            Check.Run("KeePassLib : chargeable depuis KeePass.exe 2.61.1", KeePassLib_Loads);
            Check.Run("Arguments : --foreground seul", Arguments_ForegroundOnly);
            Check.Run("Arguments : toutes les options de la spec §7", Arguments_AllOptions);
            Check.Run("Arguments : --version, --help, vide", Arguments_VersionHelpEmpty);
            Check.Run("Arguments : option inconnue, casse, positionnel", Arguments_Unknown);
            Check.Run("Arguments : valeur manquante ou vide pour --data et --log-level", Arguments_MissingValue);
            Check.Run("Arguments : niveau de log inconnu", Arguments_BadLogLevel);
            Check.Run("Arguments : option répétée refusée", Arguments_Duplicate);
            Check.Run("Arguments : usage en français, accents intacts", Arguments_UsageText);
            Check.Run("Json : aller-retour ordonné, indentation", Json_RoundTripOrdered);
            Check.Run("Json : compact et échappements", Json_CompactAndEscapes);
            Check.Run("Json : dates ISO 8601 UTC", Json_Dates);
            Check.Run("Json : erreurs de parse et d'accès", Json_Errors);
            Check.Run("Json : nombres", Json_Numbers);
            Check.Run("Modèles : validation des hôtes", Models_HostName);
            Check.Run("Modèles : validation des secrets", Models_SecretValidation);
            Check.Run("Modèles : Secret ↔ JSON", Models_SecretJson);
            Check.Run("Modèles : MITMRule ↔ JSON", Models_MITMRule);
            Check.Run("Modèles : Event avec Alert (fixture IRIS)", Models_EventWithAlert);
            Check.Run("Modèles : Event systemAlert, flags, compat", Models_EventSystemAlertAndFlags);
            Check.Run("Modèles : valeurs de fil des énumérations", Models_EnumWire);
            Check.Run("Logging : niveaux et format", Logging_LevelsAndFormat);
            Check.Run("Logging : valeurs de fil des niveaux", Logging_LevelWire);
            Check.Run("Logging : redaction", Logging_Redaction);
            Check.Run("Config : défauts et format de fil", Config_DefaultAndWire);
            Check.Run("Config : plugins conservé tel quel", Config_PluginsPreservedRaw);
            Check.Run("Config : validation de chaque champ", Config_Validation);
            Check.Run("Backups : copie horodatée et rotation", Backups_CopyAndRotate);
            Check.Run("ConfigStore : seed et relecture", ConfigStore_SeedAndLoad);
            Check.Run("ConfigStore : Save, backups, rotation", ConfigStore_SaveBackupsRotation);
            Check.Run("ConfigStore : démarrage dégradé sur corruption", ConfigStore_Corrupted_DegradedBoot);
            Check.Run("ConfigStore : erreur d'E/S irrécupérable", ConfigStore_IOError);
            Check.Run("Events : ring borné et totaux", Events_Ring);
            Check.Run("Events : bus d'abonnés", Events_Bus);
            Check.Run("Events : journal JSONL par jour, purge", Events_JsonlStore);
            Check.Run("Events : pipeline", Events_Pipeline);
            Check.Run("SecretStore : contrat (mémoire)", SecretStore_InMemoryContract);
            Check.Run("SecretStore : copies défensives", SecretStore_InMemoryDefensiveCopies);
            Check.Run("SecretStore : cache LRU 32 / TTL", SecretStore_Cache);
            Check.Run("EnvSecrets : chargement IRIS_SECRET_*", EnvSecrets_Load);
            Check.Run("EnvSecrets : sans hôtes = ignoré", EnvSecrets_MissingHosts_Ignored);
            Check.Run("MetaStore : défauts, Flush, purge, format", MetaStore_DefaultsAndFlush);
            Check.Run("MetaStore : débounce et Dispose", MetaStore_DebounceAndDispose);
            Check.Run("MetaStore : fichier corrompu = repart vide", MetaStore_CorruptFileStartsEmpty);

            return Check.Summary();
        }

        // ---- Harnais ---------------------------------------------------

        private static void Check_SelfTest()
        {
            CheckException ex = Check.Throws<CheckException>(delegate { Check.Eq(1, 2, "un contre deux"); }, "Eq détecte l'écart");
            Check.True(ex.Message.Contains("attendu <1>") && ex.Message.Contains("obtenu <2>"), "le message cite les deux valeurs");
            Check.Throws<CheckException>(delegate { Check.True(false, "faux"); }, "True(false) lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { }, "rien"); },
                "Throws sans exception lève");
            Check.Throws<CheckException>(
                delegate { Check.Throws<InvalidOperationException>(delegate { throw new ArgumentException("x"); }, "autre"); },
                "Throws avec un autre type lève");
        }

        // ---- Version ---------------------------------------------------

        private static void Version_Consistent()
        {
            Version assembly = typeof(IrisVersion).Assembly.GetName().Version;
            Check.Eq(IrisVersion.Value + ".0", assembly.ToString(), "AssemblyVersion = IrisVersion.Value + .0");

            string manifest = File.ReadAllText(RepoPath("app.manifest"));
            Check.True(manifest.Contains("version=\"" + IrisVersion.Value + ".0\""), "app.manifest porte la même version");
        }

        // ---- KeePass ---------------------------------------------------

        private static void KeePassLib_Loads()
        {
            KeePassLib.PwDatabase db = new KeePassLib.PwDatabase();
            Check.True(!db.IsOpen, "base neuve fermée");
            Check.Eq("2.61.1.0", typeof(KeePassLib.PwDatabase).Assembly.GetName().Version.ToString(), "version de l'assembly KeePass");
        }

        // ---- Arguments de irisd ----------------------------------------

        private static void Arguments_ForegroundOnly()
        {
            Arguments a = Arguments.Parse(new[] { "--foreground" });
            Check.True(a.Foreground, "Foreground");
            Check.True(!a.ShowVersion && !a.ShowHelp && !a.InMemorySecrets && !a.InMemoryCa, "autres drapeaux à faux");
            Check.Eq(null, a.Data, "Data par défaut");
            Check.Eq(null, a.LogLevel, "LogLevel par défaut");
        }

        private static void Arguments_AllOptions()
        {
            Arguments a = Arguments.Parse(new[] {
                "--foreground", "--data", "D:\\iris data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "debug" });
            Check.True(a.Foreground && a.InMemorySecrets && a.InMemoryCa, "drapeaux");
            Check.Eq("D:\\iris data", a.Data, "Data conservé tel quel, espace compris");
            Check.Eq("debug", a.LogLevel, "LogLevel");
            foreach (string level in Arguments.LogLevels)
                Check.Eq(level, Arguments.Parse(new[] { "--log-level", level }).LogLevel, "niveau " + level);
            Check.Eq(4, Arguments.LogLevels.Length, "quatre niveaux : debug, info, warning, error");
        }

        private static void Arguments_VersionHelpEmpty()
        {
            Check.True(Arguments.Parse(new[] { "--version" }).ShowVersion, "--version");
            Check.True(Arguments.Parse(new[] { "--help" }).ShowHelp, "--help");
            Arguments empty = Arguments.Parse(new string[0]);
            Check.True(!empty.Foreground && !empty.ShowVersion && !empty.ShowHelp, "vide : rien de demandé");
        }

        private static void Arguments_Unknown()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--foreground", "--verbose" }); }, "option inconnue");
            Check.True(ex.Message.Contains("--verbose"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--Foreground" }); }, "sensible à la casse");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "foreground" }); }, "positionnel refusé");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "-f" }); }, "forme courte refusée");
        }

        private static void Arguments_MissingValue()
        {
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--data" }); }, "--data en fin");
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "--foreground" }); }, "--data suivi d'une option");
            Check.True(ex.Message.Contains("--data"), "le message cite --data");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--data", "" }); }, "--data vide");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level" }); }, "--log-level en fin");
        }

        private static void Arguments_BadLogLevel()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--log-level", "verbose" }); }, "niveau inconnu");
            Check.True(ex.Message.Contains("verbose") && ex.Message.Contains("debug"), "le message cite la valeur et les niveaux attendus");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--log-level", "INFO" }); }, "casse des niveaux");
        }

        private static void Arguments_Duplicate()
        {
            ArgumentsException ex = Check.Throws<ArgumentsException>(
                delegate { Arguments.Parse(new[] { "--data", "a", "--data", "b" }); }, "--data répété");
            Check.True(ex.Message.Contains("--data"), "le message cite l'option");
            Check.Throws<ArgumentsException>(delegate { Arguments.Parse(new[] { "--foreground", "--foreground" }); }, "--foreground répété");
        }

        private static void Arguments_UsageText()
        {
            string usage = Arguments.Usage();
            Check.True(usage.StartsWith("Usage : irisd --foreground"), "première ligne");
            foreach (string option in new[] { "--foreground", "--data", "--in-memory-secrets", "--in-memory-ca", "--log-level", "--version", "--help" })
                Check.True(usage.Contains(option), "usage cite " + option);
            Check.True(usage.Contains("d\u00e9faut"), "accent é intact (codepage 65001)");
            Check.True(usage.Contains("DEBUG"), "les modes in-memory sont marqués DEBUG");
        }

        // ---- Outils ----------------------------------------------------

        /// <summary>Chemin d'un fichier du dépôt, depuis l'emplacement de Iris.Tests.exe (tests\).</summary>
        private static string RepoPath(string relative)
        {
            string testsDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            return Path.GetFullPath(Path.Combine(testsDir, "..", relative));
        }
    }
}
