using System;
using System.IO;
using System.Reflection;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    /// <summary>
    /// Harnais de tests sans framework : compilé et exécuté par test.bat avec le csc.exe natif.
    /// Remplace src\irisd\Program.cs ; chaque test est une méthode, Summary() donne le code de sortie.
    /// </summary>
    public static class TestMain
    {
        public static int Main()
        {
            Console.OutputEncoding = Encoding.UTF8;

            Check.Run("Check : Eq et Throws signalent les écarts", Check_SelfTest);
            Check.Run("Version : constante, assembly et manifeste cohérents", Version_Consistent);
            Check.Run("KeePassLib : chargeable depuis KeePass.exe 2.61.1", KeePassLib_Loads);

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

        // ---- Outils ----------------------------------------------------

        /// <summary>Chemin d'un fichier du dépôt, depuis l'emplacement de Iris.Tests.exe (tests\).</summary>
        private static string RepoPath(string relative)
        {
            string testsDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            return Path.GetFullPath(Path.Combine(testsDir, "..", relative));
        }
    }
}
