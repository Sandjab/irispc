using System;
using System.Diagnostics;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Identité du serveur du pipe (spec phase 5 §8) ----------------------------------

        /// <summary>Jonction NTFS (mklink /J, sans droits administrateur) : `link` → `target`.</summary>
        private static void MakeJunction(string link, string target)
        {
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c mklink /J \"" + link + "\" \"" + target + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            using (Process p = Process.Start(psi))
            {
                p.StandardOutput.ReadToEnd();
                string err = p.StandardError.ReadToEnd();
                p.WaitForExit();
                if (p.ExitCode != 0) throw new IOException("mklink /J a échoué : " + err);
            }
        }

        /// <summary>Supprime la jonction elle-même (jamais sa cible) ; faux si elle n'a pas pu être retirée.</summary>
        private static bool RemoveJunction(string link)
        {
            try
            {
                if (Directory.Exists(link)) Directory.Delete(link, false);
                return true;
            }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }

        private static void FileIdentity_SameFileThroughJunctionCaseAndCopy()
        {
            string dir = TestDir.Create();
            string link = Path.Combine(dir, "lien");
            try
            {
                string self = SelfPath();
                Check.True(FileIdentity.Same(self, self.ToUpperInvariant()), "casse différente : même fichier");
                MakeJunction(link, Path.GetDirectoryName(self));
                string viaLink = Path.Combine(link, Path.GetFileName(self));
                Check.True(File.Exists(viaLink), "jonction créée : " + viaLink);
                Check.True(FileIdentity.Same(self, viaLink), "chemin par jonction : même fichier");
                Check.True(FileIdentity.Of(self).Equals(FileIdentity.Of(viaLink)), "Of : identités égales");
                string copy = Path.Combine(dir, Path.GetFileName(self));
                File.Copy(self, copy);
                Check.True(!FileIdentity.Same(self, copy), "copie identique ailleurs : autre fichier");
                string absent = Path.Combine(dir, "absent.exe");
                Check.True(!FileIdentity.Same(self, absent), "fichier absent : jamais le même");
                Check.Throws<IOException>(delegate { FileIdentity.Of(absent); }, "Of sur un fichier absent : IOException");
                Check.True(!FileIdentity.Same(self, ""), "chemin vide : jamais le même");
            }
            finally
            {
                if (RemoveJunction(link)) TestDir.Delete(dir);
            }
        }

        private static void AdminPipe_IdentityByFile()
        {
            string name = TestPipeName();
            EchoHandler echo = new EchoHandler();
            string dir = TestDir.Create();
            string link = Path.Combine(dir, "lien");
            try
            {
                MakeJunction(link, Path.GetDirectoryName(SelfPath()));
                string copy = Path.Combine(dir, Path.GetFileName(SelfPath()));
                File.Copy(SelfPath(), copy);
                using (AdminServer server = new AdminServer(name, echo.Handle))
                {
                    server.Start();
                    string viaLink = Path.Combine(link, Path.GetFileName(SelfPath()));
                    using (AdminClient ok = AdminClient.Connect(name, viaLink, TimeSpan.FromSeconds(5)))
                        Check.True(ok.Call("ping", null) != null, "serveur attendu atteint par une jonction : accepté");
                    AdminServerIdentityException ex = Check.Throws<AdminServerIdentityException>(
                        delegate { AdminClient.Connect(name, copy, TimeSpan.FromSeconds(5)); }, "copie identique ailleurs : refusée");
                    Check.True(ex.Expected == copy, "le message cite le chemin attendu");
                    Check.Eq(1, echo.Calls, "seul le client accepté a envoyé une requête");
                }
            }
            finally
            {
                if (RemoveJunction(link)) TestDir.Delete(dir);
            }
        }
    }
}
