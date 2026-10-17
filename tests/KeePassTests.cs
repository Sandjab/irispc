using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using IrisKit;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- KeePass (base temporaire, jamais une base utilisateur) ----

        private static string FileHash(string path)
        {
            using (SHA256 sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(File.ReadAllBytes(path)));
        }

        private static SecretsMetaStore MetaFor(KeePassVault vault, string dir)
        {
            return new SecretsMetaStore(Path.Combine(dir, "secrets-meta.json"), delegate { return vault.SecretNames(); }, TimeSpan.FromHours(1), delegate { return T0; });
        }

        private static void KeePass_CreateContractReopen()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("maître-é"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    Check.True(File.Exists(kdbx) && !vault.IsBusy, "base créée");
                    SecretStoreContract(new KeePassSecretStore(vault, meta));
                }
                using (KeePassVault again = KeePassVault.Open(kdbx, Secure("maître-é")))
                using (SecretsMetaStore meta = MetaFor(again, dir))
                {
                    KeePassSecretStore store = new KeePassSecretStore(again, meta);
                    IList<Secret> list = Wait(store.ListAsync());
                    Check.True(list.Count == 1 && list[0].Name == "anthropic_api_key" && list[0].AllowedHosts[0] == "api.anthropic.com" && list[0].CreatedAt == T0, "secret relu après réouverture");
                    Check.Eq("sk-ant-1", Encoding.UTF8.GetString(Wait(store.ValueAsync("anthropic_api_key"))), "valeur relue");
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("maître-é"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                Check.True(raw.KdfParameters.KdfUuid.Equals(new KeePassLib.Cryptography.KeyDerivation.Argon2Kdf().Uuid), "KDF Argon2d");
                Check.Eq("iris", raw.Name, "nom de base");
                PwGroup secrets = null;
                foreach (PwGroup g in raw.RootGroup.Groups) if (g.Name == "secrets") secrets = g;
                Check.True(secrets != null && secrets.Entries.UCount == 1, "groupe secrets, une entrée");
                PwEntry entry = secrets.Entries.GetAt(0);
                Check.True(entry.Strings.GetSafe(PwDefs.PasswordField).IsProtected, "valeur en champ protégé");
                Check.Eq("[\"api.anthropic.com\"]", entry.Strings.ReadSafe("allowed_hosts"), "allowed_hosts = tableau JSON");
                Check.Eq("2023-11-14T22:13:20Z", entry.Strings.ReadSafe("created_at"), "created_at ISO");
                raw.Close();
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_WrongPasswordAndCorruption()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                KeePassVault.Create(kdbx, Secure("bon"), T0).Dispose();
                SecretStoreException ex = Check.Throws<SecretStoreException>(delegate { KeePassVault.Open(kdbx, Secure("mauvais")); }, "mauvais mot de passe");
                Check.Eq(SecretStoreErrorKind.VaultLocked, ex.Kind, "VaultLocked");
                Check.True(!ex.Message.Contains("mauvais"), "le mot de passe n'est pas dans le message");
                File.WriteAllText(Path.Combine(dir, "corrupt.kdbx"), "ceci n'est pas une base");
                Check.Eq(SecretStoreErrorKind.DataCorruption, Check.Throws<SecretStoreException>(delegate { KeePassVault.Open(Path.Combine(dir, "corrupt.kdbx"), Secure("x")); }, "fichier corrompu").Kind, "DataCorruption");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_LockFile_VaultBusy()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    KeePassSecretStore store = new KeePassSecretStore(vault, meta);
                    Wait(store.AddAsync("k", Bytes("v"), new[] { "h.example" }, T0));
                    string before = FileHash(kdbx);
                    int backupsBefore = Directory.GetFiles(vault.BackupsDir).Length;
                    File.WriteAllText(vault.LockPath, "KeePass a la base ouverte");
                    Check.True(vault.IsBusy, "lock détecté");
                    Check.Eq("v", Encoding.UTF8.GetString(Wait(store.ValueAsync("k"))), "lecture permise");
                    Check.Eq(1, Wait(store.ListAsync()).Count, "liste permise");
                    foreach (Action write in new Action[] {
                        delegate { Wait(store.AddAsync("k2", Bytes("v"), new[] { "h.example" }, T0)); },
                        delegate { Wait(store.UpdateAsync("k", new[] { "other.example" })); },
                        delegate { Wait(store.RotateAsync("k", Bytes("v2"))); },
                        delegate { Wait(store.DeleteAsync("k")); } })
                    {
                        SecretStoreException ex = Check.Throws<SecretStoreException>(write, "écriture refusée");
                        Check.Eq(SecretStoreErrorKind.VaultBusy, ex.Kind, "VaultBusy");
                        Check.True(ex.Message.Contains("KeePass"), "message explicite");
                    }
                    Check.Eq(before, FileHash(kdbx), "base intacte");
                    Check.Eq(backupsBefore, Directory.GetFiles(vault.BackupsDir).Length, "aucun backup créé");
                    Wait(store.RecordUsageAsync("k", T0));
                    Check.True(Wait(store.SetQuarantinedAsync("k", true)).Quarantined, "métadonnées modifiables malgré le lock (hors kdbx)");
                    Check.Eq(before, FileHash(kdbx), "les métadonnées n'écrivent jamais le kdbx");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_BackupsBeforeWrite()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (SecretsMetaStore meta = MetaFor(vault, dir))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.MaxBackups = 2;
                    int tick = 0;
                    vault.Clock = delegate { return T0.AddSeconds(tick++); };
                    KeePassSecretStore store = new KeePassSecretStore(vault, meta);
                    Wait(store.AddAsync("a", Bytes("1"), new[] { "h.example" }, T0));
                    string[] one = Directory.GetFiles(vault.BackupsDir, "iris-*.kdbx");
                    Check.Eq(1, one.Length, "copie avant la première écriture");
                    Check.True(new FileInfo(one[0]).Length > 0, "copie non vide");
                    Wait(store.AddAsync("b", Bytes("2"), new[] { "h.example" }, T0));
                    Wait(store.RotateAsync("a", Bytes("3")));
                    Check.Eq(2, Directory.GetFiles(vault.BackupsDir, "iris-*.kdbx").Length, "rotation à MaxBackups");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_ForeignContentIgnored()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.AddSecret("mine", Bytes("v"), new[] { "h.example" }, T0);
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("p"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                PwEntry stray = new PwEntry(true, true);
                stray.Strings.Set(PwDefs.TitleField, new ProtectedString(false, "perso"));
                stray.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, "x"));
                raw.RootGroup.AddEntry(stray, true);
                PwGroup other = new PwGroup(true, true, "banque", PwIcon.Money);
                other.AddEntry(new PwEntry(true, true), true);
                raw.RootGroup.AddGroup(other, true);
                raw.Save(new NullStatusLogger());
                raw.Close();
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                {
                    IList<VaultSecretEntry> list = vault.ListSecrets();
                    Check.True(list.Count == 1 && list[0].Name == "mine", "seul le groupe secrets est lu");
                    Check.True(vault.ReadCA() == null, "pas de CA encore");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void KeePass_CAEntry()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                byte[] keyBytes = Bytes("pkcs8-factice");
                byte[] certBytes = Bytes("der-factice");
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    vault.WriteCA(new CAMaterial(keyBytes, certBytes, T0));
                    vault.WriteCA(new CAMaterial(keyBytes, certBytes, T0.AddDays(1)));
                }
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                {
                    CAMaterial ca = vault.ReadCA();
                    Check.True(ca != null && Convert.ToBase64String(ca.PrivateKeyPkcs8) == Convert.ToBase64String(keyBytes) && Convert.ToBase64String(ca.CertificateDer) == Convert.ToBase64String(certBytes) && ca.CreatedAt == T0.AddDays(1), "CA relu, la réécriture remplace l'entrée root");
                }
                PwDatabase raw = new PwDatabase();
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword("p"));
                raw.Open(IOConnectionInfo.FromPath(kdbx), key, new NullStatusLogger());
                PwGroup ca2 = null;
                foreach (PwGroup g in raw.RootGroup.Groups) if (g.Name == "ca") ca2 = g;
                Check.True(ca2 != null && ca2.Entries.UCount == 1, "groupe ca, une seule entrée root");
                PwEntry root = ca2.Entries.GetAt(0);
                Check.True(root.Strings.ReadSafe(PwDefs.TitleField) == "root" && root.Strings.GetSafe(PwDefs.PasswordField).IsProtected, "clé privée en champ protégé");
                Check.Eq(Convert.ToBase64String(certBytes), root.Strings.ReadSafe("certificate"), "certificat en base64 dans un champ libre");
                raw.Close();
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
