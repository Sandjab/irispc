using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using KeePassLib;
using KeePassLib.Cryptography.KeyDerivation;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Security;
using KeePassLib.Serialization;

namespace IrisKit
{
    public sealed class VaultSecretEntry
    {
        public string Name { get; private set; }
        public IList<string> AllowedHosts { get; private set; }
        public DateTime CreatedAt { get; private set; }

        public VaultSecretEntry(string name, IList<string> allowedHosts, DateTime createdAt)
        {
            Name = name; AllowedHosts = allowedHosts; CreatedAt = createdAt;
        }
    }

    /// <summary>
    /// Accès bas niveau à iris.kdbx (spec §4.1, §4.5) via KeePassLib : groupe `secrets` (une entrée par secret,
    /// valeur en champ protégé, `allowed_hosts` JSON, `created_at` ISO) et groupe `ca` (entrée `root`).
    /// Tout autre contenu est ignoré. Toute mutation : refus si `.lock` → backup → modification → Save, sous verrou.
    /// </summary>
    public sealed class KeePassVault : IDisposable
    {
        public const string DatabaseName = "iris";
        public const string SecretsGroup = "secrets";
        public const string CAGroup = "ca";
        public const string CAEntryTitle = "root";
        public const string HostsField = "allowed_hosts";
        public const string CreatedAtField = "created_at";
        public const string CertificateField = "certificate";

        private readonly object gate = new object();
        private PwDatabase db;

        public string Path { get; private set; }
        public string LockPath { get { return Path + ".lock"; } }
        public string BackupsDir { get; set; }
        public int MaxBackups { get; set; }
        public Func<DateTime> Clock { get; set; }
        public bool IsBusy { get { return File.Exists(LockPath); } }

        private KeePassVault(string path, PwDatabase db)
        {
            Path = path;
            this.db = db;
            BackupsDir = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(path), "backups");
            MaxBackups = 10;
            Clock = delegate { return DateTime.UtcNow; };
        }

        // ---- Ouverture / création -------------------------------------

        public static KeePassVault Create(string path, SecureString password, DateTime now)
        {
            PwDatabase db = new PwDatabase();
            db.New(IOConnectionInfo.FromPath(path), MakeKey(password));
            db.Name = DatabaseName;
            db.KdfParameters = new Argon2Kdf(Argon2Type.D).GetDefaultParameters();
            db.RootGroup.AddGroup(new PwGroup(true, true, SecretsGroup, PwIcon.Key), true);
            db.RootGroup.AddGroup(new PwGroup(true, true, CAGroup, PwIcon.Certificate), true);
            KeePassVault vault = new KeePassVault(path, db);
            vault.SaveUnlocked();
            Log.Info("vault", "coffre créé : " + path);
            return vault;
        }

        /// <summary>Mauvais mot de passe → VaultLocked ; fichier illisible → DataCorruption.</summary>
        public static KeePassVault Open(string path, SecureString password)
        {
            PwDatabase db = new PwDatabase();
            try
            {
                db.Open(IOConnectionInfo.FromPath(path), MakeKey(password), new NullStatusLogger());
            }
            catch (InvalidCompositeKeyException ex)
            {
                throw new SecretStoreException(SecretStoreErrorKind.VaultLocked, null, "mot de passe maître refusé pour " + path, ex);
            }
            catch (Exception ex)
            {
                throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "coffre illisible : " + path + " (" + ex.GetType().Name + " : " + ex.Message + ")", ex);
            }
            return new KeePassVault(path, db);
        }

        /// <summary>CompositeKey depuis une SecureString : les octets UTF-8 transitoires sont effacés aussitôt.</summary>
        private static CompositeKey MakeKey(SecureString password)
        {
            IntPtr unicode = IntPtr.Zero;
            byte[] utf8 = null;
            try
            {
                unicode = Marshal.SecureStringToGlobalAllocUnicode(password);
                string plain = Marshal.PtrToStringUni(unicode);
                utf8 = Encoding.UTF8.GetBytes(plain);
                CompositeKey key = new CompositeKey();
                key.AddUserKey(new KcpPassword(utf8));
                return key;
            }
            finally
            {
                if (utf8 != null) Array.Clear(utf8, 0, utf8.Length);
                if (unicode != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(unicode);
            }
        }

        // ---- Lecture ---------------------------------------------------

        private PwGroup Group(string name, bool create)
        {
            foreach (PwGroup g in db.RootGroup.Groups) if (g.Name == name) return g;
            if (!create) return null;
            PwGroup created = new PwGroup(true, true, name, PwIcon.Key);
            db.RootGroup.AddGroup(created, true);
            return created;
        }

        private PwEntry Entry(string groupName, string title)
        {
            PwGroup g = Group(groupName, false);
            if (g == null) return null;
            foreach (PwEntry e in g.Entries) if (e.Strings.ReadSafe(PwDefs.TitleField) == title) return e;
            return null;
        }

        private static VaultSecretEntry ToEntry(PwEntry e)
        {
            string name = e.Strings.ReadSafe(PwDefs.TitleField);
            List<string> hosts = new List<string>();
            string hostsJson = e.Strings.ReadSafe(HostsField);
            try
            {
                if (hostsJson.Length > 0)
                    foreach (object h in (IList<object>)Json.Parse(hostsJson)) hosts.Add((string)h);
            }
            catch (Exception ex)
            {
                if (ex is JsonException || ex is InvalidCastException)
                    throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, name, "allowed_hosts illisible pour " + name, ex);
                throw;
            }
            string created = e.Strings.ReadSafe(CreatedAtField);
            DateTime createdAt;
            try { createdAt = created.Length > 0 ? Json.ParseDate(created) : e.CreationTime.ToUniversalTime(); }
            catch (JsonException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, name, "created_at illisible pour " + name, ex); }
            return new VaultSecretEntry(name, hosts.AsReadOnly(), createdAt);
        }

        public IList<VaultSecretEntry> ListSecrets()
        {
            lock (gate)
            {
                List<VaultSecretEntry> list = new List<VaultSecretEntry>();
                PwGroup g = Group(SecretsGroup, false);
                if (g != null) foreach (PwEntry e in g.Entries) list.Add(ToEntry(e));
                list.Sort(delegate(VaultSecretEntry a, VaultSecretEntry b) { return string.CompareOrdinal(a.Name, b.Name); });
                return list;
            }
        }

        public ICollection<string> SecretNames()
        {
            List<string> names = new List<string>();
            foreach (VaultSecretEntry e in ListSecrets()) names.Add(e.Name);
            return names;
        }

        public VaultSecretEntry FindSecret(string name)
        {
            lock (gate)
            {
                PwEntry e = Entry(SecretsGroup, name);
                return e == null ? null : ToEntry(e);
            }
        }

        public byte[] ReadValue(string name)
        {
            lock (gate)
            {
                PwEntry e = Entry(SecretsGroup, name);
                return e == null ? null : e.Strings.GetSafe(PwDefs.PasswordField).ReadUtf8();
            }
        }

        public CAMaterial ReadCA()
        {
            lock (gate)
            {
                PwEntry e = Entry(CAGroup, CAEntryTitle);
                if (e == null) return null;
                try
                {
                    string created = e.Strings.ReadSafe(CreatedAtField);
                    return new CAMaterial(
                        Convert.FromBase64String(e.Strings.GetSafe(PwDefs.PasswordField).ReadString()),
                        Convert.FromBase64String(e.Strings.ReadSafe(CertificateField)),
                        created.Length > 0 ? Json.ParseDate(created) : e.CreationTime.ToUniversalTime());
                }
                catch (FormatException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, CAEntryTitle, "entrée CA illisible", ex); }
                catch (JsonException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, CAEntryTitle, "entrée CA illisible", ex); }
            }
        }

        // ---- Écriture --------------------------------------------------

        public void AddSecret(string name, byte[] value, IList<string> hosts, DateTime createdAt)
        {
            Mutate(delegate
            {
                PwGroup g = Group(SecretsGroup, true);
                foreach (PwEntry existing in g.Entries)
                    if (string.Equals(existing.Strings.ReadSafe(PwDefs.TitleField), name, StringComparison.OrdinalIgnoreCase))
                        throw new SecretStoreException(SecretStoreErrorKind.Duplicate, name, "secret déjà présent : " + existing.Strings.ReadSafe(PwDefs.TitleField));
                PwEntry e = new PwEntry(true, true);
                e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, name));
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, value));
                e.Strings.Set(HostsField, new ProtectedString(false, Json.EmitCompact(new List<string>(hosts))));
                e.Strings.Set(CreatedAtField, new ProtectedString(false, Json.FormatDate(createdAt)));
                g.AddEntry(e, true);
            });
        }

        public void SetAllowedHosts(string name, IList<string> hosts)
        {
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                e.Strings.Set(HostsField, new ProtectedString(false, Json.EmitCompact(new List<string>(hosts))));
                e.Touch(true);
            });
        }

        public void SetValue(string name, byte[] value)
        {
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, value));
                e.Touch(true);
            });
        }

        public bool DeleteSecret(string name)
        {
            bool removed = false;
            Mutate(delegate
            {
                PwEntry e = Entry(SecretsGroup, name);
                if (e == null) throw new SecretStoreException(SecretStoreErrorKind.UnknownSecret, name, "secret inconnu : " + name);
                removed = Group(SecretsGroup, false).Entries.Remove(e);
            });
            return removed;
        }

        public void WriteCA(CAMaterial material)
        {
            Mutate(delegate
            {
                PwGroup g = Group(CAGroup, true);
                PwEntry e = Entry(CAGroup, CAEntryTitle);
                if (e == null)
                {
                    e = new PwEntry(true, true);
                    e.Strings.Set(PwDefs.TitleField, new ProtectedString(false, CAEntryTitle));
                    g.AddEntry(e, true);
                }
                e.Strings.Set(PwDefs.PasswordField, new ProtectedString(true, Convert.ToBase64String(material.PrivateKeyPkcs8)));
                e.Strings.Set(CertificateField, new ProtectedString(false, Convert.ToBase64String(material.CertificateDer)));
                e.Strings.Set(CreatedAtField, new ProtectedString(false, Json.FormatDate(material.CreatedAt)));
                e.Touch(true);
            });
        }

        /// <summary>Verrou process → refus si KeePass.exe a la base (`.lock`) → backup horodaté + rotation → mutation → Save.</summary>
        private void Mutate(Action action)
        {
            lock (gate)
            {
                if (db == null) throw new ObjectDisposedException("KeePassVault");
                if (IsBusy)
                    throw new SecretStoreException(SecretStoreErrorKind.VaultBusy, null,
                        "la base est ouverte dans KeePass (" + LockPath + " présent) : fermez-la dans KeePass avant de modifier des secrets");
                try
                {
                    Backups.CopyWithStamp(Path, BackupsDir, "iris", ".kdbx", Clock());
                    Backups.Rotate(BackupsDir, "iris", ".kdbx", MaxBackups);
                }
                catch (IOException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "backup du coffre impossible : " + ex.Message, ex); }
                catch (UnauthorizedAccessException ex) { throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "backup du coffre impossible : " + ex.Message, ex); }
                action();
                SaveUnlocked();
            }
        }

        private void SaveUnlocked()
        {
            try { db.Save(new NullStatusLogger()); }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                    throw new SecretStoreException(SecretStoreErrorKind.DataCorruption, null, "écriture du coffre impossible : " + ex.Message, ex);
                throw;
            }
        }

        public void Dispose()
        {
            lock (gate)
            {
                if (db == null) return;
                db.Close();
                db = null;
            }
        }
    }
}
