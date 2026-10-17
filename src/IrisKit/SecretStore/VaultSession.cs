using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;

namespace IrisKit
{
    public static class SecureStrings
    {
        /// <summary>Comparaison en temps constant sur la longueur commune, sans laisser de copie en clair.</summary>
        public static bool Equal(SecureString a, SecureString b)
        {
            if (a == null || b == null) return false;
            if (a.Length != b.Length) return false;
            IntPtr pa = IntPtr.Zero, pb = IntPtr.Zero;
            try
            {
                pa = Marshal.SecureStringToGlobalAllocUnicode(a);
                pb = Marshal.SecureStringToGlobalAllocUnicode(b);
                int diff = 0;
                for (int i = 0; i < a.Length; i++) diff |= Marshal.ReadInt16(pa, i * 2) ^ Marshal.ReadInt16(pb, i * 2);
                return diff == 0;
            }
            finally
            {
                if (pa != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pa);
                if (pb != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pb);
            }
        }
    }

    /// <summary>
    /// Cycle de vie du coffre (spec §4.3) : chemin `data\iris.kdbx`, création ou déverrouillage par SecureString.
    /// L'API `Unlock(SecureString)` sera aussi appelée par le lot IPC (`vault.unlock`).
    /// </summary>
    public sealed class VaultSession : IDisposable
    {
        public string KdbxPath { get; private set; }
        public KeePassVault Vault { get; private set; }
        public bool Exists { get { return File.Exists(KdbxPath); } }
        public bool IsUnlocked { get { return Vault != null; } }

        public VaultSession(string dataDir)
        {
            KdbxPath = Path.Combine(dataDir, "iris.kdbx");
        }

        public KeePassVault Unlock(SecureString password)
        {
            if (Vault != null) return Vault;
            Vault = KeePassVault.Open(KdbxPath, password);
            return Vault;
        }

        public KeePassVault Create(SecureString password, DateTime now)
        {
            if (Exists) throw new SecretStoreException(SecretStoreErrorKind.Duplicate, null, "le coffre existe déjà : " + KdbxPath);
            Vault = KeePassVault.Create(KdbxPath, password, now);
            return Vault;
        }

        public void Dispose()
        {
            if (Vault != null) { Vault.Dispose(); Vault = null; }
        }
    }
}
