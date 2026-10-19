using System.Security.Cryptography.X509Certificates;

namespace IrisKit
{
    /// <summary>Lecture seule du magasin CurrentUser\Root (`ca.is_trusted`) ; l'installation du CA arrive en phase 7.</summary>
    public static class CATrust
    {
        /// <summary>Le certificat d'empreinte SHA-1 `thumbprint` est-il dans CurrentUser\Root ? Sans invite, sans écriture.</summary>
        public static bool IsInCurrentUserRoot(string thumbprint)
        {
            X509Store store = new X509Store(StoreName.Root, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
            }
            finally { store.Close(); }
        }

        /// <summary>Présent dans CurrentUser\Root ou LocalMachine\Root (iris doctor : une installation machine compte aussi). Lecture seule.</summary>
        public static bool IsInAnyRoot(string thumbprint)
        {
            return InStore(StoreLocation.CurrentUser, thumbprint) || InStore(StoreLocation.LocalMachine, thumbprint);
        }

        private static bool InStore(StoreLocation location, string thumbprint)
        {
            X509Store store = new X509Store(StoreName.Root, location);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Count > 0;
            }
            catch (System.Security.Cryptography.CryptographicException) { return false; }
            finally { store.Close(); }
        }
    }
}
