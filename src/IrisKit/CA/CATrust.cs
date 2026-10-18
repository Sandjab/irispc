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
    }
}
