using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IrisKit;
using KeePassLib;
using KeePassLib.Interfaces;
using KeePassLib.Keys;
using KeePassLib.Serialization;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- CA ------------------------------------------------------

        private static void CA_GenerateAndReload()
        {
            string dir = TestDir.Create();
            try
            {
                string pem = Path.Combine(dir, "ca.pem");
                InMemoryCAKeyStore store = new InMemoryCAKeyStore();
                CACertificate info;
                string thumbprint;
                using (CAManager ca = new CAManager(store, pem, delegate { return T0; }))
                {
                    info = ca.EnsureCA();
                    Check.True(ca.Regenerated, "première génération");
                    X509Certificate2 cert = ca.Certificate;
                    thumbprint = cert.Thumbprint;
                    Check.Eq("CN=IRIS local CA, O=iris", cert.Subject, "sujet");
                    Check.Eq(cert.Subject, cert.Issuer, "auto-signé");
                    Check.True(!cert.HasPrivateKey, "Certificate est la partie publique seulement");
                    bool caTrue = false, keyUsageOk = false;
                    foreach (X509Extension ext in cert.Extensions)
                    {
                        X509BasicConstraintsExtension bc = ext as X509BasicConstraintsExtension;
                        if (bc != null) caTrue = bc.CertificateAuthority && bc.Critical;
                        X509KeyUsageExtension ku = ext as X509KeyUsageExtension;
                        if (ku != null) keyUsageOk = (ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0 && (ku.KeyUsages & X509KeyUsageFlags.CrlSign) != 0;
                    }
                    Check.True(caTrue && keyUsageOk, "basicConstraints CA:TRUE critique, keyUsage keyCertSign+cRLSign");
                    Check.True(cert.NotBefore.ToUniversalTime() <= T0 && cert.NotAfter.ToUniversalTime() >= T0.AddYears(10).AddDays(-1), "validité 10 ans, notBefore antidaté");
                    Check.True(info.FingerprintSha256.Length == 95 && info.FingerprintSha256.Contains(":"), "empreinte SHA-256 hex avec deux-points");
                    Check.True(File.ReadAllText(pem).StartsWith("-----BEGIN CERTIFICATE-----\n") && File.ReadAllText(pem).EndsWith("-----END CERTIFICATE-----\n"), "ca.pem PEM");
                    Check.Eq(thumbprint, new X509Certificate2(pem).Thumbprint, "ca.pem = le certificat");
                    byte[] data = Encoding.UTF8.GetBytes("tbs");
                    byte[] sig = ca.SigningKey.SignData(data, HashAlgorithmName.SHA256);
                    Check.True(cert.GetECDsaPublicKey().VerifyData(data, sig, HashAlgorithmName.SHA256), "la clé de signature correspond au certificat");
                }
                Check.True(store.Load() != null && store.Load().CertificateDer.Length > 0 && store.Load().PrivateKeyPkcs8.Length > 100, "matériel stocké");
                File.WriteAllText(pem, "périmé");
                using (CAManager again = new CAManager(store, pem, delegate { return T0.AddDays(1); }))
                {
                    again.EnsureCA();
                    Check.True(!again.Regenerated && again.Certificate.Thumbprint == thumbprint, "rechargé depuis le store, pas régénéré");
                    Check.Eq(thumbprint, new X509Certificate2(pem).Thumbprint, "ca.pem réécrit s'il ne correspond plus");
                    byte[] data = Encoding.UTF8.GetBytes("tbs2");
                    Check.True(again.Certificate.GetECDsaPublicKey().VerifyData(data, again.SigningKey.SignData(data, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256), "clé réimportée depuis PKCS#8 utilisable");
                }
                using (CAManager noPem = new CAManager(store, null, delegate { return T0; }))
                {
                    noPem.EnsureCA();
                    Check.True(!noPem.Regenerated, "pemPath null : pas d'export, pas de régénération");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void CA_MismatchOrExpiredRegenerates()
        {
            InMemoryCAKeyStore store = new InMemoryCAKeyStore();
            using (ECDsaCng k1 = CACrypto.GenerateKey())
            using (ECDsaCng k2 = CACrypto.GenerateKey())
            {
                X509Certificate2 certOfK2 = CACrypto.CreateRootCertificate(k2, T0, 10);
                store.Store(new CAMaterial(CACrypto.ExportPkcs8(k1), certOfK2.Export(X509ContentType.Cert), T0));
                using (CAManager ca = new CAManager(store, null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(ca.Regenerated && ca.Certificate.Thumbprint != certOfK2.Thumbprint, "clé et certificat désaccordés → régénéré");
                    Check.True(CACrypto.SameKey(ca.SigningKey, ca.Certificate), "nouveau couple cohérent");
                }
                X509Certificate2 expired = CACrypto.CreateRootCertificate(k1, T0.AddYears(-11), 10);
                store.Store(new CAMaterial(CACrypto.ExportPkcs8(k1), expired.Export(X509ContentType.Cert), T0.AddYears(-11)));
                using (CAManager ca = new CAManager(store, null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(ca.Regenerated, "certificat expiré → régénéré");
                }
            }
        }

        private static void CA_KeePassKeyStore()
        {
            string dir = TestDir.Create();
            try
            {
                string kdbx = Path.Combine(dir, "iris.kdbx");
                string thumbprint;
                using (KeePassVault vault = KeePassVault.Create(kdbx, Secure("p"), T0))
                using (CAManager ca = new CAManager(new KeePassCAKeyStore(vault), Path.Combine(dir, "ca.pem"), delegate { return T0; }))
                {
                    vault.BackupsDir = Path.Combine(dir, "backups");
                    ca.EnsureCA();
                    thumbprint = ca.Certificate.Thumbprint;
                }
                using (KeePassVault vault = KeePassVault.Open(kdbx, Secure("p")))
                using (CAManager ca = new CAManager(new KeePassCAKeyStore(vault), null, delegate { return T0; }))
                {
                    ca.EnsureCA();
                    Check.True(!ca.Regenerated && ca.Certificate.Thumbprint == thumbprint, "CA persisté dans le coffre et rechargé");
                }
                string pemText = File.ReadAllText(Path.Combine(dir, "ca.pem"));
                byte[] kdbxBytes = File.ReadAllBytes(kdbx);
                Check.True(Encoding.ASCII.GetString(kdbxBytes).IndexOf("BEGIN", StringComparison.Ordinal) < 0, "rien en clair dans le kdbx (chiffré)");
                Check.True(!pemText.Contains("PRIVATE"), "ca.pem ne contient que le certificat");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
