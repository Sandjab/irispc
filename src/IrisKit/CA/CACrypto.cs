using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Primitives du CA (SPECS §11.1, spec socle §6.1) sur CNG : ECDSA P-256, PKCS#8 (`Pkcs8PrivateBlob`),
    /// racine auto-signée CN=IRIS local CA, O=iris, 10 ans, basicConstraints CA:TRUE, keyUsage keyCertSign+cRLSign.
    /// </summary>
    public static class CACrypto
    {
        public const string Subject = "CN=IRIS local CA, O=iris";

        public static ECDsaCng GenerateKey()
        {
            return new ECDsaCng(ECCurve.NamedCurves.nistP256);
        }

        public static byte[] ExportPkcs8(ECDsaCng key)
        {
            return key.Key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
        }

        public static ECDsaCng ImportPkcs8(byte[] pkcs8)
        {
            return new ECDsaCng(CngKey.Import(pkcs8, CngKeyBlobFormat.Pkcs8PrivateBlob));
        }

        /// <summary>Racine auto-signée ; rend la partie publique seulement (la clé reste dans `key`). notBefore antidaté d'une heure.</summary>
        public static X509Certificate2 CreateRootCertificate(ECDsaCng key, DateTime now, int validityYears)
        {
            CertificateRequest req = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
            DateTimeOffset notBefore = new DateTimeOffset(now.ToUniversalTime()).AddHours(-1);
            using (X509Certificate2 withKey = req.CreateSelfSigned(notBefore, notBefore.AddYears(validityYears).AddHours(1)))
            {
                return new X509Certificate2(withKey.Export(X509ContentType.Cert));
            }
        }

        public static byte[] RandomSerial()
        {
            byte[] serial = new byte[16];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) rng.GetBytes(serial);
            serial[0] &= 0x7f;
            if (serial[0] == 0) serial[0] = 1;
            return serial;
        }

        public static string Fingerprint(byte[] der)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(der);
                StringBuilder sb = new StringBuilder(95);
                for (int i = 0; i < digest.Length; i++)
                {
                    if (i > 0) sb.Append(':');
                    sb.Append(digest[i].ToString("x2"));
                }
                return sb.ToString();
            }
        }

        public static string ToPem(byte[] der)
        {
            StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
            string b64 = Convert.ToBase64String(der);
            for (int i = 0; i < b64.Length; i += 64)
                sb.Append(b64, i, Math.Min(64, b64.Length - i)).Append('\n');
            sb.Append("-----END CERTIFICATE-----\n");
            return sb.ToString();
        }

        /// <summary>La clé publique de `key` est-elle celle du certificat ?</summary>
        public static bool SameKey(ECDsa key, X509Certificate2 certificate)
        {
            using (ECDsa pub = certificate.GetECDsaPublicKey())
            {
                if (pub == null) return false;
                ECParameters a = key.ExportParameters(false);
                ECParameters b = pub.ExportParameters(false);
                return Convert.ToBase64String(a.Q.X) == Convert.ToBase64String(b.Q.X) && Convert.ToBase64String(a.Q.Y) == Convert.ToBase64String(b.Q.Y);
            }
        }

        // ---- Feuilles (SPECS §11.2) -------------------------------------------

        public const int LeafValidityDays = 90;

        /// <summary>
        /// Feuille pour `host` : CN et SAN DNS = hôte, serverAuth, digitalSignature+keyEncipherment, CA:FALSE, série aléatoire,
        /// signée par la clé du CA (jamais exportée ici). La clé privée de la feuille est persistée dans le KSP par un aller-retour PFX
        /// (`PersistKeySet`) parce que Schannel refuse une clé éphémère ; l'appelant la supprime avec DestroyPrivateKey.
        /// </summary>
        public static X509Certificate2 CreateLeafCertificate(string host, X509Certificate2 caCertificate, ECDsa caKey, DateTime now, int validityDays)
        {
            using (ECDsaCng leafKey = new ECDsaCng(ECCurve.NamedCurves.nistP256))
            {
                CertificateRequest req = new CertificateRequest("CN=" + host, leafKey, HashAlgorithmName.SHA256);
                req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));
                req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
                SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                san.AddDnsName(host);
                req.CertificateExtensions.Add(san.Build());
                DateTimeOffset notBefore = new DateTimeOffset(now.ToUniversalTime()).AddHours(-1);
                X509SignatureGenerator generator = X509SignatureGenerator.CreateForECDsa(caKey);
                using (X509Certificate2 publicOnly = req.Create(caCertificate.SubjectName, generator, notBefore, notBefore.AddDays(validityDays).AddHours(1), RandomSerial()))
                using (X509Certificate2 withKey = publicOnly.CopyWithPrivateKey(leafKey))
                {
                    byte[] pfx = withKey.Export(X509ContentType.Pfx, "iris");
                    try { return new X509Certificate2(pfx, "iris", X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet); }
                    finally { Array.Clear(pfx, 0, pfx.Length); }
                }
            }
        }

        /// <summary>Nom du conteneur CNG de la clé privée (null si absente ou non CNG).</summary>
        public static string PrivateKeyName(X509Certificate2 certificate)
        {
            using (ECDsaCng key = certificate.GetECDsaPrivateKey() as ECDsaCng)
            {
                return key == null ? null : key.Key.KeyName;
            }
        }

        /// <summary>Supprime le conteneur CNG de la clé privée (spec §8.4 : une feuille évincée ne survit pas) et libère le certificat.</summary>
        public static void DestroyPrivateKey(X509Certificate2 certificate)
        {
            try
            {
                using (ECDsaCng key = certificate.GetECDsaPrivateKey() as ECDsaCng)
                {
                    if (key != null) key.Key.Delete();
                }
            }
            catch (CryptographicException ex) { Log.Warn("ca", "suppression de la clé d'une feuille impossible : " + ex.Message); }
        }
    }
}
