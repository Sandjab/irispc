using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IrisKit
{
    public sealed class CACertificate
    {
        public byte[] Der { get; private set; }
        public string Pem { get; private set; }
        public string FingerprintSha256 { get; private set; }
        public DateTime NotBefore { get; private set; }
        public DateTime NotAfter { get; private set; }
        public string Subject { get; private set; }

        public CACertificate(X509Certificate2 certificate)
        {
            Der = certificate.Export(X509ContentType.Cert);
            Pem = CACrypto.ToPem(Der);
            FingerprintSha256 = CACrypto.Fingerprint(Der);
            NotBefore = certificate.NotBefore.ToUniversalTime();
            NotAfter = certificate.NotAfter.ToUniversalTime();
            Subject = certificate.Subject;
        }
    }

    /// <summary>
    /// Charge le CA depuis le store ou le génère (clé + certificat stockés ensemble), vérifie la cohérence
    /// clé/certificat et la validité (sinon régénère, avec avertissement), exporte ca.pem si demandé.
    /// </summary>
    public sealed class CAManager : IDisposable
    {
        public const int ValidityYears = 10;
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        private readonly ICAKeyStore store;
        private readonly string pemPath;
        private readonly Func<DateTime> clock;

        public X509Certificate2 Certificate { get; private set; }
        public ECDsaCng SigningKey { get; private set; }
        public CACertificate Info { get; private set; }
        public bool Regenerated { get; private set; }

        public CAManager(ICAKeyStore store, string pemPath, Func<DateTime> clock)
        {
            if (store == null) throw new ArgumentNullException("store");
            this.store = store;
            this.pemPath = pemPath;
            this.clock = clock;
        }

        public CACertificate EnsureCA()
        {
            DateTime now = clock();
            CAMaterial material = store.Load();
            if (material != null && TryLoad(material, now))
            {
                Regenerated = false;
            }
            else
            {
                if (material != null) Log.Warn("ca", "CA stocké inutilisable (clé et certificat désaccordés, ou certificat hors validité) : régénération, les clients devront réapprouver data\\ca.pem");
                Generate(now);
                Regenerated = true;
            }
            Info = new CACertificate(Certificate);
            ExportPem();
            Log.Info("ca", "CA " + (Regenerated ? "généré" : "chargé") + " : " + Info.Subject + ", empreinte SHA-256 " + Info.FingerprintSha256 + ", valide jusqu'au " + Json.FormatDate(Info.NotAfter));
            return Info;
        }

        private bool TryLoad(CAMaterial material, DateTime now)
        {
            ECDsaCng key = null;
            X509Certificate2 cert = null;
            try
            {
                key = CACrypto.ImportPkcs8(material.PrivateKeyPkcs8);
                cert = new X509Certificate2(material.CertificateDer);
                if (!CACrypto.SameKey(key, cert)) return false;
                if (cert.NotBefore.ToUniversalTime() > now || cert.NotAfter.ToUniversalTime() <= now) return false;
                if (cert.Subject != CACrypto.Subject) return false;
                SigningKey = key;
                Certificate = cert;
                key = null;
                return true;
            }
            catch (CryptographicException ex)
            {
                Log.Warn("ca", "matériel CA illisible : " + ex.Message);
                return false;
            }
            finally
            {
                if (key != null) key.Dispose();
            }
        }

        private void Generate(DateTime now)
        {
            ECDsaCng key = CACrypto.GenerateKey();
            X509Certificate2 cert = CACrypto.CreateRootCertificate(key, now, ValidityYears);
            store.Store(new CAMaterial(CACrypto.ExportPkcs8(key), cert.Export(X509ContentType.Cert), now));
            SigningKey = key;
            Certificate = cert;
        }

        private void ExportPem()
        {
            if (pemPath == null) return;
            try
            {
                if (File.Exists(pemPath) && File.ReadAllText(pemPath, Encoding.UTF8) == Info.Pem) return;
                Directory.CreateDirectory(Path.GetDirectoryName(pemPath));
                File.WriteAllText(pemPath, Info.Pem, Utf8NoBom);
                Log.Info("ca", "certificat public exporté : " + pemPath);
            }
            catch (IOException ex) { Log.Error("ca", "export de " + pemPath + " impossible : " + ex.Message); }
            catch (UnauthorizedAccessException ex) { Log.Error("ca", "export de " + pemPath + " impossible : " + ex.Message); }
        }

        public void Dispose()
        {
            if (SigningKey != null) { SigningKey.Dispose(); SigningKey = null; }
            if (Certificate != null) { Certificate.Reset(); Certificate = null; }
        }
    }
}
