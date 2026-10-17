using System;

namespace IrisKit
{
    /// <summary>Clé privée (PKCS#8 DER) et certificat (DER) du CA, tels que stockés dans le coffre (spec §4.1, groupe `ca`).</summary>
    public sealed class CAMaterial
    {
        public byte[] PrivateKeyPkcs8 { get; private set; }
        public byte[] CertificateDer { get; private set; }
        public DateTime CreatedAt { get; private set; }

        public CAMaterial(byte[] privateKeyPkcs8, byte[] certificateDer, DateTime createdAt)
        {
            PrivateKeyPkcs8 = (byte[])privateKeyPkcs8.Clone();
            CertificateDer = (byte[])certificateDer.Clone();
            CreatedAt = createdAt;
        }
    }
}
