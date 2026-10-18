using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Feuilles et confiance amont ---------------------------------------

        private static CAManager FreshCA()
        {
            CAManager ca = new CAManager(new InMemoryCAKeyStore(), null, delegate { return DateTime.UtcNow; });
            ca.EnsureCA();
            return ca;
        }

        private static bool ChainsTo(X509Certificate2 leaf, X509Certificate2 root)
        {
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            bool built = chain.Build(leaf);
            return built && chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint == root.Thumbprint;
        }

        private static void Leaf_SignedByCA_SanValidity()
        {
            using (CAManager ca = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; }))
            {
                X509Certificate2 leaf = cache.Get("Example.COM");
                Check.Eq("CN=example.com", leaf.Subject, "CN = hôte normalisé");
                Check.Eq(ca.Certificate.Subject, leaf.Issuer, "émetteur = CA");
                Check.True(leaf.HasPrivateKey, "clé privée attachée");
                Check.True(ChainsTo(leaf, ca.Certificate), "signature vérifiable par X509Chain avec le CA");
                bool san = false, serverAuth = false, notCa = false;
                foreach (X509Extension ext in leaf.Extensions)
                {
                    if (ext.Oid.Value == "2.5.29.17") san = ext.Format(false).ToLowerInvariant().Contains("example.com");
                    X509EnhancedKeyUsageExtension eku = ext as X509EnhancedKeyUsageExtension;
                    if (eku != null) foreach (Oid o in eku.EnhancedKeyUsages) if (o.Value == "1.3.6.1.5.5.7.3.1") serverAuth = true;
                    X509BasicConstraintsExtension bc = ext as X509BasicConstraintsExtension;
                    if (bc != null) notCa = !bc.CertificateAuthority;
                }
                Check.True(san, "SAN DNS = hôte");
                Check.True(serverAuth, "EKU serverAuth");
                Check.True(notCa, "basicConstraints CA:FALSE");
                double days = (leaf.NotAfter.ToUniversalTime() - leaf.NotBefore.ToUniversalTime()).TotalDays;
                Check.True(days > 89.9 && days < 90.2, "validité ≈ 90 jours (notBefore antidaté d'une heure)");
                Check.True(leaf.NotBefore.ToUniversalTime() < DateTime.UtcNow, "déjà valide");
                Check.True(leaf.SerialNumber.Length >= 16, "série aléatoire de 16 octets (RandomSerial)");
            }
        }

        private static void Leaf_CacheEvictAndDispose_DeleteCngKeys()
        {
            string nameA, nameB;
            using (CAManager ca = FreshCA())
            {
                LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; });
                X509Certificate2 a1 = cache.Get("alpha.example");
                X509Certificate2 a2 = cache.Get("ALPHA.example");
                X509Certificate2 b = cache.Get("beta.example");
                Check.Eq(a1.Thumbprint, a2.Thumbprint, "même hôte (insensible à la casse) = même feuille");
                Check.True(a1.Thumbprint != b.Thumbprint, "hôtes différents = feuilles différentes");
                Check.Eq(2, cache.Count, "deux entrées");
                nameA = CACrypto.PrivateKeyName(a1);
                nameB = CACrypto.PrivateKeyName(b);
                Check.True(nameA != null && CngKey.Exists(nameA), "la clé de la feuille est un conteneur CNG persistant");
                Check.True(cache.Evict("alpha.example"), "éviction");
                Check.True(!CngKey.Exists(nameA), "le conteneur CNG n'existe plus après Evict (spec §8.4)");
                Check.True(!cache.Evict("alpha.example"), "éviction d'un absent = false");
                Check.Eq(1, cache.Count, "une entrée");
                cache.Dispose();
                Check.True(!CngKey.Exists(nameB), "Dispose supprime les clés restantes");
                Check.Eq(0, cache.Count, "vide après Dispose");
            }
        }

        private static void Leaf_RenewalNearExpiry()
        {
            DateTime now = DateTime.UtcNow;
            DateTime clock = now;
            using (CAManager ca = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return clock; }))
            {
                X509Certificate2 first = cache.Get("renew.example");
                string firstKey = CACrypto.PrivateKeyName(first);
                clock = now.AddDays(10);
                Check.Eq(first.Thumbprint, cache.Get("renew.example").Thumbprint, "dix jours plus tard : même feuille");
                clock = now.AddDays(90).AddHours(-12);
                X509Certificate2 renewed = cache.Get("renew.example");
                Check.True(renewed.Thumbprint != first.Thumbprint, "moins d'un jour avant expiration : renouvelée");
                Check.True(!CngKey.Exists(firstKey), "la clé de l'ancienne feuille est supprimée au renouvellement");
                Check.Eq(1, cache.Count, "toujours une entrée");
            }
        }

        private static void Leaf_SchannelHandshake_PinnedTrust()
        {
            using (CAManager ca = FreshCA())
            using (CAManager other = FreshCA())
            using (LeafCertCache cache = new LeafCertCache(ca, delegate { return DateTime.UtcNow; }))
            {
                X509Certificate2 leaf = cache.Get("localhost");
                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                Task server = Task.Run(async delegate
                {
                    for (int i = 0; i < 3; i++)
                    {
                        using (TcpClient c = await listener.AcceptTcpClientAsync())
                        using (SslStream ssl = new SslStream(c.GetStream(), false))
                        {
                            try
                            {
                                await ssl.AuthenticateAsServerAsync(leaf, false, SslProtocols.Tls12, false);
                                byte[] buf = new byte[16];
                                int n = await ssl.ReadAsync(buf, 0, buf.Length);
                                byte[] reply = Encoding.ASCII.GetBytes("pong:" + Encoding.ASCII.GetString(buf, 0, n));
                                await ssl.WriteAsync(reply, 0, reply.Length);
                            }
                            catch (IOException) { }
                            catch (AuthenticationException) { }
                        }
                    }
                });
                try
                {
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(ca.Certificate))))
                    {
                        ssl.AuthenticateAsClient("localhost", null, SslProtocols.Tls12, false);
                        Check.Eq(SslProtocols.Tls12, ssl.SslProtocol, "TLS 1.2 négocié avec la feuille ECDSA persistée (Schannel)");
                        ssl.Write(Encoding.ASCII.GetBytes("ping"));
                        byte[] buf = new byte[16];
                        int n = ssl.Read(buf, 0, buf.Length);
                        Check.Eq("pong:ping", Encoding.ASCII.GetString(buf, 0, n), "échange chiffré");
                    }
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(other.Certificate))))
                        Check.Throws<AuthenticationException>(delegate { ssl.AuthenticateAsClient("localhost", null, SslProtocols.Tls12, false); }, "autre racine épinglée → refus");
                    using (TcpClient client = new TcpClient("127.0.0.1", port))
                    using (SslStream ssl = new SslStream(client.GetStream(), false, UpstreamTrustAdapter.Callback(new PinnedRootTrust(ca.Certificate))))
                        Check.Throws<AuthenticationException>(delegate { ssl.AuthenticateAsClient("other.example", null, SslProtocols.Tls12, false); }, "nom d'hôte différent du SAN → refus");
                }
                finally
                {
                    listener.Stop();
                    try { server.Wait(2000); } catch (AggregateException) { }
                }
            }
        }

        private static void UpstreamTrust_System()
        {
            SystemTrust trust = new SystemTrust();
            using (CAManager ca = FreshCA())
            {
                Check.True(trust.Validate(ca.Certificate, null, SslPolicyErrors.None), "aucune erreur → accepté");
                Check.True(!trust.Validate(ca.Certificate, null, SslPolicyErrors.RemoteCertificateChainErrors), "chaîne non fiable → refusé");
                Check.True(!trust.Validate(ca.Certificate, null, SslPolicyErrors.RemoteCertificateNameMismatch), "nom → refusé");
                Check.True(trust.Describe().Length > 0 && new PinnedRootTrust(ca.Certificate).Describe().Contains(ca.Certificate.Thumbprint.Substring(0, 8).ToLowerInvariant()), "Describe");
            }
        }
    }
}
