using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace IrisKit
{
    /// <summary>Validation du certificat amont (spec §6.1 : validation standard via le magasin Windows ; épinglage pour les tests).</summary>
    public interface IUpstreamTrust
    {
        bool Validate(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors);
        string Describe();
    }

    /// <summary>Magasin de certificats Windows : seule une chaîne sans erreur est acceptée.</summary>
    public sealed class SystemTrust : IUpstreamTrust
    {
        public bool Validate(X509Certificate2 certificate, X509Chain chain, SslPolicyErrors errors) { return errors == SslPolicyErrors.None; }
        public string Describe() { return "magasin Windows"; }
    }

    /// <summary>Racine épinglée (tests et MockUpstream) : la chaîne doit se construire jusqu'à cette racine et le nom doit correspondre.</summary>
    public sealed class PinnedRootTrust : IUpstreamTrust
    {
        private readonly X509Certificate2 root;

        public PinnedRootTrust(X509Certificate2 root)
        {
            if (root == null) throw new ArgumentNullException("root");
            this.root = root;
        }

        public bool Validate(X509Certificate2 certificate, X509Chain ignored, SslPolicyErrors errors)
        {
            if ((errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0 || (errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(root);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            if (!chain.Build(certificate)) return false;
            return chain.ChainElements[chain.ChainElements.Count - 1].Certificate.Thumbprint == root.Thumbprint;
        }

        public string Describe() { return "racine épinglée " + root.Thumbprint.ToLowerInvariant(); }
    }

    public static class UpstreamTrustAdapter
    {
        public static RemoteCertificateValidationCallback Callback(IUpstreamTrust trust)
        {
            return delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
            {
                if (certificate == null) return false;
                return trust.Validate(new X509Certificate2(certificate), chain, errors);
            };
        }
    }
}
