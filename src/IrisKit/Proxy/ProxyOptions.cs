using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;

namespace IrisKit
{
    public class ProxyException : Exception
    {
        public ProxyException(string message) : base(message) { }
        public ProxyException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>Port du proxy déjà pris : irisd sort avec le code 3 (spec §7).</summary>
    public sealed class ProxyPortInUseException : PortBindException
    {
        public ProxyPortInUseException(int port, Exception inner)
            : base(PortBindFailure.InUse, "proxy", port,
                "le port " + port.ToString(CultureInfo.InvariantCulture) + " est déjà utilisé : un autre irisd tourne, ou un autre programme écoute dessus", inner)
        {
        }
    }

    /// <summary>Options du proxy (spec §6) ; `FromConfig` lit `broker.listen`, `hosts` et `security`.</summary>
    public sealed class ProxyOptions
    {
        public string ListenHost = "127.0.0.1";
        public int ListenPort = 8888;
        public ISet<string> AllowedHosts = new HashSet<string>(StringComparer.Ordinal);
        public SecurityConfig Security = new SecurityConfig(ExfilPolicy.BlockAndNotify, 60);
        public IUpstreamTrust UpstreamTrust = new SystemTrust();
        public TimeSpan IdleTimeout = TimeSpan.FromSeconds(120);
        public TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
        public TimeSpan ShutdownGrace = TimeSpan.FromSeconds(5);

        public static ProxyOptions FromConfig(Config config)
        {
            ProxyOptions o = new ProxyOptions();
            string[] parts = config.Broker.Listen.Split(':');
            o.ListenHost = parts[0];
            o.ListenPort = int.Parse(parts[1], CultureInfo.InvariantCulture);
            foreach (string h in config.AllowedHosts) o.AllowedHosts.Add(HostName.Normalize(h));
            o.Security = config.Security;
            return o;
        }

        public void Validate()
        {
            IPAddress ip;
            if (!IPAddress.TryParse(ListenHost, out ip) || !IPAddress.IsLoopback(ip))
                throw new ProxyException("le proxy n'écoute que sur une adresse de bouclage (127.0.0.1 ou ::1), pas sur " + ListenHost + " : il injecterait les secrets de l'utilisateur pour tout le réseau");
            if (ListenPort < 0 || ListenPort > 65535) throw new ProxyException("port d'écoute invalide : " + ListenPort);
            if (Security == null) throw new ProxyException("Security manquant");
            if (UpstreamTrust == null) throw new ProxyException("UpstreamTrust manquant");
        }
    }
}
