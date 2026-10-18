using System;
using System.Globalization;
using System.Net.Sockets;

namespace IrisKit
{
    public enum PortBindFailure { InUse, AccessDenied }

    /// <summary>Écoute impossible sur un port (proxy ou flux d'events) : irisd sort avec le code 3 (spec phase 3 §9).</summary>
    public class PortBindException : ProxyException
    {
        public PortBindFailure Failure { get; private set; }
        public string Role { get; private set; }
        public int Port { get; private set; }

        public PortBindException(PortBindFailure failure, string role, int port, string message, Exception inner) : base(message, inner)
        {
            Failure = failure;
            Role = role;
            Port = port;
        }
    }

    /// <summary>Bind d'un TcpListener avec des erreurs distinctes : port pris, accès refusé (plage réservée, pare-feu), autre.</summary>
    public static class PortBinding
    {
        public static void Start(TcpListener listener, int backlog, string role, int port)
        {
            try { listener.Start(backlog); }
            catch (SocketException ex) { throw Translate(ex, role, port); }
        }

        public static ProxyException Translate(SocketException ex, string role, int port)
        {
            string p = port.ToString(CultureInfo.InvariantCulture);
            if (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                if (role == "proxy") return new ProxyPortInUseException(port, ex);
                return new PortBindException(PortBindFailure.InUse, role, port,
                    "le port " + p + " (" + role + ") est déjà utilisé : un autre irisd tourne, ou un autre programme écoute dessus", ex);
            }
            if (ex.SocketErrorCode == SocketError.AccessDenied)
                return new PortBindException(PortBindFailure.AccessDenied, role, port,
                    "accès refusé au port " + p + " (" + role + ") : plage réservée par Windows (netsh int ipv4 show excludedportrange protocol=tcp) ou pare-feu", ex);
            return new ProxyException("écoute " + role + " sur le port " + p + " impossible : " + ex.Message, ex);
        }
    }
}
