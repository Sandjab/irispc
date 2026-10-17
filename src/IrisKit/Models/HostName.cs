using System;

namespace IrisKit
{
    /// <summary>Nom d'hôte DNS tel qu'IRIS le valide (Secret.isValidHost) et le compare (minuscules, sans port, exact).</summary>
    public static class HostName
    {
        public static bool IsValid(string host)
        {
            if (string.IsNullOrEmpty(host) || host.Length > 253) return false;
            string[] labels = host.Split('.');
            foreach (string label in labels)
            {
                if (label.Length < 1 || label.Length > 63) return false;
                if (label[0] == '-' || label[label.Length - 1] == '-') return false;
                foreach (char c in label)
                {
                    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
                    if (!ok) return false;
                }
            }
            return true;
        }

        /// <summary>Minuscules, espaces retirés, port retiré (`host:443` → `host`).</summary>
        public static string Normalize(string host)
        {
            if (host == null) return "";
            string h = host.Trim().ToLowerInvariant();
            int colon = h.IndexOf(':');
            return colon >= 0 ? h.Substring(0, colon) : h;
        }
    }
}
