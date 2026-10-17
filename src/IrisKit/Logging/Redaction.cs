using System.Security.Cryptography;
using System.Text;

namespace IrisKit
{
    /// <summary>Redaction d'IRIS (SPECS §19.1) : `[REDACTED:` + 8 premiers hex du SHA-256 + `]`.</summary>
    public static class Redaction
    {
        public static string Redact(string value)
        {
            return Redact(Encoding.UTF8.GetBytes(value ?? ""));
        }

        public static string Redact(byte[] value)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] digest = sha.ComputeHash(value ?? new byte[0]);
                StringBuilder sb = new StringBuilder("[REDACTED:");
                for (int i = 0; i < 4; i++) sb.Append(digest[i].ToString("x2"));
                sb.Append(']');
                return sb.ToString();
            }
        }
    }
}
