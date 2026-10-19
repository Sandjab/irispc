using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace IrisCli
{
    /// <summary>Valeurs de secrets (spec phase 5 §5) : lues en octets, jamais affichées ; les tampons intermédiaires sont effacés.</summary>
    public static class SecretValue
    {
        public static byte[] ReadAll(Stream input)
        {
            MemoryStream m = new MemoryStream();
            input.CopyTo(m);
            byte[] bytes = m.ToArray();
            Array.Clear(m.GetBuffer(), 0, (int)m.Length);
            return bytes;
        }

        /// <summary>
        /// Retire au plus un BOM UTF-8 initial (pipe de PowerShell 5.1 avec $OutputEncoding UTF-8) et au plus un `\r\n` ou un `\n`
        /// final ; vide ou fait seulement d'espaces → code 1. `raw` est effacé.
        /// </summary>
        public static byte[] Normalize(byte[] raw)
        {
            int start = raw.Length >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF ? 3 : 0;
            int end = raw.Length;
            if (end - start >= 2 && raw[end - 2] == 13 && raw[end - 1] == 10) end -= 2;
            else if (end - start >= 1 && raw[end - 1] == 10) end -= 1;
            int length = end - start;
            byte[] value = new byte[length];
            Buffer.BlockCopy(raw, start, value, 0, length);
            Array.Clear(raw, 0, raw.Length);
            if (length == 0 || IsBlank(value))
            {
                Array.Clear(value, 0, value.Length);
                throw new CliException(CliExit.Logic, "la valeur ne peut pas être vide ni faite seulement d'espaces");
            }
            return value;
        }

        /// <summary>Blanche = UTF-8 valide fait seulement d'espaces ; des octets non UTF-8 ne sont jamais blancs (valeur binaire).</summary>
        private static bool IsBlank(byte[] value)
        {
            string text;
            try { text = new UTF8Encoding(false, true).GetString(value); }
            catch (DecoderFallbackException) { return false; }
            foreach (char c in text)
                if (!char.IsWhiteSpace(c)) return false;
            return true;
        }

        /// <summary>Saisie console → octets UTF-8 ; la copie en caractères est effacée.</summary>
        public static byte[] FromSecure(SecureString s)
        {
            char[] chars = Chars(s);
            try { return Encoding.UTF8.GetBytes(chars); }
            finally { Array.Clear(chars, 0, chars.Length); }
        }

        /// <summary>SecureString → string pour la trame JSON (limite du runtime acceptée en phase 3).</summary>
        public static string ToPlain(SecureString s)
        {
            char[] chars = Chars(s);
            try { return new string(chars); }
            finally { Array.Clear(chars, 0, chars.Length); }
        }

        public static bool SameText(SecureString a, SecureString b)
        {
            char[] x = Chars(a);
            char[] y = Chars(b);
            try
            {
                if (x.Length != y.Length) return false;
                int diff = 0;
                for (int i = 0; i < x.Length; i++) diff |= x[i] ^ y[i];
                return diff == 0;
            }
            finally
            {
                Array.Clear(x, 0, x.Length);
                Array.Clear(y, 0, y.Length);
            }
        }

        private static char[] Chars(SecureString s)
        {
            IntPtr bstr = Marshal.SecureStringToBSTR(s);
            try
            {
                char[] chars = new char[s.Length];
                Marshal.Copy(bstr, chars, 0, chars.Length);
                return chars;
            }
            finally { Marshal.ZeroFreeBSTR(bstr); }
        }
    }

    public static class CliInput
    {
        /// <summary>Une ligne UTF-8 sans `\r\n` ; null en fin de flux. Octet par octet : ne consomme rien au-delà de la ligne.</summary>
        public static string ReadLine(Stream input)
        {
            MemoryStream m = new MemoryStream();
            int b;
            while ((b = input.ReadByte()) >= 0 && b != '\n') m.WriteByte((byte)b);
            if (b < 0 && m.Length == 0) return null;
            return Encoding.UTF8.GetString(m.ToArray()).TrimEnd('\r');
        }
    }
}
