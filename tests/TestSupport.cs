using System;
using System.IO;
using System.Security;

namespace Iris.Tests
{
    /// <summary>Dossiers temporaires isolés : jamais une base ou une config utilisateur.</summary>
    public static class TestDir
    {
        public static string Create()
        {
            string dir = Path.Combine(Path.GetTempPath(), "irispc-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(dir);
            return dir;
        }

        public static void Delete(string dir)
        {
            try { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    public static partial class TestMain
    {
        public static SecureString Secure(string text)
        {
            SecureString s = new SecureString();
            foreach (char c in text) s.AppendChar(c);
            s.MakeReadOnly();
            return s;
        }
    }
}
