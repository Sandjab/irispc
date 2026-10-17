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

    /// <summary>Console scriptée : chaque ReadPassword rend la réponse suivante, null quand la liste est épuisée (EOF).</summary>
    public sealed class ScriptedConsoleInput : Irisd.IConsoleInput
    {
        private readonly System.Collections.Generic.Queue<string> answers;
        public System.Collections.Generic.List<string> Prompts = new System.Collections.Generic.List<string>();

        public ScriptedConsoleInput(params string[] answers)
        {
            this.answers = new System.Collections.Generic.Queue<string>(answers);
        }

        public SecureString ReadPassword(string prompt)
        {
            Prompts.Add(prompt);
            return answers.Count == 0 ? null : TestMain.Secure(answers.Dequeue());
        }
    }
}
