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

    /// <summary>Console scriptée : chaque ReadPassword rend la réponse suivante ; liste épuisée = null (EOF), ou attente de l'annulation (OperationCanceledException) si BlockWhenExhausted.</summary>
    public sealed class ScriptedConsoleInput : IrisKit.IPasswordReader
    {
        private readonly System.Collections.Generic.Queue<string> answers;
        public System.Collections.Generic.List<string> Prompts = new System.Collections.Generic.List<string>();
        public bool BlockWhenExhausted;

        public ScriptedConsoleInput(params string[] answers)
        {
            this.answers = new System.Collections.Generic.Queue<string>(answers);
        }

        public SecureString ReadPassword(string prompt, System.Threading.CancellationToken cancel)
        {
            lock (Prompts) Prompts.Add(prompt);
            if (answers.Count > 0) return TestMain.Secure(answers.Dequeue());
            if (BlockWhenExhausted) { cancel.WaitHandle.WaitOne(); cancel.ThrowIfCancellationRequested(); }
            return null;
        }

        public int PromptCount { get { lock (Prompts) return Prompts.Count; } }
    }

    /// <summary>TextWriter verrouillé dont on peut lire un instantané depuis un autre thread (daemon lancé en tâche).</summary>
    public sealed class CapturingWriter : TextWriter
    {
        private readonly System.Text.StringBuilder sb = new System.Text.StringBuilder();
        private readonly object gate = new object();
        public override System.Text.Encoding Encoding { get { return System.Text.Encoding.UTF8; } }
        public override void Write(char value) { lock (gate) sb.Append(value); }
        public override void Write(string value) { lock (gate) sb.Append(value); }
        public string Snapshot() { lock (gate) return sb.ToString(); }
        public override string ToString() { return Snapshot(); }
    }
}
