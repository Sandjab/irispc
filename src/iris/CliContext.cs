using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using IrisKit;

namespace IrisCli
{
    /// <summary>
    /// Tout ce que la CLI lit ou écrit hors du pipe, injecté pour que Cli.Run soit testable en process (spec phase 5 §3).
    /// Le nom du pipe par défaut se déduit de `DataDirectory` (PipeNames).
    /// </summary>
    public sealed class CliContext
    {
        private volatile bool interruptible;

        public TextWriter Out;
        public TextWriter Err;
        public Stream In;
        public bool IsStdinRedirected;
        public IPasswordReader Passwords;
        public string ExpectedServerPath;
        public string DataDirectory;
        public IDictionary<string, string> EnvironmentVariables;
        public string UserProfile;
        public CancellationToken Cancel;
        public Func<DateTime> Now;
        public TimeSpan ConnectTimeout;
        /// <summary>Empreinte SHA-1 → présente dans un magasin racine de confiance (doctor) ; injectée par les tests.</summary>
        public Func<string, bool> IsCaTrusted;

        /// <summary>Vrai pendant une commande longue (logs --follow, mcp wrap --watch) : Ctrl+C l'arrête proprement au lieu de tuer le processus.</summary>
        public bool Interruptible
        {
            get { return interruptible; }
            set { interruptible = value; }
        }

        public static CliContext ForConsole(TextWriter stdout, TextWriter stderr, CancellationToken cancel)
        {
            CliContext c = new CliContext();
            c.Out = stdout;
            c.Err = stderr;
            c.In = Console.OpenStandardInput();
            c.IsStdinRedirected = Console.IsInputRedirected;
            c.Passwords = new ConsolePasswordReader();
            c.ExpectedServerPath = AdminClient.DefaultServerPath();
            c.DataDirectory = DataDir.Resolve(null);
            c.EnvironmentVariables = CurrentEnvironment();
            c.UserProfile = System.Environment.GetFolderPath(System.Environment.SpecialFolder.UserProfile);
            c.Cancel = cancel;
            c.Now = delegate { return DateTime.UtcNow; };
            c.ConnectTimeout = TimeSpan.FromSeconds(2);
            c.IsCaTrusted = CATrust.IsInAnyRoot;
            return c;
        }

        private static IDictionary<string, string> CurrentEnvironment()
        {
            Dictionary<string, string> env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry e in System.Environment.GetEnvironmentVariables()) env[(string)e.Key] = (string)e.Value;
            return env;
        }
    }
}
