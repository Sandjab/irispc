using System;
using System.IO;
using System.Text;
using System.Threading;

namespace IrisCli
{
    /// <summary>iris.exe : construit le contexte réel (console, UTF-8 si redirigé, Ctrl+C) et délègue à Cli.Run.</summary>
    public static class Program
    {
        public static int Main(string[] args)
        {
            TextWriter stdout = Console.IsOutputRedirected ? Utf8(Console.OpenStandardOutput()) : Console.Out;
            TextWriter stderr = Console.IsErrorRedirected ? Utf8(Console.OpenStandardError()) : Console.Error;
            CancellationTokenSource cts = new CancellationTokenSource();
            CliContext ctx = CliContext.ForConsole(stdout, stderr, cts.Token);
            Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e)
            {
                // Commande courte : Ctrl+C garde son effet habituel. Commande longue : arrêt propre, code 0.
                if (!ctx.Interruptible) return;
                e.Cancel = true;
                cts.Cancel();
            };
            try { return Cli.Run(args, ctx); }
            finally
            {
                stdout.Flush();
                stderr.Flush();
            }
        }

        /// <summary>Sortie redirigée : UTF-8 sans BOM (consommateurs de --json) ; à la console, l'encodage de la console.</summary>
        private static TextWriter Utf8(Stream stream)
        {
            StreamWriter w = new StreamWriter(stream, new UTF8Encoding(false));
            w.AutoFlush = true;
            return w;
        }
    }
}
