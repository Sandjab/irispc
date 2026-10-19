using System;
using System.IO;
using System.Threading;
using IrisKit;

namespace Irisd
{
    /// <summary>Point d'entrée testable (revue phase 0) : analyse des arguments, aide, version, puis Daemon.Run.</summary>
    public static class Entry
    {
        public static int Run(string[] args, TextWriter stdout, TextWriter stderr, IPasswordReader console, CancellationToken cancel)
        {
            Arguments options;
            try { options = Arguments.Parse(args); }
            catch (ArgumentsException ex)
            {
                stderr.WriteLine("irisd : " + ex.Message);
                stderr.WriteLine();
                stderr.Write(Arguments.Usage());
                return ExitCodes.Arguments;
            }
            if (options.ShowHelp) { stdout.Write(Arguments.Usage()); return ExitCodes.Ok; }
            if (options.ShowVersion) { stdout.WriteLine("irisd " + IrisVersion.Value); return ExitCodes.Ok; }
            if (!options.Foreground)
            {
                // Sans --foreground le socle affiche l'aide et sort code 1 (le mode arrière-plan arrive avec le lot autostart).
                stderr.Write(Arguments.Usage());
                return ExitCodes.Data;
            }
            try { return new Daemon(options, stdout, stderr, console).Run(cancel); }
            catch (SecretStoreException ex)
            {
                stderr.WriteLine("irisd : coffre : " + ex.Message);
                return ExitCodes.Vault;
            }
            catch (Exception ex)
            {
                // Garde-fou : jamais de trace de pile brute pour l'utilisateur (le message d'une exception ne contient jamais de secret).
                stderr.WriteLine("irisd : erreur inattendue (" + ex.GetType().Name + ") : " + ex.Message);
                return ExitCodes.Data;
            }
        }
    }
}
