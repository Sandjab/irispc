using System;
using System.Text;
using IrisKit;

namespace Irisd
{
    /// <summary>
    /// Point d'entrée de irisd. Phase 0 : aide, version et codes de sortie ; le daemon lui-même arrive en phase 1.
    /// Codes de sortie (spec §7) : 0 normal, 1 données ou config, 2 coffre, 3 port occupé, 4 argument invalide.
    /// </summary>
    public static class Program
    {
        public const int ExitOk = 0;
        public const int ExitArguments = 4;

        public static int Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            Arguments options;
            try
            {
                options = Arguments.Parse(args);
            }
            catch (ArgumentsException ex)
            {
                Console.Error.WriteLine("irisd : " + ex.Message);
                Console.Error.WriteLine();
                Console.Error.Write(Arguments.Usage());
                return ExitArguments;
            }

            if (options.ShowHelp)
            {
                Console.Write(Arguments.Usage());
                return ExitOk;
            }
            if (options.ShowVersion)
            {
                Console.WriteLine("irisd " + IrisVersion.Value);
                return ExitOk;
            }
            if (!options.Foreground)
            {
                // Sans --foreground le socle affiche l'aide et sort code 1 (le mode arrière-plan arrive avec le lot autostart).
                Console.Error.Write(Arguments.Usage());
                return 1;
            }

            Console.WriteLine("irisd " + IrisVersion.Value + " : socle en construction, le daemon arrive avec la phase 1.");
            return ExitOk;
        }
    }
}
