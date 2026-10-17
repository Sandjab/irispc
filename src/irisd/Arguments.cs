using System;
using System.Collections.Generic;

namespace Irisd
{
    /// <summary>Ligne de commande invalide : message en français, code de sortie 4 (spec §7).</summary>
    public sealed class ArgumentsException : Exception
    {
        public ArgumentsException(string message) : base(message) { }
    }

    /// <summary>
    /// Options de irisd (spec socle §7). Analyse stricte : options exactes et sensibles à la casse,
    /// pas de forme courte, pas de positionnel, pas de répétition, valeur obligatoire pour --data et --log-level.
    /// Aucun secret ni mot de passe ne passe jamais par la ligne de commande.
    /// </summary>
    public sealed class Arguments
    {
        public static readonly string[] LogLevels = { "debug", "info", "warning", "error" };

        public bool Foreground { get; private set; }
        public bool ShowVersion { get; private set; }
        public bool ShowHelp { get; private set; }
        public bool InMemorySecrets { get; private set; }
        public bool InMemoryCa { get; private set; }
        /// <summary>Dossier des données ; null = data\ à côté de l'exécutable.</summary>
        public string Data { get; private set; }
        /// <summary>Niveau de log ; null = valeur de config.json.</summary>
        public string LogLevel { get; private set; }

        public static Arguments Parse(string[] args)
        {
            Arguments result = new Arguments();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                if (!arg.StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentsException("argument inattendu : " + arg);
                if (!seen.Add(arg))
                    throw new ArgumentsException("option répétée : " + arg);
                switch (arg)
                {
                    case "--foreground": result.Foreground = true; break;
                    case "--version": result.ShowVersion = true; break;
                    case "--help": result.ShowHelp = true; break;
                    case "--in-memory-secrets": result.InMemorySecrets = true; break;
                    case "--in-memory-ca": result.InMemoryCa = true; break;
                    case "--data":
                        result.Data = ValueOf(args, ref i);
                        break;
                    case "--log-level":
                        result.LogLevel = ValueOf(args, ref i);
                        if (Array.IndexOf(LogLevels, result.LogLevel) < 0)
                            throw new ArgumentsException("niveau de log inconnu : " + result.LogLevel
                                + " (attendu : " + string.Join(", ", LogLevels) + ")");
                        break;
                    default:
                        throw new ArgumentsException("option inconnue : " + arg);
                }
            }
            return result;
        }

        public static string Usage()
        {
            return string.Join(Environment.NewLine, new[] {
                "Usage : irisd --foreground [--data <dossier>] [--in-memory-secrets] [--in-memory-ca] [--log-level <niveau>]",
                "        irisd --version | --help",
                "",
                "Options :",
                "  --foreground           lance le daemon en avant-plan (obligatoire dans cette version)",
                "  --data <dossier>       dossier des données (défaut : data\\ à côté de irisd.exe)",
                "  --in-memory-secrets    DEBUG : secrets lus depuis IRIS_SECRET_<NAME>, coffre non ouvert",
                "  --in-memory-ca         DEBUG : CA éphémère, jamais écrit dans le coffre",
                "  --log-level <niveau>   debug | info | warning | error (défaut : config.json)",
                "  --version              affiche la version",
                "  --help                 affiche cette aide",
                ""
            });
        }

        /// <summary>Valeur de l'option courante : l'argument suivant, non vide, qui n'est pas lui-même une option.</summary>
        private static string ValueOf(string[] args, ref int i)
        {
            string option = args[i];
            if (i + 1 >= args.Length || args[i + 1].Length == 0 || args[i + 1].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentsException("valeur manquante pour " + option);
            i++;
            return args[i];
        }
    }
}
