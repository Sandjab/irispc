using System;
using System.Collections.Generic;

namespace IrisCli
{
    /// <summary>Codes de sortie d'IRIS (SPECS §16, spec phase 5 §3).</summary>
    public static class CliExit
    {
        public const int Ok = 0;
        public const int Logic = 1;
        public const int Unreachable = 2;
        public const int Io = 3;
        public const int Usage = 64;
    }

    /// <summary>Ligne de commande invalide : code 64, message en français suivi de `voir : iris … --help`.</summary>
    public sealed class UsageException : Exception
    {
        public UsageException(string message) : base(message) { }
    }

    /// <summary>Échec d'une commande avec son code de sortie (1 logique, 3 E/S locale, 64 usage métier). Jamais de valeur de secret dans le message.</summary>
    public sealed class CliException : Exception
    {
        public int Code { get; private set; }

        public CliException(int code, string message) : base(message) { Code = code; }
    }

    public delegate int CommandHandler(ParsedArgs args, CliContext ctx);

    /// <summary>Une sous-commande : chemin (« secret add »), aide, positionnels, options à valeur, drapeaux, gestionnaire.</summary>
    public sealed class CommandSpec
    {
        public string Path;
        /// <summary>Sans le préfixe « iris », par exemple « secret add NAME [--allowed-hosts h1,h2] [--json] ».</summary>
        public string Usage;
        public string Summary;
        public string[] Positionals = new string[0];
        public string[] Options = new string[0];
        public string[] Flags = new string[0];
        /// <summary>Parle au daemon : accepte en plus --pipe-name et --config-path.</summary>
        public bool UsesDaemon;
        public CommandHandler Run;
    }

    public sealed class ParsedArgs
    {
        private readonly List<string> positionals = new List<string>();
        private readonly Dictionary<string, string> options = new Dictionary<string, string>(StringComparer.Ordinal);
        private readonly HashSet<string> flags = new HashSet<string>(StringComparer.Ordinal);

        public bool HelpRequested { get; internal set; }

        public string Positional(int index) { return positionals[index]; }

        public string Option(string name)
        {
            string value;
            return options.TryGetValue(name, out value) ? value : null;
        }

        public bool Flag(string name) { return flags.Contains(name); }

        public bool Json { get { return Flag("--json"); } }

        internal int PositionalCount { get { return positionals.Count; } }
        internal void AddPositional(string value) { positionals.Add(value); }
        internal bool HasOption(string name) { return options.ContainsKey(name); }
        internal void SetOption(string name, string value) { options[name] = value; }
        internal void SetFlag(string name) { flags.Add(name); }
    }

    /// <summary>
    /// Analyseur strict (comme celui d'irisd) : options longues exactes et sensibles à la casse, `--nom valeur` ou drapeau `--nom`,
    /// positionnels ; `-h` seule forme courte. Inconnu, répété, valeur manquante ou vide, positionnel manquant ou en trop → UsageException.
    /// </summary>
    public static class CliArguments
    {
        public static ParsedArgs Parse(CommandSpec spec, string[] args, int start)
        {
            ParsedArgs p = new ParsedArgs();
            List<string> valueOptions = new List<string>(spec.Options);
            if (spec.UsesDaemon)
            {
                valueOptions.Add("--pipe-name");
                valueOptions.Add("--config-path");
            }
            for (int i = start; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--help" || a == "-h")
                {
                    p.HelpRequested = true;
                    return p;
                }
                if (a.StartsWith("--", StringComparison.Ordinal))
                {
                    if (valueOptions.Contains(a))
                    {
                        if (p.HasOption(a)) throw new UsageException("option répétée : " + a);
                        if (i + 1 >= args.Length || args[i + 1].StartsWith("--", StringComparison.Ordinal)) throw new UsageException("valeur manquante pour " + a);
                        string value = args[++i];
                        if (value.Trim().Length == 0) throw new UsageException("valeur vide pour " + a);
                        p.SetOption(a, value);
                    }
                    else if (Array.IndexOf(spec.Flags, a) >= 0)
                    {
                        if (p.Flag(a)) throw new UsageException("option répétée : " + a);
                        p.SetFlag(a);
                    }
                    else throw new UsageException("option inconnue : " + a);
                    continue;
                }
                // L'argument n'est pas recopié : c'est souvent une valeur de secret collée par erreur (revue finale phase 5, m3).
                if (p.PositionalCount >= spec.Positionals.Length)
                    throw new UsageException("argument en trop en position " + (p.PositionalCount + 1) + " (" + spec.Positionals.Length + " attendu(s))");
                p.AddPositional(a);
            }
            if (p.PositionalCount < spec.Positionals.Length) throw new UsageException("argument manquant : " + spec.Positionals[p.PositionalCount]);
            return p;
        }
    }
}
