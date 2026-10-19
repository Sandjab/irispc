using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using IrisKit;

namespace IrisCli
{
    /// <summary>Sorties communes : JSON d'IRIS (indenté), acquittements, lignes.</summary>
    public static class CliOutput
    {
        public static void Emit(CliContext ctx, object raw) { ctx.Out.WriteLine(Json.Emit(raw)); }

        /// <summary>Acquittement sans charge utile : texte, ou `{"ok": true, "message": "…"}` en --json.</summary>
        public static void Ack(CliContext ctx, bool json, string message)
        {
            if (!json)
            {
                ctx.Out.WriteLine(message);
                return;
            }
            OrderedDictionary o = new OrderedDictionary();
            o["ok"] = true;
            o["message"] = message;
            Emit(ctx, o);
        }

        public static void Lines(CliContext ctx, IEnumerable<string> lines)
        {
            foreach (string line in lines) ctx.Out.WriteLine(line);
        }
    }

    /// <summary>Messages dédiés aux erreurs RPC fréquentes (spec phase 5 §3) ; sinon le message du daemon.</summary>
    public static class RpcMessages
    {
        public static string For(RpcException ex)
        {
            switch (ex.Code)
            {
                case RpcErrors.VaultLocked: return "coffre verrouillé : lancez iris vault unlock";
                case RpcErrors.BadPassword: return "mot de passe refusé";
                case RpcErrors.RateLimited: return "trop d'essais : réessayez dans " + RetryAfter(ex) + " s";
                case RpcErrors.VaultExists: return "un coffre existe déjà";
                default: return ex.Message;
            }
        }

        private static string RetryAfter(RpcException ex)
        {
            IDictionary<string, object> data = ex.ErrorData as IDictionary<string, object>;
            object value;
            if (data != null && data.TryGetValue("retry_after_s", out value) && value != null) return Convert.ToString(value, CultureInfo.InvariantCulture);
            return "?";
        }
    }

    /// <summary>Point d'entrée testable d'iris.exe : table des commandes, aide, analyse, exécution, erreurs → codes de sortie.</summary>
    public static class Cli
    {
        private static readonly string[] Groups = { "secret", "rule", "config", "ca", "vault", "mcp" };
        private static readonly List<CommandSpec> Commands = BuildCommands();

        private static List<CommandSpec> BuildCommands()
        {
            List<CommandSpec> list = new List<CommandSpec>();
            DaemonCommands.Register(list);
            SecretCommands.Register(list);
            RuleCommands.Register(list);
            ConfigCommands.Register(list);
            CaCommands.Register(list);
            LogsCommand.Register(list);
            VaultCommands.Register(list);
            McpCommands.Register(list);
            DoctorCommand.Register(list);
            return list;
        }

        public static int Run(string[] args, CliContext ctx)
        {
            if (args.Length == 0 || IsHelp(args[0]) || args[0] == "help")
            {
                ctx.Out.Write(GeneralHelp());
                return CliExit.Ok;
            }
            if (args[0] == "--version")
            {
                ctx.Out.WriteLine("iris " + IrisVersion.Value);
                return CliExit.Ok;
            }
            CommandSpec spec = Find(args[0]);
            int start = 1;
            if (spec == null)
            {
                if (Array.IndexOf(Groups, args[0]) < 0) return UsageError(ctx, "commande inconnue : " + args[0], "iris --help");
                if (args.Length < 2 || IsHelp(args[1]))
                {
                    ctx.Out.Write(GroupHelp(args[0]));
                    return CliExit.Ok;
                }
                spec = Find(args[0] + " " + args[1]);
                if (spec == null) return UsageError(ctx, "sous-commande inconnue : " + args[0] + " " + args[1], "iris " + args[0] + " --help");
                start = 2;
            }
            ParsedArgs parsed;
            try { parsed = CliArguments.Parse(spec, args, start); }
            catch (UsageException ex) { return UsageError(ctx, ex.Message, "iris " + spec.Path + " --help"); }
            if (parsed.HelpRequested)
            {
                ctx.Out.Write(CommandHelp(spec));
                return CliExit.Ok;
            }
            return Execute(spec, parsed, ctx);
        }

        private static int Execute(CommandSpec spec, ParsedArgs parsed, CliContext ctx)
        {
            try { return spec.Run(parsed, ctx); }
            catch (UsageException ex) { return UsageError(ctx, ex.Message, "iris " + spec.Path + " --help"); }
            catch (CliException ex)
            {
                ctx.Err.WriteLine("erreur : " + ex.Message);
                return ex.Code;
            }
            catch (DaemonUnreachableException ex)
            {
                ctx.Err.WriteLine(ex.Message);
                return CliExit.Unreachable;
            }
            catch (AdminServerIdentityException ex)
            {
                ctx.Err.WriteLine("erreur : " + ex.Message);
                return CliExit.Unreachable;
            }
            catch (RpcException ex)
            {
                ctx.Err.WriteLine("erreur : " + RpcMessages.For(ex));
                return CliExit.Logic;
            }
            catch (Exception ex)
            {
                // Garde-fou : jamais de trace de pile ; les messages d'exception ne portent jamais de valeur de secret.
                ctx.Err.WriteLine("erreur inattendue (" + ex.GetType().Name + ") : " + ex.Message);
                return CliExit.Logic;
            }
        }

        private static int UsageError(CliContext ctx, string message, string seeAlso)
        {
            ctx.Err.WriteLine("iris : " + message);
            ctx.Err.WriteLine("voir : " + seeAlso);
            return CliExit.Usage;
        }

        private static bool IsHelp(string arg) { return arg == "--help" || arg == "-h"; }

        private static CommandSpec Find(string path)
        {
            foreach (CommandSpec c in Commands)
                if (c.Path == path) return c;
            return null;
        }

        private static string GeneralHelp()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Usage : iris <commande> [options]");
            sb.AppendLine();
            sb.AppendLine("IRIS pour Windows : client du daemon irisd (coffre, secrets, règles, events, fichiers MCP).");
            sb.AppendLine();
            sb.AppendLine("Commandes :");
            foreach (CommandSpec c in Commands) sb.AppendLine("  " + c.Path.PadRight(22) + c.Summary);
            sb.AppendLine();
            sb.AppendLine("Options communes : --json (sortie JSON), --pipe-name NOM, --config-path CHEMIN, --help");
            sb.AppendLine("Version : iris --version");
            return sb.ToString();
        }

        private static string GroupHelp(string group)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Usage : iris " + group + " <sous-commande> [options]");
            sb.AppendLine();
            sb.AppendLine("Sous-commandes :");
            foreach (CommandSpec c in Commands)
                if (c.Path.StartsWith(group + " ", StringComparison.Ordinal)) sb.AppendLine("  iris " + c.Usage);
            return sb.ToString();
        }

        private static string CommandHelp(CommandSpec spec)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Usage : iris " + spec.Usage);
            sb.AppendLine();
            sb.AppendLine(spec.Summary);
            if (spec.UsesDaemon)
            {
                sb.AppendLine();
                sb.AppendLine("Options communes : --pipe-name NOM, --config-path CHEMIN");
            }
            return sb.ToString();
        }
    }
}
