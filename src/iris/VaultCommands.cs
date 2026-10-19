using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security;
using IrisKit;

namespace IrisCli
{
    /// <summary>
    /// `iris vault status|unlock|create` (spec phase 5 §4, §5) : le mot de passe maître ne vient que d'une console, jamais d'une
    /// option ni de stdin ; aucune nouvelle tentative dans la CLI (le daemon applique son délai anti-force brute).
    /// </summary>
    internal static class VaultCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec { Path = "vault status", Usage = "vault status [--json]", Summary = "état du coffre : absent, locked ou unlocked", Flags = new[] { "--json" }, UsesDaemon = true, Run = Status });
            list.Add(new CommandSpec { Path = "vault unlock", Usage = "vault unlock [--json]", Summary = "déverrouille le coffre (mot de passe saisi à la console, sans écho)", Flags = new[] { "--json" }, UsesDaemon = true, Run = Unlock });
            list.Add(new CommandSpec { Path = "vault create", Usage = "vault create [--json]", Summary = "crée le coffre (mot de passe saisi deux fois à la console)", Flags = new[] { "--json" }, UsesDaemon = true, Run = Create });
        }

        private static int Status(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("vault.status", null);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            JsonObject s = CliConnection.AsObject(raw);
            string path = s.OptionalString("path");
            ctx.Out.WriteLine("coffre : " + TextFormatter.VaultState(s.String("state")) + (path == null ? " (secrets en mémoire)" : " (" + path + ")"));
            return CliExit.Ok;
        }

        private static void RequireConsole(CliContext ctx)
        {
            if (ctx.IsStdinRedirected)
                throw new CliException(CliExit.Usage, "vault unlock|create exige une console : le mot de passe maître ne se lit jamais sur l'entrée standard");
        }

        private static string State(CliConnection c) { return CliConnection.AsObject(c.Call("vault.status", null)).String("state"); }

        private static SecureString Read(CliContext ctx, string prompt)
        {
            SecureString s = ctx.Passwords.ReadPassword(prompt, ctx.Cancel);
            if (s == null) throw new CliException(CliExit.Logic, "saisie interrompue : rien n'a été modifié");
            if (s.Length == 0)
            {
                s.Dispose();
                throw new CliException(CliExit.Logic, "le mot de passe ne peut pas être vide");
            }
            return s;
        }

        private static object CallWithPassword(CliConnection c, string method, SecureString password)
        {
            OrderedDictionary p = new OrderedDictionary();
            p["password"] = SecretValue.ToPlain(password);
            try { return c.Call(method, p); }
            finally { p["password"] = null; }
        }

        private static OrderedDictionary Unlocked()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["state"] = "unlocked";
            return o;
        }

        private static int Unlock(ParsedArgs a, CliContext ctx)
        {
            RequireConsole(ctx);
            object raw;
            string message;
            using (CliConnection c = CliConnection.Open(a, ctx))
            {
                string state = State(c);
                if (state == "absent") throw new CliException(CliExit.Logic, "aucun coffre : iris vault create");
                if (state == "unlocked")
                {
                    raw = Unlocked();
                    message = "déjà déverrouillé";
                }
                else
                {
                    using (SecureString password = Read(ctx, "Mot de passe maître : ")) raw = CallWithPassword(c, "vault.unlock", password);
                    message = "coffre déverrouillé";
                }
            }
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine(message);
            return CliExit.Ok;
        }

        private static int Create(ParsedArgs a, CliContext ctx)
        {
            RequireConsole(ctx);
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx))
            {
                string state = State(c);
                if (state != "absent") throw new CliException(CliExit.Logic, "un coffre existe déjà" + (state == "locked" ? " : iris vault unlock" : ""));
                using (SecureString first = Read(ctx, "Nouveau mot de passe maître : "))
                using (SecureString second = Read(ctx, "Confirmez le mot de passe maître : "))
                {
                    if (!SecretValue.SameText(first, second)) throw new CliException(CliExit.Logic, "les deux saisies diffèrent : coffre non créé");
                    raw = CallWithPassword(c, "vault.create", first);
                }
            }
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine("coffre créé et déverrouillé");
            return CliExit.Ok;
        }
    }
}
