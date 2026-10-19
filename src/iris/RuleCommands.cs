using System.Collections.Generic;
using System.Collections.Specialized;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris rule …` : whitelist MITM ; les hôtes `default` ne se suppriment pas (code 64, comme IRIS).</summary>
    internal static class RuleCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec { Path = "rule add", Usage = "rule add HOST [--json]", Summary = "met un hôte en interception MITM (origine user)", Positionals = new[] { "HOST" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Add });
            list.Add(new CommandSpec { Path = "rule list", Usage = "rule list [--json]", Summary = "liste les hôtes interceptés (default et user)", Flags = new[] { "--json" }, UsesDaemon = true, Run = List });
            list.Add(new CommandSpec { Path = "rule rm", Usage = "rule rm HOST [--json]", Summary = "retire un hôte ajouté par l'utilisateur", Positionals = new[] { "HOST" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Remove });
        }

        private static OrderedDictionary Host(string host)
        {
            OrderedDictionary p = new OrderedDictionary();
            p["host"] = host;
            return p;
        }

        private static int Add(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("rule.add", Host(a.Positional(0)));
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            MITMRule rule = MITMRule.FromJson(CliConnection.AsObject(raw));
            ctx.Out.WriteLine("règle ajoutée : " + rule.Host + " (" + RuleOriginWire.ToWire(rule.Origin) + ")");
            return CliExit.Ok;
        }

        private static int List(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("rule.list", null);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            List<string[]> rows = new List<string[]>();
            foreach (object item in CliConnection.AsList(raw))
            {
                MITMRule rule = MITMRule.FromJson(CliConnection.AsObject(item));
                rows.Add(new[] { rule.Host, RuleOriginWire.ToWire(rule.Origin), rule.CreatedAt.Year <= 1970 ? "—" : Json.FormatDate(rule.CreatedAt) });
            }
            if (rows.Count == 0) ctx.Out.WriteLine("aucune règle");
            else CliOutput.Lines(ctx, TextFormatter.Table(new[] { "HÔTE", "ORIGINE", "CRÉÉ" }, rows));
            return CliExit.Ok;
        }

        private static int Remove(ParsedArgs a, CliContext ctx)
        {
            string host = a.Positional(0);
            object raw;
            try
            {
                using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("rule.delete", Host(host));
            }
            catch (RpcException ex)
            {
                if (ex.Code == RpcErrors.RuleProtected) throw new CliException(CliExit.Usage, "hôte par défaut, non supprimable : " + host);
                if (ex.Code == RpcErrors.RuleNotFound) throw new CliException(CliExit.Usage, "règle introuvable : " + host);
                throw;
            }
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine("règle supprimée : " + host);
            return CliExit.Ok;
        }
    }
}
