using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris config get|set|reload` : lecture, mutation (le daemon écrit) et rechargement de config.json.</summary>
    internal static class ConfigCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec { Path = "config get", Usage = "config get [--json]", Summary = "affiche la configuration chargée par le daemon", Flags = new[] { "--json" }, UsesDaemon = true, Run = Get });
            list.Add(new CommandSpec { Path = "config set", Usage = "config set KEY VALUE [--json]", Summary = "modifie une clé (ex. security.on_exfil_attempt block_only)", Positionals = new[] { "KEY", "VALUE" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Set });
            list.Add(new CommandSpec { Path = "config reload", Usage = "config reload [--json]", Summary = "relit config.json (les clés broker.* demandent un redémarrage)", Flags = new[] { "--json" }, UsesDaemon = true, Run = Reload });
        }

        private static int Get(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("config.get", null);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            CliConnection.AsObject(raw); // valide que la réponse est un objet
            Render(ctx, (IDictionary<string, object>)raw);
            return CliExit.Ok;
        }

        /// <summary>Rendu par sections : scalaires de tête, `[section]` par objet, `[[hosts]]` par hôte, autres tableaux en JSON compact.</summary>
        private static void Render(CliContext ctx, IDictionary<string, object> config)
        {
            foreach (KeyValuePair<string, object> kv in config)
                if (!(kv.Value is IDictionary<string, object>) && !(kv.Value is IList<object>)) ctx.Out.WriteLine(kv.Key + " = " + Scalar(kv.Value));
            foreach (KeyValuePair<string, object> kv in config)
            {
                IDictionary<string, object> section = kv.Value as IDictionary<string, object>;
                if (section == null) continue;
                ctx.Out.WriteLine();
                ctx.Out.WriteLine("[" + kv.Key + "]");
                foreach (KeyValuePair<string, object> field in section) ctx.Out.WriteLine(field.Key + " = " + Scalar(field.Value));
            }
            foreach (KeyValuePair<string, object> kv in config)
            {
                IList<object> items = kv.Value as IList<object>;
                if (items == null || items.Count == 0) continue;
                if (kv.Key != "hosts")
                {
                    ctx.Out.WriteLine();
                    ctx.Out.WriteLine(kv.Key + " = " + Json.EmitCompact(items));
                    continue;
                }
                foreach (object item in items)
                {
                    ctx.Out.WriteLine();
                    ctx.Out.WriteLine("[[hosts]]");
                    IDictionary<string, object> host = item as IDictionary<string, object>;
                    if (host == null) continue;
                    foreach (KeyValuePair<string, object> field in host) ctx.Out.WriteLine(field.Key + " = " + Scalar(field.Value));
                }
            }
        }

        private static string Scalar(object value)
        {
            if (value == null) return "null";
            string s = value as string;
            if (s != null) return "\"" + s + "\"";
            if (value is bool) return (bool)value ? "true" : "false";
            if (value is long || value is double) return Convert.ToString(value, CultureInfo.InvariantCulture);
            return Json.EmitCompact(value);
        }

        private static int Set(ParsedArgs a, CliContext ctx)
        {
            OrderedDictionary update = new OrderedDictionary();
            update["key"] = a.Positional(0);
            update["value"] = a.Positional(1);
            OrderedDictionary p = new OrderedDictionary();
            p["updates"] = new List<object> { update };
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("config.set", p);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            JsonObject r = CliConnection.AsObject(raw);
            IList<string> applied = r.StringArray("applied");
            IList<string> restart = r.StringArray("requires_restart");
            if (applied.Count > 0) ctx.Out.WriteLine("appliqué : " + string.Join(", ", applied));
            if (restart.Count > 0) ctx.Out.WriteLine("redémarrage requis : " + string.Join(", ", restart));
            return CliExit.Ok;
        }

        private static int Reload(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("config.reload", null);
            IList<string> ignored = CliConnection.AsObject(raw).StringArray("ignored");
            if (ignored.Count > 0) ctx.Err.WriteLine("avertissement : modifications ignorées, redémarrage requis : " + string.Join(", ", ignored));
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine("configuration rechargée");
            return CliExit.Ok;
        }
    }
}
