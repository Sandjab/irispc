using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Security;
using System.Text;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris secret …` (SPECS §4.3, spec phase 5 §4) : la valeur part vers le daemon et n'est jamais affichée.</summary>
    internal static class SecretCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec
            {
                Path = "secret add",
                Usage = "secret add NAME [--allowed-hosts h1,h2] (--value-from-stdin | --value V) [--json]",
                Summary = "ajoute un secret, utilisable comme {{kc:NAME}} ; préférez --value-from-stdin",
                Positionals = new[] { "NAME" },
                Options = new[] { "--allowed-hosts", "--value" },
                Flags = new[] { "--value-from-stdin", "--json" },
                UsesDaemon = true,
                Run = Add
            });
            list.Add(new CommandSpec { Path = "secret list", Usage = "secret list [--json]", Summary = "liste les secrets (jamais leur valeur)", Flags = new[] { "--json" }, UsesDaemon = true, Run = List });
            list.Add(new CommandSpec { Path = "secret show", Usage = "secret show NAME [--json]", Summary = "métadonnées d'un secret (jamais sa valeur)", Positionals = new[] { "NAME" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Show });
            list.Add(new CommandSpec { Path = "secret edit", Usage = "secret edit NAME --allowed-hosts h1,h2 [--json]", Summary = "remplace la liste des hôtes autorisés", Positionals = new[] { "NAME" }, Options = new[] { "--allowed-hosts" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Edit });
            list.Add(new CommandSpec { Path = "secret rotate", Usage = "secret rotate NAME [--json]", Summary = "remplace la valeur (saisie sans écho, ou stdin redirigé)", Positionals = new[] { "NAME" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Rotate });
            list.Add(new CommandSpec { Path = "secret rm", Usage = "secret rm NAME [--yes] [--json]", Summary = "supprime un secret (confirmation par le nom, sauf --yes)", Positionals = new[] { "NAME" }, Flags = new[] { "--yes", "--json" }, UsesDaemon = true, Run = Remove });
            list.Add(new CommandSpec { Path = "secret quarantine", Usage = "secret quarantine NAME [--json]", Summary = "suspend la substitution de ce secret", Positionals = new[] { "NAME" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Quarantine });
            list.Add(new CommandSpec { Path = "secret unquarantine", Usage = "secret unquarantine NAME [--json]", Summary = "rétablit la substitution de ce secret", Positionals = new[] { "NAME" }, Flags = new[] { "--json" }, UsesDaemon = true, Run = Unquarantine });
        }

        private static List<string> Hosts(string raw)
        {
            List<string> hosts = new List<string>();
            if (raw == null) return hosts;
            foreach (string h in raw.Split(','))
            {
                string t = h.Trim();
                if (t.Length > 0) hosts.Add(t);
            }
            return hosts;
        }

        private static OrderedDictionary Named(string name)
        {
            OrderedDictionary p = new OrderedDictionary();
            p["name"] = name;
            return p;
        }

        private static string HostsText(Secret s) { return string.Join(",", s.AllowedHosts); }

        private static int Add(ParsedArgs a, CliContext ctx)
        {
            string inline = a.Option("--value");
            bool fromStdin = a.Flag("--value-from-stdin");
            if (inline != null && fromStdin) throw new UsageException("--value et --value-from-stdin sont exclusifs");
            if (inline == null && !fromStdin) throw new UsageException("indiquez --value-from-stdin (recommandé) ou --value V");
            byte[] value;
            if (inline != null)
            {
                ctx.Err.WriteLine("avertissement : --value expose le secret dans l'historique du shell ; préférez --value-from-stdin");
                value = SecretValue.Normalize(Encoding.UTF8.GetBytes(inline));
            }
            else if (ctx.IsStdinRedirected) value = SecretValue.Normalize(SecretValue.ReadAll(ctx.In));
            else
            {
                // Console interactive : saisie sans écho, comme rotate (revue finale phase 5, m1) — jamais de valeur à l'écran.
                SecureString typed = ctx.Passwords.ReadPassword("Valeur pour " + a.Positional(0) + " : ", ctx.Cancel);
                if (typed == null) throw new CliException(CliExit.Logic, "saisie interrompue : rien n'a été ajouté");
                using (typed) value = SecretValue.Normalize(SecretValue.FromSecure(typed));
            }
            OrderedDictionary p = Named(a.Positional(0));
            p["allowed_hosts"] = Hosts(a.Option("--allowed-hosts"));
            object raw;
            try
            {
                p["value"] = Convert.ToBase64String(value);
                using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.add", p);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
                p["value"] = null;
            }
            return Report(a, ctx, raw, "secret ajouté : ", true);
        }

        private static int List(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.list", null);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            IList<object> items = CliConnection.AsList(raw);
            if (items.Count == 0)
            {
                ctx.Out.WriteLine("aucun secret");
                return CliExit.Ok;
            }
            DateTime now = ctx.Now();
            List<string[]> rows = new List<string[]>();
            foreach (object item in items)
            {
                Secret s = Secret.FromJson(CliConnection.AsObject(item));
                rows.Add(new[]
                {
                    s.Name,
                    s.Quarantined ? "QUARANTAINE" : "actif",
                    TextFormatter.Ago(s.CreatedAt, now),
                    s.LastUsedAt.HasValue ? TextFormatter.Ago(s.LastUsedAt.Value, now) : "-",
                    s.UsageCount.ToString(CultureInfo.InvariantCulture),
                    HostsText(s)
                });
            }
            CliOutput.Lines(ctx, TextFormatter.Table(new[] { "NOM", "ÉTAT", "CRÉÉ", "DERNIER_USAGE", "USAGES", "HÔTES" }, rows));
            return CliExit.Ok;
        }

        private static int Show(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.get", Named(a.Positional(0)));
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            Secret s = Secret.FromJson(CliConnection.AsObject(raw));
            ctx.Out.WriteLine("nom : " + s.Name);
            ctx.Out.WriteLine("hôtes : " + HostsText(s));
            ctx.Out.WriteLine("créé : " + Json.FormatDate(s.CreatedAt));
            ctx.Out.WriteLine("dernier usage : " + (s.LastUsedAt.HasValue ? Json.FormatDate(s.LastUsedAt.Value) : "-"));
            ctx.Out.WriteLine("usages : " + s.UsageCount.ToString(CultureInfo.InvariantCulture));
            ctx.Out.WriteLine("quarantaine : " + TextFormatter.YesNo(s.Quarantined));
            return CliExit.Ok;
        }

        private static int Edit(ParsedArgs a, CliContext ctx)
        {
            string hosts = a.Option("--allowed-hosts");
            if (hosts == null) throw new UsageException("--allowed-hosts est obligatoire");
            OrderedDictionary p = Named(a.Positional(0));
            p["allowed_hosts"] = Hosts(hosts);
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.update", p);
            return Report(a, ctx, raw, "secret modifié : ", true);
        }

        private static int Rotate(ParsedArgs a, CliContext ctx)
        {
            string name = a.Positional(0);
            byte[] value;
            if (ctx.IsStdinRedirected) value = SecretValue.Normalize(SecretValue.ReadAll(ctx.In));
            else
            {
                SecureString typed = ctx.Passwords.ReadPassword("Nouvelle valeur pour " + name + " : ", ctx.Cancel);
                if (typed == null) throw new CliException(CliExit.Logic, "saisie interrompue : rien n'a été modifié");
                using (typed) value = SecretValue.Normalize(SecretValue.FromSecure(typed));
            }
            OrderedDictionary p = Named(name);
            object raw;
            try
            {
                p["value"] = Convert.ToBase64String(value);
                using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.rotate", p);
            }
            finally
            {
                Array.Clear(value, 0, value.Length);
                p["value"] = null;
            }
            return Report(a, ctx, raw, "secret renouvelé : ", false);
        }

        private static int Remove(ParsedArgs a, CliContext ctx)
        {
            string name = a.Positional(0);
            if (!a.Flag("--yes"))
            {
                ctx.Err.Write("Tapez le nom du secret pour confirmer : ");
                string line = CliInput.ReadLine(ctx.In);
                if (line != name) throw new CliException(CliExit.Usage, "confirmation incorrecte : suppression annulée");
            }
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.delete", Named(name));
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine("secret supprimé : " + name);
            return CliExit.Ok;
        }

        private static int Quarantine(ParsedArgs a, CliContext ctx) { return SetQuarantined(a, ctx, true); }

        private static int Unquarantine(ParsedArgs a, CliContext ctx) { return SetQuarantined(a, ctx, false); }

        private static int SetQuarantined(ParsedArgs a, CliContext ctx, bool quarantined)
        {
            OrderedDictionary p = Named(a.Positional(0));
            p["quarantined"] = quarantined;
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("secret.set_quarantined", p);
            return Report(a, ctx, raw, quarantined ? "secret mis en quarantaine : " : "secret sorti de quarantaine : ", false);
        }

        private static int Report(ParsedArgs a, CliContext ctx, object raw, string label, bool withHosts)
        {
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            Secret s = Secret.FromJson(CliConnection.AsObject(raw));
            ctx.Out.WriteLine(label + s.Name + (withHosts ? " (hôtes : " + HostsText(s) + ")" : ""));
            return CliExit.Ok;
        }
    }
}
