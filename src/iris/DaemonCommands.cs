using System.Collections.Generic;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris status`, `iris pause`, `iris resume` (SPECS §4.3).</summary>
    internal static class DaemonCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec
            {
                Path = "status",
                Usage = "status [--json]",
                Summary = "état du daemon : pid, uptime, version, compteurs, pause, coffre",
                Flags = new[] { "--json" },
                UsesDaemon = true,
                Run = Status
            });
            list.Add(new CommandSpec
            {
                Path = "pause",
                Usage = "pause [--json]",
                Summary = "suspend la substitution (idempotent)",
                Flags = new[] { "--json" },
                UsesDaemon = true,
                Run = Pause
            });
            list.Add(new CommandSpec
            {
                Path = "resume",
                Usage = "resume [--json]",
                Summary = "reprend la substitution (idempotent)",
                Flags = new[] { "--json" },
                UsesDaemon = true,
                Run = Resume
            });
        }

        private static int Status(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("daemon.status", null);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            JsonObject s = CliConnection.AsObject(raw);
            JsonObject stats = s.Object("stats");
            ctx.Out.WriteLine("pid " + s.Int("pid") + " · uptime " + TextFormatter.Duration(s.Int("uptime_s")) + " · version " + s.String("version"));
            ctx.Out.WriteLine("coffre : " + TextFormatter.VaultState(s.OptionalString("vault")) + " · substitution : " + (s.Bool("paused", false) ? "en pause" : "active"));
            ctx.Out.WriteLine("requêtes " + stats.Int("req_total") + " · substitutions " + stats.Int("sub_total")
                + " · exfiltrations bloquées " + stats.Int("exfil_blocked_total") + " · erreurs " + stats.Int("errors_total"));
            return CliExit.Ok;
        }

        private static int Pause(ParsedArgs a, CliContext ctx) { return SetPaused(a, ctx, "daemon.pause"); }

        private static int Resume(ParsedArgs a, CliContext ctx) { return SetPaused(a, ctx, "daemon.resume"); }

        private static int SetPaused(ParsedArgs a, CliContext ctx, string method)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call(method, null);
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine(CliConnection.AsObject(raw).Bool("paused", false) ? "en pause" : "actif");
            return CliExit.Ok;
        }
    }
}
