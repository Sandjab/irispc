using System;
using System.Collections.Generic;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris doctor` : huit contrôles dans l'ordre ; code 2 si le pipe est injoignable, 1 si un contrôle échoue, sinon 0.</summary>
    internal static class DoctorCommand
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec
            {
                Path = "doctor",
                Usage = "doctor [--json]",
                Summary = "diagnostic : pipe, daemon, coffre, CA, variables d'environnement, proxy, Claude Code",
                Flags = new[] { "--json" },
                UsesDaemon = true,
                Run = Run
            });
        }

        private static int Run(ParsedArgs a, CliContext ctx)
        {
            List<DoctorResult> results = new List<DoctorResult>();
            string pipe = CliConnection.ResolvePipe(a, ctx);
            CliConnection c;
            try { c = CliConnection.Open(pipe, ctx); }
            catch (DaemonUnreachableException ex)
            {
                results.Add(DoctorChecks.AdminPipe(pipe, ex.Message.Replace(Environment.NewLine, " ; ")));
                Emit(a, ctx, results);
                return CliExit.Unreachable;
            }
            catch (AdminServerIdentityException ex)
            {
                results.Add(DoctorChecks.AdminPipe(pipe, ex.Message));
                Emit(a, ctx, results);
                return CliExit.Unreachable;
            }
            JsonObject status;
            JsonObject config;
            string pem;
            using (c)
            {
                status = CliConnection.AsObject(c.Call("daemon.status", null));
                pem = CliConnection.AsObject(c.Call("ca.export_path", null)).String("path");
                config = CliConnection.AsObject(c.Call("config.get", null));
            }
            string listen = config.Object("broker").String("listen");
            results.Add(DoctorChecks.AdminPipe(pipe, null));
            results.Add(DoctorChecks.DaemonAlive(status.Int("pid"), status.Int("uptime_s"), DoctorChecks.IsProcessAlive));
            results.Add(DoctorChecks.VaultUnlocked(status.String("vault")));
            DoctorResult present = DoctorChecks.CaCertPresent(pem);
            results.Add(present);
            if (present.Severity == DoctorSeverity.Ok) results.Add(DoctorChecks.CaTrusted(pem, ctx.IsCaTrusted));
            results.Add(DoctorChecks.ShellEnvVars(ctx.EnvironmentVariables, listen, pem));
            results.Add(DoctorChecks.ProxyPing(listen, TimeSpan.FromSeconds(2)));
            results.Add(DoctorChecks.ClaudeApiKeyHelper(ctx.UserProfile));
            Emit(a, ctx, results);
            foreach (DoctorResult r in results)
                if (r.Severity == DoctorSeverity.Fail) return CliExit.Logic;
            return CliExit.Ok;
        }

        private static void Emit(ParsedArgs a, CliContext ctx, List<DoctorResult> results)
        {
            if (a.Json)
            {
                List<object> items = new List<object>();
                foreach (DoctorResult r in results) items.Add(r.ToJson());
                CliOutput.Emit(ctx, items);
                return;
            }
            foreach (DoctorResult r in results)
                ctx.Out.WriteLine(("[" + DoctorResult.SeverityWire(r.Severity) + "]").PadRight(8) + r.Name + " — " + r.Detail);
        }
    }
}
