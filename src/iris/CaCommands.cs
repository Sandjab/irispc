using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris ca export|fingerprint|is-trusted` ; install/uninstall arrivent en phase 7.</summary>
    internal static class CaCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec { Path = "ca export", Usage = "ca export [--path P | --print] [--json]", Summary = "chemin de ca.pem, copie (--path) ou contenu PEM (--print)", Options = new[] { "--path" }, Flags = new[] { "--print", "--json" }, UsesDaemon = true, Run = Export });
            list.Add(new CommandSpec { Path = "ca fingerprint", Usage = "ca fingerprint [--json]", Summary = "empreinte SHA-256 du CA", Flags = new[] { "--json" }, UsesDaemon = true, Run = Fingerprint });
            list.Add(new CommandSpec { Path = "ca is-trusted", Usage = "ca is-trusted [--json]", Summary = "le CA est-il dans le magasin racine de l'utilisateur ? (code 1 sinon)", Flags = new[] { "--json" }, UsesDaemon = true, Run = IsTrusted });
        }

        private static int Export(ParsedArgs a, CliContext ctx)
        {
            string destination = a.Option("--path");
            if (destination != null && a.Flag("--print")) throw new UsageException("--path et --print sont exclusifs");
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("ca.export_path", null);
            string source = CliConnection.AsObject(raw).String("path");
            if (source.Length == 0) throw new CliException(CliExit.Logic, "CA absent : déverrouillez ou créez le coffre (iris vault unlock)");
            if (destination != null)
            {
                string target;
                try
                {
                    target = Paths.ExpandHome(destination, ctx.UserProfile);
                    File.Copy(source, target, true);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException || ex is ArgumentException || ex is NotSupportedException)
                        throw new CliException(CliExit.Io, "copie du CA impossible vers " + destination + " : " + ex.Message);
                    throw;
                }
                CliOutput.Ack(ctx, a.Json, "CA copié vers " + target);
                return CliExit.Ok;
            }
            if (a.Flag("--print"))
            {
                ctx.Out.Write(File.ReadAllText(source, Encoding.UTF8));
                return CliExit.Ok;
            }
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine(source);
            return CliExit.Ok;
        }

        private static int Fingerprint(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("ca.fingerprint", null);
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine("sha256 : " + CliConnection.AsObject(raw).String("sha256"));
            return CliExit.Ok;
        }

        private static int IsTrusted(ParsedArgs a, CliContext ctx)
        {
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("ca.is_trusted", null);
            bool trusted = CliConnection.AsObject(raw).Bool("trusted", false);
            if (a.Json) CliOutput.Emit(ctx, raw);
            else ctx.Out.WriteLine(trusted ? "approuvé" : "non approuvé");
            return trusted ? CliExit.Ok : CliExit.Logic;
        }
    }
}
