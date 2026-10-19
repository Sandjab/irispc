using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris mcp wrap|unwrap` (SPECS §16.1, spec phase 5 §6) : seul le fichier MCP est écrit, jamais config.json ni le coffre.</summary>
    internal static class McpCommands
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec
            {
                Path = "mcp wrap",
                Usage = "mcp wrap PATH [--dry-run] [--watch] [--log-level L] [--json]",
                Summary = "ajoute proxy et CA aux serveurs MCP du fichier (.mcp.json, .claude.json, claude_desktop_config.json)",
                Positionals = new[] { "PATH" },
                Options = new[] { "--log-level" },
                Flags = new[] { "--dry-run", "--watch", "--json" },
                UsesDaemon = true,
                Run = Wrap
            });
            list.Add(new CommandSpec { Path = "mcp unwrap", Usage = "mcp unwrap PATH [--json]", Summary = "restaure le fichier depuis PATH.iris.bak", Positionals = new[] { "PATH" }, Flags = new[] { "--json" }, Run = Unwrap });
        }

        private sealed class Target
        {
            public string Listen;
            public string CaPem;
        }

        private static string ResolvePath(string raw, CliContext ctx)
        {
            try { return Paths.ExpandHome(raw, ctx.UserProfile); }
            catch (ArgumentException ex) { throw new UsageException("chemin invalide : " + raw + " (" + ex.Message + ")"); }
            catch (NotSupportedException ex) { throw new UsageException("chemin invalide : " + raw + " (" + ex.Message + ")"); }
        }

        private static Target FetchTarget(string pipe, CliContext ctx)
        {
            Target t = new Target();
            using (CliConnection c = CliConnection.Open(pipe, ctx))
            {
                t.Listen = CliConnection.AsObject(c.Call("config.get", null)).Object("broker").String("listen");
                t.CaPem = CliConnection.AsObject(c.Call("ca.export_path", null)).String("path");
            }
            if (t.CaPem.Length == 0) throw new CliException(CliExit.Logic, "CA absent : déverrouillez ou créez le coffre (iris vault unlock), puis relancez");
            return t;
        }

        private static McpWrapOptions Options(string path, Target t, bool dryRun, CliContext ctx)
        {
            McpWrapOptions o = new McpWrapOptions();
            o.Path = path;
            o.BrokerListen = t.Listen;
            o.CaPemPath = t.CaPem;
            o.DryRun = dryRun;
            o.Registry = WrappedPathsRegistry.ForDataDir(ctx.DataDirectory);
            return o;
        }

        private static int Wrap(ParsedArgs a, CliContext ctx)
        {
            string path = ResolvePath(a.Positional(0), ctx);
            bool watch = a.Flag("--watch");
            if (watch && a.Flag("--dry-run")) throw new UsageException("--watch et --dry-run sont exclusifs");
            if (a.Option("--log-level") != null && !watch) throw new UsageException("--log-level ne s'utilise qu'avec --watch");
            if (path.EndsWith(".iris.bak", StringComparison.OrdinalIgnoreCase)) throw new CliException(CliExit.Logic, "refus d'enrober un backup : " + path);
            if (watch) return Watch(a, ctx, path);
            Target t = FetchTarget(CliConnection.ResolvePipe(a, ctx), ctx);
            McpWrapResult r;
            try { r = McpWrapper.Wrap(Options(path, t, a.Flag("--dry-run"), ctx)); }
            catch (McpFileException ex) { throw new CliException(ex.IsIo ? CliExit.Io : CliExit.Logic, ex.Message); }
            if (r.Outcome == McpWrapOutcome.CommentsFound)
                throw new CliException(CliExit.Logic, path + " : commentaires détectés en L" + r.FirstComment.Line + ":" + r.FirstComment.Column + " : retirez-les ou utilisez --dry-run");
            if (r.Outcome == McpWrapOutcome.ChangedDuringPatch)
                throw new CliException(CliExit.Logic, "fichier modifié pendant le patch : relancez (" + path + ")");
            if (r.RegistryWarning != null) ctx.Err.WriteLine("avertissement : " + r.RegistryWarning);
            if (a.Json)
            {
                CliOutput.Emit(ctx, Summary(r.Patch.Summary));
                return CliExit.Ok;
            }
            if (r.Outcome == McpWrapOutcome.AlreadyCompliant) ctx.Out.WriteLine("déjà conforme : " + path);
            else if (r.Outcome == McpWrapOutcome.DryRun)
            {
                foreach (string addition in r.Patch.Additions) ctx.Out.WriteLine("+ " + addition);
                foreach (string server in r.Patch.SkippedServers) ctx.Out.WriteLine("ignoré (http/sse sans env) : " + server);
                ctx.Out.WriteLine("(simulation : rien n'a été écrit)");
            }
            else ctx.Out.WriteLine("patché : " + path + " (backup : " + r.BackupPath + ")");
            return CliExit.Ok;
        }

        private static OrderedDictionary Summary(McpPatchSummary s)
        {
            OrderedDictionary o = new OrderedDictionary();
            o["patched"] = (long)s.Patched;
            o["already_compliant"] = (long)s.AlreadyCompliant;
            o["skipped"] = (long)s.Skipped;
            o["errors"] = 0L;
            return o;
        }

        private static int Unwrap(ParsedArgs a, CliContext ctx)
        {
            string path = ResolvePath(a.Positional(0), ctx);
            string warning;
            try { warning = McpWrapper.Unwrap(path, WrappedPathsRegistry.ForDataDir(ctx.DataDirectory)); }
            catch (McpFileException ex) { throw new CliException(ex.IsIo ? CliExit.Io : CliExit.Logic, ex.Message); }
            if (warning != null) ctx.Err.WriteLine("avertissement : " + warning);
            if (a.Json)
            {
                OrderedDictionary o = new OrderedDictionary();
                o["ok"] = true;
                o["restored"] = path;
                CliOutput.Emit(ctx, o);
            }
            else ctx.Out.WriteLine("restauré : " + path);
            return CliExit.Ok;
        }

        // ---- --watch ------------------------------------------------------------------------

        private static int Watch(ParsedArgs a, CliContext ctx, string path)
        {
            LogLevel minimum = LogLevel.Info;
            string level = a.Option("--log-level");
            if (level != null && !LogLevelWire.TryParse(level, out minimum))
                throw new UsageException("niveau de log inconnu : " + level + " (trace | debug | info | warn | error)");
            if (!File.Exists(path)) throw new CliException(CliExit.Logic, "fichier introuvable : " + path);
            WatchLoop loop = new WatchLoop(ctx, minimum, path, CliConnection.ResolvePipe(a, ctx));
            ctx.Interruptible = true;
            // L'observateur est créé avant le premier cycle : un changement pendant ce cycle n'est pas perdu.
            using (McpFileWatcher watcher = new McpFileWatcher(path, TimeSpan.FromMilliseconds(500)))
            {
                if (!loop.Cycle(true)) return CliExit.Unreachable;
                loop.Log(LogLevel.Info, "surveillance de " + path + " (Ctrl+C pour arrêter)");
                while (true)
                {
                    try { watcher.WaitForChange(ctx.Cancel); }
                    catch (OperationCanceledException)
                    {
                        loop.Log(LogLevel.Info, "arrêt de la surveillance");
                        return CliExit.Ok;
                    }
                    loop.Cycle(false);
                }
            }
        }

        /// <summary>Un cycle par changement : config et CA relus au daemon ; les échecs sont journalisés, la surveillance continue.</summary>
        private sealed class WatchLoop
        {
            private readonly CliContext ctx;
            private readonly LogLevel minimum;
            private readonly string path;
            private readonly string pipe;
            private byte[] lastHash;

            public WatchLoop(CliContext ctx, LogLevel minimum, string path, string pipe)
            {
                this.ctx = ctx;
                this.minimum = minimum;
                this.path = path;
                this.pipe = pipe;
            }

            public void Log(LogLevel level, string message)
            {
                if (level < minimum) return;
                ctx.Err.WriteLine(Json.FormatDate(ctx.Now()) + " " + LogLevelWire.ToWire(level) + " " + message);
                ctx.Err.Flush();
            }

            /// <summary>Faux seulement au premier cycle, daemon injoignable ou identité refusée (code 2).</summary>
            public bool Cycle(bool first)
            {
                Target t;
                try { t = FetchTarget(pipe, ctx); }
                catch (DaemonUnreachableException ex)
                {
                    if (first)
                    {
                        ctx.Err.WriteLine(ex.Message);
                        return false;
                    }
                    Log(LogLevel.Warn, "daemon injoignable : nouvel essai au prochain changement");
                    return true;
                }
                catch (AdminServerIdentityException ex)
                {
                    if (first)
                    {
                        ctx.Err.WriteLine("erreur : " + ex.Message);
                        return false;
                    }
                    Log(LogLevel.Warn, ex.Message);
                    return true;
                }
                catch (CliException ex)
                {
                    Log(LogLevel.Warn, ex.Message);
                    return true;
                }
                catch (RpcException ex)
                {
                    Log(LogLevel.Warn, "erreur du daemon : " + RpcMessages.For(ex));
                    return true;
                }
                McpWrapOptions o = Options(path, t, false, ctx);
                o.SkipIfHash = lastHash;
                McpWrapResult r;
                try { r = McpWrapper.Wrap(o); }
                catch (McpFileException ex)
                {
                    Log(LogLevel.Warn, ex.Message);
                    return true;
                }
                switch (r.Outcome)
                {
                    case McpWrapOutcome.SkippedOwnWrite:
                        Log(LogLevel.Debug, "contenu déjà traité (écriture d'iris) : ignoré");
                        break;
                    case McpWrapOutcome.AlreadyCompliant:
                        lastHash = r.ContentHash;
                        Log(LogLevel.Debug, "déjà conforme");
                        break;
                    case McpWrapOutcome.CommentsFound:
                        Log(LogLevel.Warn, "commentaires détectés en L" + r.FirstComment.Line + ":" + r.FirstComment.Column + " : écriture refusée");
                        break;
                    case McpWrapOutcome.ChangedDuringPatch:
                        Log(LogLevel.Warn, "fichier modifié pendant le patch : nouvel essai au prochain changement");
                        break;
                    default:
                        lastHash = r.ContentHash;
                        Log(LogLevel.Info, "fichier patché (backup : " + Path.GetFileName(r.BackupPath) + ", serveurs patchés : " + r.Patch.Summary.Patched + ")");
                        if (r.RegistryWarning != null) Log(LogLevel.Warn, r.RegistryWarning);
                        break;
                }
                return true;
            }
        }
    }
}
