using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using IrisKit;

namespace IrisCli
{
    /// <summary>`iris logs` : `events.query` ponctuel, ou flux SSE (`--follow`) jusqu'à Ctrl+C ; ndjson en --json --follow.</summary>
    internal static class LogsCommand
    {
        public static void Register(IList<CommandSpec> list)
        {
            list.Add(new CommandSpec
            {
                Path = "logs",
                Usage = "logs [--since T] [--until T] [--limit N] [--kind k1,k2] [--host H] [--follow] [--json]",
                Summary = "events du daemon (T : 30s, 5m, 1h, 2d ou ISO-8601) ; --follow suit le flux jusqu'à Ctrl+C",
                Options = new[] { "--since", "--until", "--limit", "--kind", "--host" },
                Flags = new[] { "--follow", "--json" },
                UsesDaemon = true,
                Run = Run
            });
        }

        /// <summary>`<date ISO>  <kind>  <hôte>  <méthode> <chemin>  sub=<noms> dur=<ms>` (comme IRIS).</summary>
        public static string Line(Event e)
        {
            string subs = e.SubstitutedSecrets.Count == 0 ? "-" : string.Join(",", e.SubstitutedSecrets);
            string duration = e.DurationMs.HasValue ? e.DurationMs.Value.ToString(CultureInfo.InvariantCulture) + "ms" : "-";
            return Json.FormatDate(e.Timestamp) + "  " + EventWire.KindToWire(e.Kind) + "  " + e.Host + "  " + e.Method + " " + e.Path + "  sub=" + subs + " dur=" + duration;
        }

        private static int Run(ParsedArgs a, CliContext ctx)
        {
            List<string> kinds = Kinds(a.Option("--kind"));
            string host = a.Option("--host");
            if (a.Flag("--follow"))
            {
                if (a.Option("--since") != null || a.Option("--until") != null || a.Option("--limit") != null)
                    throw new UsageException("--follow est incompatible avec --since, --until et --limit");
                return Follow(a, ctx, kinds, host);
            }
            OrderedDictionary p = new OrderedDictionary();
            if (a.Option("--since") != null) p["since"] = Json.FormatDate(RelativeTime.Parse(a.Option("--since"), ctx.Now()));
            if (a.Option("--until") != null) p["until"] = Json.FormatDate(RelativeTime.Parse(a.Option("--until"), ctx.Now()));
            if (a.Option("--limit") != null)
            {
                int limit;
                if (!int.TryParse(a.Option("--limit"), NumberStyles.None, CultureInfo.InvariantCulture, out limit) || limit <= 0)
                    throw new UsageException("--limit attend un entier positif");
                p["limit"] = (long)limit;
            }
            if (kinds.Count > 0) p["kind"] = kinds;
            if (host != null) p["host"] = host;
            object raw;
            using (CliConnection c = CliConnection.Open(a, ctx)) raw = c.Call("events.query", p);
            if (a.Json)
            {
                CliOutput.Emit(ctx, raw);
                return CliExit.Ok;
            }
            IList<object> events = CliConnection.AsList(raw);
            if (events.Count == 0) ctx.Out.WriteLine("aucun event");
            foreach (object item in events) ctx.Out.WriteLine(Line(Event.FromJson(CliConnection.AsObject(item))));
            return CliExit.Ok;
        }

        private static List<string> Kinds(string raw)
        {
            List<string> kinds = new List<string>();
            if (raw == null) return kinds;
            foreach (string part in raw.Split(','))
            {
                string k = part.Trim();
                if (k.Length == 0) continue;
                try { EventWire.ParseKind(k); }
                catch (JsonException) { throw new UsageException("kind inconnu : " + k + " (substituted, passThrough, noMatch, exfilBlocked, error, systemAlert)"); }
                kinds.Add(k);
            }
            return kinds;
        }

        private static int Follow(ParsedArgs a, CliContext ctx, List<string> kinds, string host)
        {
            ctx.Interruptible = true;
            int port;
            using (CliConnection c = CliConnection.Open(a, ctx))
                port = EventsPort(CliConnection.AsObject(c.Call("config.get", null)).Object("broker").String("events_listen"));
            if (ctx.Cancel.IsCancellationRequested) return CliExit.Ok;
            EventsClient sse;
            try { sse = EventsClient.ConnectAsync(port, Query(kinds, host), TimeSpan.FromSeconds(60)).GetAwaiter().GetResult(); }
            catch (SocketException ex) { throw new CliException(CliExit.Io, "flux d'events injoignable : " + ex.Message); }
            catch (IOException ex) { throw new CliException(CliExit.Io, "flux d'events injoignable : " + ex.Message); }
            catch (EventsClientException ex) { throw new CliException(CliExit.Io, "flux d'events refusé : " + ex.Message); }
            using (sse)
            using (ctx.Cancel.Register(delegate { sse.Dispose(); }))
            {
                while (true)
                {
                    SseMessage m;
                    try { m = sse.ReadAsync().GetAwaiter().GetResult(); }
                    catch (Exception ex)
                    {
                        if (ctx.Cancel.IsCancellationRequested) return CliExit.Ok;
                        if (ex is IOException || ex is ObjectDisposedException || ex is SocketException || ex is TimeoutException)
                            throw new CliException(CliExit.Io, "flux d'events interrompu : " + ex.Message);
                        throw;
                    }
                    if (m == null)
                    {
                        if (ctx.Cancel.IsCancellationRequested) return CliExit.Ok;
                        throw new CliException(CliExit.Io, "flux d'events interrompu : le daemon a fermé la connexion");
                    }
                    if (m.IsComment) continue;
                    if (m.EventName == "dropped")
                    {
                        ctx.Err.WriteLine("avertissement : events perdus, lecteur trop lent (" + m.Data + ")");
                        continue;
                    }
                    Event e = m.ToEvent();
                    ctx.Out.WriteLine(a.Json ? Json.EmitCompact(e.ToJson()) : Line(e));
                    ctx.Out.Flush();
                }
            }
        }

        private static int EventsPort(string listen)
        {
            int colon = listen.LastIndexOf(':');
            int port;
            if (colon < 0 || !int.TryParse(listen.Substring(colon + 1), NumberStyles.None, CultureInfo.InvariantCulture, out port) || port <= 0 || port > 65535)
                throw new CliException(CliExit.Logic, "broker.events_listen invalide : " + listen);
            return port;
        }

        private static string Query(List<string> kinds, string host)
        {
            List<string> parts = new List<string>();
            if (kinds.Count > 0) parts.Add("kind=" + Uri.EscapeDataString(string.Join(",", kinds)));
            if (host != null) parts.Add("host=" + Uri.EscapeDataString(host));
            return string.Join("&", parts);
        }
    }
}
