using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Méthodes rule/config/daemon/events/ca (spec phase 3 §5) -------------------

        private static Event IpcEvent(EventKind kind, string host, DateTime at)
        {
            return new Event(Guid.NewGuid(), at, kind, host, "GET", "/x", 200, 5, null, null, null, EventFlags.None);
        }

        private static List<string> Hosts(object result)
        {
            List<string> hosts = new List<string>();
            foreach (object o in (IList<object>)result) hosts.Add(new JsonObject((IDictionary<string, object>)o).String("host"));
            return hosts;
        }

        private static void Methods_RulesAndConfig()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                Check.True(Hosts(rig.Call("rule.list", null)).Contains("api.anthropic.com"), "rule.list : hôte semé");
                JsonObject added = R(rig.Call("rule.add", P("host", "API.Example.com")));
                Check.True(added.String("host") == "api.example.com" && added.String("origin") == "user", "rule.add normalise, origin user");
                Check.True(rig.Applied.Count == 1 && rig.Applied[0].AllowedHosts.Contains("api.example.com"), "OnConfigChanged reçoit la nouvelle whitelist");
                rig.Call("rule.add", P("host", "api.example.com"));
                Check.Eq(2, Hosts(rig.Call("rule.list", null)).Count, "rule.add idempotent");
                Check.True(R(rig.Call("rule.delete", P("host", "api.example.com"))).Bool("deleted", false), "rule.delete");
                rig.Fails("rule.delete", P("host", "api.example.com"), RpcErrors.RuleNotFound);
                rig.Fails("rule.delete", P("host", "api.anthropic.com"), RpcErrors.RuleProtected);
                rig.Fails("rule.add", P("host", "bad host"), RpcErrors.InvalidParams);

                JsonObject config = R(rig.Call("config.get", null));
                Check.Eq("iris-admin", config.Object("broker").String("admin_pipe"), "config.get : broker.admin_pipe");
                Check.True(R(rig.Call("config.path", null)).String("path").EndsWith("config.json"), "config.path");
                JsonObject set = R(rig.Call("config.set", P("updates", new object[] {
                    P("key", "security.max_substitutions_per_minute", "value", "5"),
                    P("key", "broker.listen", "value", "127.0.0.1:9999") })));
                Check.Eq("security.max_substitutions_per_minute", string.Join(",", set.StringArray("applied")), "applied");
                Check.Eq("broker.listen", string.Join(",", set.StringArray("requires_restart")), "requires_restart");
                Check.Eq(5, rig.Applied[rig.Applied.Count - 1].Security.MaxSubstitutionsPerMinute, "OnConfigChanged reçoit la sécurité");
                Check.True(rig.Fails("config.set", P("updates", new object[] { P("key", "nope", "value", "1") }), RpcErrors.InvalidParams).Message.Contains("unknown key"), "clé inconnue");
                Check.True(rig.Fails("config.set", P("updates", new object[] { P("key", "security.max_substitutions_per_minute", "value", "0") }), RpcErrors.InvalidParams).Message.Contains("invalid value"), "valeur refusée");
                rig.Fails("config.set", P("updates", new object[] { P("key", "backups.max_count", "value", 3L) }), RpcErrors.InvalidParams);

                Config c = rig.Config.Current;
                Config edited = new Config(c.Version, new BrokerConfig("127.0.0.1:7777", c.Broker.EventsListen, c.Broker.AdminPipe, c.Broker.LogLevel, c.Broker.EventRetentionDays, c.Broker.EventRingSize),
                    new SecurityConfig(ExfilPolicy.BlockOnly, 9), c.Backups, c.Hosts, c.Plugins);
                File.WriteAllText(rig.Config.Path, Json.Emit(edited.ToJson()), new UTF8Encoding(false));
                JsonObject reload = R(rig.Call("config.reload", null));
                Check.True(reload.Bool("reloaded", false) && string.Join(",", reload.StringArray("ignored")) == "broker.listen", "config.reload : ignored");
                Check.Eq(9, rig.Applied[rig.Applied.Count - 1].Security.MaxSubstitutionsPerMinute, "config.reload appliqué à chaud");
                File.WriteAllText(rig.Config.Path, "{ corrompu");
                rig.Fails("config.reload", null, RpcErrors.ConfigReloadFailed);
            }
        }

        private static void Methods_DaemonStatusAndPause()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                rig.Events.Emit(IpcEvent(EventKind.Substituted, "a.example", T0));
                rig.Events.Emit(IpcEvent(EventKind.Substituted, "a.example", T0));
                rig.Events.Emit(IpcEvent(EventKind.Error, "b.example", T0));
                JsonObject stats = R(rig.Call("daemon.stats", null));
                Check.True(stats.Int("req_total") == 3 && stats.Int("sub_total") == 2 && stats.Int("errors_total") == 1 && stats.Int("exfil_blocked_total") == 0, "daemon.stats");
                rig.Now = T0.AddSeconds(90.7);
                JsonObject status = R(rig.Call("daemon.status", null));
                Check.True(status.Int("pid") == 4242 && status.String("version") == "9.9.9" && status.Int("uptime_s") == 90, "pid, version, uptime");
                Check.True(!status.Bool("paused", true) && status.String("vault") == "unlocked" && status.Object("stats").Int("req_total") == 3, "paused, vault, stats");
                Check.True(R(rig.Call("daemon.pause", null)).Bool("paused", false) && rig.Daemon.Paused, "daemon.pause");
                Check.True(R(rig.Call("daemon.status", null)).Bool("paused", false), "status reflète la pause");
                Check.True(!R(rig.Call("daemon.resume", null)).Bool("paused", true) && !rig.Daemon.Paused, "daemon.resume");
            }
            using (DispatcherRig locked = new DispatcherRig(false, null))
                Check.Eq("absent", R(locked.Call("daemon.status", null)).String("vault"), "daemon.status : vault absent");
        }

        private static void Methods_EventsQueryAndClear()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                rig.Now = T0.AddDays(3);
                Event old = IpcEvent(EventKind.Error, "old.example", T0.AddDays(1));
                rig.Events.Store.Append(old); // journal seul : hors du ring
                Event a = IpcEvent(EventKind.Substituted, "a.example", T0.AddDays(3));
                Event b = IpcEvent(EventKind.Error, "b.example", T0.AddDays(3).AddSeconds(1));
                rig.Events.Emit(a);
                rig.Events.Emit(b);
                IList<object> ring = (IList<object>)rig.Call("events.query", null);
                Check.Eq(2, ring.Count, "sans since : le ring seul");
                IList<object> all = (IList<object>)rig.Call("events.query", P("since", Json.FormatDate(T0)));
                Check.Eq(3, all.Count, "since antérieur au ring : complété par le journal (fichier du jour ouvert en écriture)");
                Check.Eq("old.example", R(all[0]).String("host"), "ordre chronologique");
                Check.Eq(1, ((IList<object>)rig.Call("events.query", P("since", Json.FormatDate(T0), "kind", new[] { "error" }, "host", "b.example"))).Count, "filtres kind et host");
                IList<object> last = (IList<object>)rig.Call("events.query", P("since", Json.FormatDate(T0), "limit", 1L));
                Check.True(last.Count == 1 && R(last[0]).String("host") == "b.example", "limit garde les plus récents");
                Check.Eq(3, ((IList<object>)rig.Call("events.query", P("since", Json.FormatDate(T0), "limit", 999999L))).Count, "limit énorme plafonné");
                Check.Eq(2, ((IList<object>)rig.Call("events.query", P("until", Json.FormatDate(T0.AddDays(3)), "since", Json.FormatDate(T0)))).Count, "until");
                rig.Fails("events.query", P("limit", 0L), RpcErrors.InvalidParams);
                rig.Fails("events.query", P("limit", -5L), RpcErrors.InvalidParams);
                rig.Fails("events.query", P("kind", new[] { "bogus" }), RpcErrors.InvalidParams);
                rig.Fails("events.query", P("since", "hier"), RpcErrors.InvalidParams);
                Check.Eq(3L, R(rig.Call("events.clear", null)).Int("deleted_count"), "events.clear : events distincts supprimés");
                Check.Eq(0, ((IList<object>)rig.Call("events.query", P("since", Json.FormatDate(T0)))).Count, "plus rien ni dans le ring ni dans le journal");
                Check.Eq(0, Directory.GetFiles(Path.Combine(rig.Dir, "events"), "events-*.jsonl").Length, "fichiers JSONL supprimés");
                rig.Events.Emit(IpcEvent(EventKind.NoMatch, "c.example", T0.AddDays(3)));
                Check.Eq(1, Directory.GetFiles(Path.Combine(rig.Dir, "events"), "events-*.jsonl").Length, "le journal reprend après clear");
            }
        }

        private static void Methods_CA()
        {
            using (DispatcherRig rig = new DispatcherRig(true, null))
            {
                Check.Eq(Path.Combine(rig.Dir, "ca.pem"), R(rig.Call("ca.export_path", null)).String("path"), "ca.export_path");
                Check.Eq(rig.Vault.CA.Info.FingerprintSha256, R(rig.Call("ca.fingerprint", null)).String("sha256"), "ca.fingerprint");
                Check.True(!R(rig.Call("ca.is_trusted", null)).Bool("trusted", true), "ca.is_trusted : faux");
                Check.Eq(rig.Vault.CA.Certificate.Thumbprint, rig.TrustedAsked, "empreinte SHA-1 transmise à la sonde");
                rig.Trusted = true;
                Check.True(R(rig.Call("ca.is_trusted", null)).Bool("trusted", false), "ca.is_trusted : vrai");
            }
            using (DispatcherRig locked = new DispatcherRig(false, null))
            {
                Check.Eq("", R(locked.Call("ca.export_path", null)).String("path"), "ca.export_path sans ca.pem");
                locked.Fails("ca.fingerprint", null, RpcErrors.VaultLocked);
                locked.Fails("ca.is_trusted", null, RpcErrors.VaultLocked);
            }
            using (CAManager fresh = FreshCA())
                Check.True(!CATrust.IsInCurrentUserRoot(fresh.Certificate.Thumbprint), "CA neuf absent de CurrentUser\\Root (lecture seule)");
        }
    }
}
