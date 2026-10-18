using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`daemon.*`, `events.*` et `ca.*` (SPECS §13.2, spec phase 3 §5).</summary>
    internal static class DaemonMethods
    {
        public static void Register(AdminDispatcher d, AdminContext c)
        {
            d.Add("daemon.status", false, delegate(JsonObject p)
            {
                OrderedDictionary o = new OrderedDictionary();
                o["pid"] = (long)c.Daemon.ProcessId;
                o["uptime_s"] = (long)Math.Max(0, Math.Floor((c.Clock() - c.Daemon.StartedAt).TotalSeconds));
                o["version"] = c.Daemon.Version;
                o["stats"] = Stats(c.Events.Ring);
                o["paused"] = c.Daemon.IsPaused;
                o["vault"] = VaultStateWire.ToWire(c.Vault.State);
                return Task.FromResult<object>(o);
            });
            d.Add("daemon.stats", false, delegate(JsonObject p) { return Task.FromResult<object>(Stats(c.Events.Ring)); });
            d.Add("daemon.pause", false, delegate(JsonObject p) { c.Daemon.SetPaused(true); return Task.FromResult<object>(Paused(true)); });
            d.Add("daemon.resume", false, delegate(JsonObject p) { c.Daemon.SetPaused(false); return Task.FromResult<object>(Paused(false)); });
            d.Add("events.query", false, delegate(JsonObject p)
            {
                List<object> result = new List<object>();
                foreach (Event e in ParseQuery(p).Run(c.Events.Ring, c.Events.Store, c.Clock())) result.Add(e.ToJson());
                return Task.FromResult<object>(result);
            });
            d.Add("events.clear", false, delegate(JsonObject p)
            {
                int ring = c.Events.Ring.Clear();
                int journal = c.Events.Store == null ? 0 : c.Events.Store.ClearAll();
                OrderedDictionary result = new OrderedDictionary();
                result["deleted_count"] = (long)Math.Max(ring, journal); // le ring est un sous-ensemble du journal
                return Task.FromResult<object>(result);
            });
            d.Add("ca.export_path", false, delegate(JsonObject p)
            {
                OrderedDictionary result = new OrderedDictionary();
                result["path"] = File.Exists(c.Vault.PemPath) ? c.Vault.PemPath : "";
                return Task.FromResult<object>(result);
            });
            d.Add("ca.fingerprint", true, delegate(JsonObject p)
            {
                OrderedDictionary result = new OrderedDictionary();
                result["sha256"] = c.Vault.CA.Info.FingerprintSha256;
                return Task.FromResult<object>(result);
            });
            d.Add("ca.is_trusted", true, delegate(JsonObject p)
            {
                OrderedDictionary result = new OrderedDictionary();
                result["trusted"] = c.IsCATrusted(c.Vault.CA.Certificate.Thumbprint);
                return Task.FromResult<object>(result);
            });
        }

        /// <summary>Compteurs cumulés du ring par kind ; `req_total` est leur somme (comme IRIS).</summary>
        internal static OrderedDictionary Stats(EventRing ring)
        {
            long total = 0;
            foreach (EventKind k in Enum.GetValues(typeof(EventKind))) total += ring.Count(k);
            OrderedDictionary o = new OrderedDictionary();
            o["req_total"] = total;
            o["sub_total"] = ring.Count(EventKind.Substituted);
            o["exfil_blocked_total"] = ring.Count(EventKind.ExfilBlocked);
            o["errors_total"] = ring.Count(EventKind.Error);
            return o;
        }

        private static OrderedDictionary Paused(bool paused)
        {
            OrderedDictionary o = new OrderedDictionary();
            o["paused"] = paused;
            return o;
        }

        private static EventQuery ParseQuery(JsonObject p)
        {
            EventQuery q = new EventQuery();
            if (p == null) return q;
            string since = p.OptionalString("since");
            if (since != null) q.Since = Json.ParseDate(since);
            string until = p.OptionalString("until");
            if (until != null) q.Until = Json.ParseDate(until);
            long? limit = p.OptionalInt("limit");
            if (limit.HasValue)
            {
                if (limit.Value <= 0) throw new RpcException(RpcErrors.InvalidParams, "Invalid params: limit doit être positif");
                q.Limit = (int)Math.Min(limit.Value, EventQuery.MaxLimit);
            }
            IList<object> kinds = p.OptionalArray("kind");
            if (kinds != null && kinds.Count > 0)
            {
                q.Kinds = new HashSet<EventKind>();
                foreach (object k in kinds)
                {
                    string s = k as string;
                    if (s == null) throw new JsonException("kind : chaînes attendues");
                    q.Kinds.Add(EventWire.ParseKind(s));
                }
            }
            q.Host = p.OptionalString("host");
            return q;
        }
    }
}
