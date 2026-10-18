using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`rule.*` et `config.*` (SPECS §13.2, spec phase 3 §5, §7) : toute mutation réussie appelle OnConfigChanged (application à chaud).</summary>
    internal static class ConfigMethods
    {
        public static void Register(AdminDispatcher d, AdminContext c)
        {
            d.Add("rule.add", false, delegate(JsonObject p)
            {
                MITMRule rule = c.Config.AddHost(AdminParams.String(p, "host"), c.Clock());
                Changed(c);
                return Task.FromResult<object>(rule.ToJson());
            });
            d.Add("rule.list", false, delegate(JsonObject p)
            {
                List<object> rules = new List<object>();
                foreach (MITMRule r in c.Config.Current.Hosts) rules.Add(r.ToJson());
                return Task.FromResult<object>(rules);
            });
            d.Add("rule.delete", false, delegate(JsonObject p)
            {
                string host = AdminParams.String(p, "host");
                if (!c.Config.DeleteHost(host, c.Clock())) throw new RpcException(RpcErrors.RuleNotFound, "rule not found: " + host);
                Changed(c);
                OrderedDictionary result = new OrderedDictionary();
                result["deleted"] = true;
                return Task.FromResult<object>(result);
            });
            d.Add("config.get", false, delegate(JsonObject p) { return Task.FromResult<object>(c.Config.Current.ToJson()); });
            d.Add("config.path", false, delegate(JsonObject p)
            {
                OrderedDictionary result = new OrderedDictionary();
                result["path"] = c.Config.Path;
                return Task.FromResult<object>(result);
            });
            d.Add("config.set", false, delegate(JsonObject p)
            {
                List<KeyValuePair<string, string>> updates = new List<KeyValuePair<string, string>>();
                foreach (object item in AdminParams.Require(p).Array("updates"))
                {
                    IDictionary<string, object> u = item as IDictionary<string, object>;
                    if (u == null) throw new JsonException("updates : objets {key, value} attendus");
                    JsonObject o = new JsonObject(u);
                    updates.Add(new KeyValuePair<string, string>(o.String("key"), o.String("value")));
                }
                ConfigSetResult r = c.Config.ApplyUpdates(updates, c.Clock());
                Changed(c);
                OrderedDictionary result = new OrderedDictionary();
                result["applied"] = new List<string>(r.Applied);
                result["requires_restart"] = new List<string>(r.RequiresRestart);
                return Task.FromResult<object>(result);
            });
            d.Add("config.reload", false, delegate(JsonObject p)
            {
                IList<string> ignored = c.Config.Reload();
                Changed(c);
                OrderedDictionary result = new OrderedDictionary();
                result["reloaded"] = true;
                result["ignored"] = new List<string>(ignored);
                return Task.FromResult<object>(result);
            });
        }

        private static void Changed(AdminContext c)
        {
            if (c.OnConfigChanged != null) c.OnConfigChanged(c.Config.Current);
        }
    }
}
