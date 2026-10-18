using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`secret.*` (SPECS §13.2) : métadonnées seulement en sortie, jamais de valeur ; valeurs d'entrée en base64, effacées après usage.</summary>
    internal static class SecretMethods
    {
        public static void Register(AdminDispatcher d, AdminContext c)
        {
            d.Add("secret.list", true, async delegate(JsonObject p)
            {
                IList<Secret> list = await c.Vault.Secrets.ListAsync().ConfigureAwait(false);
                List<object> result = new List<object>();
                foreach (Secret s in list) result.Add(s.ToJson());
                return (object)result;
            });
            d.Add("secret.get", true, async delegate(JsonObject p)
            {
                Secret s = await c.Vault.Secrets.SecretAsync(AdminParams.String(p, "name")).ConfigureAwait(false);
                return (object)s.ToJson();
            });
            d.Add("secret.add", true, async delegate(JsonObject p)
            {
                string name = AdminParams.String(p, "name");
                IList<string> hosts = AdminParams.Strings(p, "allowed_hosts");
                byte[] value = AdminParams.Base64(p, "value");
                try
                {
                    Secret s = await c.Vault.Secrets.AddAsync(name, value, hosts, c.Clock()).ConfigureAwait(false);
                    return (object)s.ToJson();
                }
                finally { Array.Clear(value, 0, value.Length); }
            });
            d.Add("secret.update", true, async delegate(JsonObject p)
            {
                Secret s = await c.Vault.Secrets.UpdateAsync(AdminParams.String(p, "name"), AdminParams.Strings(p, "allowed_hosts")).ConfigureAwait(false);
                return (object)s.ToJson();
            });
            d.Add("secret.rotate", true, async delegate(JsonObject p)
            {
                string name = AdminParams.String(p, "name");
                byte[] value = AdminParams.Base64(p, "value");
                try
                {
                    Secret s = await c.Vault.Secrets.RotateAsync(name, value).ConfigureAwait(false);
                    return (object)s.ToJson();
                }
                finally { Array.Clear(value, 0, value.Length); }
            });
            d.Add("secret.delete", true, async delegate(JsonObject p)
            {
                await c.Vault.Secrets.DeleteAsync(AdminParams.String(p, "name")).ConfigureAwait(false);
                OrderedDictionary result = new OrderedDictionary();
                result["deleted"] = true;
                return (object)result;
            });
            d.Add("secret.set_quarantined", true, async delegate(JsonObject p)
            {
                Secret s = await c.Vault.Secrets.SetQuarantinedAsync(AdminParams.String(p, "name"), AdminParams.Bool(p, "quarantined")).ConfigureAwait(false);
                return (object)s.ToJson();
            });
        }
    }
}
