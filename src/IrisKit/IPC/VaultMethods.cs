using System.Collections.Specialized;
using System.Security;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>`vault.*` propres à irispc (spec phase 3 §6). Le mot de passe passe en SecureString dès le décodage ; jamais logué.</summary>
    internal static class VaultMethods
    {
        public static void Register(AdminDispatcher d, AdminContext c)
        {
            d.Add("vault.status", false, delegate(JsonObject p)
            {
                OrderedDictionary o = new OrderedDictionary();
                o["state"] = VaultStateWire.ToWire(c.Vault.State);
                o["path"] = c.Vault.KdbxPath;
                return Task.FromResult<object>(o);
            });
            d.Add("vault.unlock", false, delegate(JsonObject p)
            {
                using (SecureString password = Password(p)) c.Vault.Unlock(password);
                return Task.FromResult<object>(Unlocked());
            });
            d.Add("vault.create", false, delegate(JsonObject p)
            {
                using (SecureString password = Password(p)) c.Vault.Create(password);
                return Task.FromResult<object>(Unlocked());
            });
        }

        private static OrderedDictionary Unlocked()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["state"] = "unlocked";
            return o;
        }

        /// <summary>`password` chaîne non vide → SecureString ; la string JSON intermédiaire est une limite du runtime (spec §6).</summary>
        private static SecureString Password(JsonObject p)
        {
            string text = AdminParams.Require(p).Raw("password") as string;
            if (string.IsNullOrEmpty(text)) throw new RpcException(RpcErrors.InvalidParams, "Invalid params: password doit être une chaîne non vide");
            SecureString s = new SecureString();
            foreach (char ch in text) s.AppendChar(ch);
            s.MakeReadOnly();
            return s;
        }
    }
}
