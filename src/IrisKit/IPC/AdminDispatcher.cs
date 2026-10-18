using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.Threading.Tasks;

namespace IrisKit
{
    /// <summary>Gestionnaire d'une méthode admin : paramètres (null si absents) → résultat JSON (dictionnaire, liste ou scalaire).</summary>
    public delegate Task<object> AdminMethod(JsonObject parameters);

    /// <summary>
    /// Routage JSON-RPC du pipe admin (SPECS §13.2, spec phase 3 §5–§6) : décode, vérifie le coffre pour les méthodes qui l'exigent,
    /// appelle le gestionnaire, traduit toute exception en erreur JSON-RPC. Ne logue que la méthode et l'id, jamais les paramètres.
    /// </summary>
    public sealed class AdminDispatcher
    {
        private readonly Dictionary<string, AdminMethod> methods = new Dictionary<string, AdminMethod>(StringComparer.Ordinal);
        private readonly HashSet<string> needsVault = new HashSet<string>(StringComparer.Ordinal);
        private readonly AdminContext context;

        public AdminDispatcher(AdminContext context)
        {
            if (context == null) throw new ArgumentNullException("context");
            this.context = context;
            SecretMethods.Register(this, context);
            VaultMethods.Register(this, context);
            ConfigMethods.Register(this, context);
            DaemonMethods.Register(this, context);
        }

        public ICollection<string> MethodNames { get { return methods.Keys; } }

        /// <summary>Déclare une méthode ; `needsVault` : refusée avec -32020 tant que le coffre est fermé.</summary>
        public void Add(string name, bool needsVault, AdminMethod method)
        {
            methods[name] = method;
            if (needsVault) this.needsVault.Add(name);
        }

        /// <summary>Trame reçue → trame de réponse. Ne lève jamais.</summary>
        public async Task<byte[]> HandleAsync(byte[] payload)
        {
            object id = null;
            object result = null;
            RpcException failure = null;
            try
            {
                RpcRequest request = JsonRpc.ParseRequest(payload, out id);
                Log.Info("ipc", "admin " + request.Method + " id=" + DescribeId(id));
                AdminMethod method;
                if (!methods.TryGetValue(request.Method, out method))
                    throw new RpcException(RpcErrors.MethodNotFound, "Method not found: " + request.Method);
                if (needsVault.Contains(request.Method) && context.Vault.State != VaultState.Unlocked) throw VaultLockedError();
                result = await method(request.Params).ConfigureAwait(false);
            }
            catch (Exception ex) { failure = Map(ex); }
            return failure == null ? JsonRpc.Success(id, result) : JsonRpc.Failure(id, failure);
        }

        public static RpcException VaultLockedError()
        {
            return new RpcException(RpcErrors.VaultLocked, "coffre verrouillé : déverrouillez-le avec vault.unlock");
        }

        /// <summary>Exception → erreur JSON-RPC (codes IRIS et irispc). Les messages ne portent jamais une valeur ni un mot de passe.</summary>
        public static RpcException Map(Exception ex)
        {
            RpcException rpc = ex as RpcException;
            if (rpc != null) return rpc;
            SecretStoreException store = ex as SecretStoreException;
            if (store != null)
            {
                switch (store.Kind)
                {
                    case SecretStoreErrorKind.UnknownSecret: return new RpcException(RpcErrors.UnknownSecret, store.Message);
                    case SecretStoreErrorKind.InvalidName: return new RpcException(RpcErrors.InvalidName, store.Message);
                    case SecretStoreErrorKind.InvalidAllowedHosts: return new RpcException(RpcErrors.InvalidAllowedHosts, store.Message);
                    case SecretStoreErrorKind.Duplicate: return new RpcException(RpcErrors.Duplicate, store.Message);
                    case SecretStoreErrorKind.VaultBusy: return new RpcException(RpcErrors.VaultBusy, store.Message);
                    case SecretStoreErrorKind.VaultLocked: return new RpcException(RpcErrors.VaultLocked, store.Message);
                    default: return new RpcException(RpcErrors.InternalError, store.Message);
                }
            }
            VaultGateException vault = ex as VaultGateException;
            if (vault != null)
            {
                switch (vault.Kind)
                {
                    case VaultGateErrorKind.BadPassword: return new RpcException(RpcErrors.BadPassword, vault.Message);
                    case VaultGateErrorKind.Exists: return new RpcException(RpcErrors.VaultExists, vault.Message);
                    case VaultGateErrorKind.Absent: return new RpcException(RpcErrors.NotFound, vault.Message);
                    default:
                        OrderedDictionary data = new OrderedDictionary();
                        data["retry_after_s"] = (long)Math.Ceiling(vault.RetryAfter.TotalSeconds);
                        return new RpcException(RpcErrors.RateLimited, vault.Message, data);
                }
            }
            ConfigKeyException key = ex as ConfigKeyException;
            if (key != null) return new RpcException(RpcErrors.InvalidParams, "unknown key: " + key.Key);
            ConfigException config = ex as ConfigException;
            if (config != null) return new RpcException(RpcErrors.InvalidParams, "invalid value '" + config.Value + "' for '" + config.Field + "'");
            if (ex is ConfigHostProtectedException) return new RpcException(RpcErrors.RuleProtected, ex.Message);
            if (ex is ConfigReloadException) return new RpcException(RpcErrors.ConfigReloadFailed, "config.reload failed: " + ex.Message);
            if (ex is JsonException || ex is FormatException) return new RpcException(RpcErrors.InvalidParams, "Invalid params: " + ex.Message);
            Log.Error("ipc", "erreur inattendue dans une méthode admin : " + ex.GetType().Name + " : " + ex.Message);
            return new RpcException(RpcErrors.InternalError, ex.Message);
        }

        private static string DescribeId(object id)
        {
            return id == null ? "null" : Convert.ToString(id, CultureInfo.InvariantCulture);
        }
    }

    /// <summary>Lecture des paramètres d'une méthode admin ; tout écart lève JsonException ou RpcException (-32602).</summary>
    internal static class AdminParams
    {
        public static JsonObject Require(JsonObject p)
        {
            if (p == null) throw new RpcException(RpcErrors.InvalidParams, "Method requires params");
            return p;
        }

        public static string String(JsonObject p, string key) { return Require(p).String(key); }

        public static IList<string> Strings(JsonObject p, string key) { return Require(p).StringArray(key); }

        public static bool Bool(JsonObject p, string key)
        {
            object value = Require(p).Raw(key);
            if (!(value is bool)) throw new JsonException("champ " + key + " : booléen attendu");
            return (bool)value;
        }

        /// <summary>Valeur binaire en base64 ; l'appelant efface le tableau après usage.</summary>
        public static byte[] Base64(JsonObject p, string key) { return Convert.FromBase64String(String(p, key)); }
    }
}
