using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Text;

namespace IrisKit
{
    /// <summary>Erreur JSON-RPC (SPECS §13.2) : code standard, IRIS ou irispc, message, données optionnelles. Jamais de valeur de secret.</summary>
    public sealed class RpcException : Exception
    {
        public int Code { get; private set; }
        public object ErrorData { get; private set; }

        public RpcException(int code, string message) : this(code, message, null) { }

        public RpcException(int code, string message, object data) : base(message)
        {
            Code = code;
            ErrorData = data;
        }
    }

    /// <summary>Codes d'erreur : JSON-RPC 2.0, IRIS (-32001…-32012) et irispc (-32020…-32024, spec phase 3 §6).</summary>
    public static class RpcErrors
    {
        public const int ParseError = -32700;
        public const int InvalidRequest = -32600;
        public const int MethodNotFound = -32601;
        public const int InvalidParams = -32602;
        public const int InternalError = -32603;
        public const int UnknownSecret = -32001;
        public const int InvalidName = -32002;
        public const int InvalidAllowedHosts = -32003;
        public const int Duplicate = -32004;
        public const int DaemonPaused = -32005;
        public const int NotFound = -32006;
        public const int RuleProtected = -32010;
        public const int RuleNotFound = -32011;
        public const int ConfigReloadFailed = -32012;
        public const int VaultLocked = -32020;
        public const int BadPassword = -32021;
        public const int VaultBusy = -32022;
        public const int RateLimited = -32023;
        public const int VaultExists = -32024;
    }

    /// <summary>Requête décodée. `Id` : long, string ou null (JSON-RPC 2.0) ; `Params` : null si absent.</summary>
    public sealed class RpcRequest
    {
        public string Method { get; private set; }
        public JsonObject Params { get; private set; }
        public object Id { get; private set; }

        public RpcRequest(string method, JsonObject parameters, object id)
        {
            Method = method;
            Params = parameters;
            Id = id;
        }
    }

    /// <summary>Enveloppes JSON-RPC 2.0 du pipe admin, côté serveur et côté client.</summary>
    public static class JsonRpc
    {
        public const string Version = "2.0";
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);

        /// <summary>
        /// Décode une requête. JSON ou UTF-8 illisible → -32700 ; enveloppe invalide → -32600 ; params non objet → -32602.
        /// `id` reçoit l'identifiant dès qu'il est lisible, pour que la réponse d'erreur le porte.
        /// </summary>
        public static RpcRequest ParseRequest(byte[] payload, out object id)
        {
            id = null;
            string text;
            try { text = StrictUtf8.GetString(payload); }
            catch (DecoderFallbackException) { throw new RpcException(RpcErrors.ParseError, "Parse error: UTF-8 invalide"); }
            object parsed;
            try { parsed = Json.Parse(text); }
            catch (JsonException) { throw new RpcException(RpcErrors.ParseError, "Parse error"); } // le message du parseur cite la requête (mot de passe compris)
            IDictionary<string, object> dict = parsed as IDictionary<string, object>;
            if (dict == null) throw new RpcException(RpcErrors.InvalidRequest, "Invalid Request: objet JSON attendu");
            object rawId;
            if (!dict.TryGetValue("id", out rawId)) throw new RpcException(RpcErrors.InvalidRequest, "Invalid Request: id manquant");
            if (rawId != null && !(rawId is long) && !(rawId is string))
                throw new RpcException(RpcErrors.InvalidRequest, "Invalid Request: id doit être entier, chaîne ou null");
            id = rawId;
            object version;
            dict.TryGetValue("jsonrpc", out version);
            if (!(version is string) || (string)version != Version)
                throw new RpcException(RpcErrors.InvalidRequest, "Invalid Request: jsonrpc doit valoir \"2.0\"");
            object method;
            dict.TryGetValue("method", out method);
            string name = method as string;
            if (string.IsNullOrEmpty(name)) throw new RpcException(RpcErrors.InvalidRequest, "Invalid Request: method manquante");
            object rawParams;
            dict.TryGetValue("params", out rawParams);
            JsonObject parameters = null;
            if (rawParams != null)
            {
                IDictionary<string, object> p = rawParams as IDictionary<string, object>;
                if (p == null) throw new RpcException(RpcErrors.InvalidParams, "Invalid params: objet attendu");
                parameters = new JsonObject(p);
            }
            return new RpcRequest(name, parameters, rawId);
        }

        public static byte[] Success(object id, object result)
        {
            OrderedDictionary o = new OrderedDictionary();
            o["jsonrpc"] = Version;
            o["id"] = id;
            o["result"] = result;
            return Encoding.UTF8.GetBytes(Json.EmitCompact(o));
        }

        public static byte[] Failure(object id, RpcException error)
        {
            OrderedDictionary e = new OrderedDictionary();
            e["code"] = (long)error.Code;
            e["message"] = error.Message;
            if (error.ErrorData != null) e["data"] = error.ErrorData;
            OrderedDictionary o = new OrderedDictionary();
            o["jsonrpc"] = Version;
            o["id"] = id;
            o["error"] = e;
            return Encoding.UTF8.GetBytes(Json.EmitCompact(o));
        }

        /// <summary>Requête côté client ; `parameters` null = pas de champ params.</summary>
        public static byte[] Request(long id, string method, IDictionary parameters)
        {
            OrderedDictionary o = new OrderedDictionary();
            o["jsonrpc"] = Version;
            o["method"] = method;
            if (parameters != null) o["params"] = parameters;
            o["id"] = id;
            return Encoding.UTF8.GetBytes(Json.EmitCompact(o));
        }

        /// <summary>Côté client : rend `result` (dictionnaire, liste ou scalaire) ou lève RpcException avec le code et le message du serveur.</summary>
        public static object ParseResponse(byte[] payload, long expectedId)
        {
            JsonObject o;
            try { o = Json.ParseObject(StrictUtf8.GetString(payload)); }
            catch (JsonException ex) { throw new RpcException(RpcErrors.ParseError, "réponse illisible : " + ex.Message); }
            catch (DecoderFallbackException) { throw new RpcException(RpcErrors.ParseError, "réponse illisible : UTF-8 invalide"); }
            JsonObject error = o.OptionalObject("error");
            if (error != null) throw new RpcException((int)error.Int("code"), error.String("message"), error.Raw("data"));
            object id = o.Raw("id");
            if (!(id is long) || (long)id != expectedId) throw new RpcException(RpcErrors.InvalidRequest, "réponse pour un autre id");
            if (!o.Has("result")) throw new RpcException(RpcErrors.InvalidRequest, "réponse sans result ni error");
            return o.Raw("result");
        }
    }
}
