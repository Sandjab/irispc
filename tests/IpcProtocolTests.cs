using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Text;
using System.Threading;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Trames et JSON-RPC (spec phase 3 §4) ---------------------------------

        private static void Frame_RoundTripAndLimits()
        {
            MemoryStream s = new MemoryStream();
            Wait(FrameCodec.WriteAsync(s, Bytes("{\"a\":1}"), CancellationToken.None));
            Wait(FrameCodec.WriteAsync(s, new byte[258], CancellationToken.None));
            byte[] raw = s.ToArray();
            Check.True(raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 7, "longueur big-endian (7)");
            Check.True(raw[11] == 0 && raw[12] == 0 && raw[13] == 1 && raw[14] == 2, "longueur big-endian (258)");
            s.Position = 0;
            Check.Eq("{\"a\":1}", Encoding.UTF8.GetString(Wait(FrameCodec.ReadAsync(s, FrameCodec.MaxRequestBytes, CancellationToken.None))), "première trame");
            Check.Eq(258, Wait(FrameCodec.ReadAsync(s, FrameCodec.MaxRequestBytes, CancellationToken.None)).Length, "seconde trame");
            Check.True(Wait(FrameCodec.ReadAsync(s, FrameCodec.MaxRequestBytes, CancellationToken.None)) == null, "EOF propre → null");

            Check.Throws<EndOfStreamException>(delegate { Wait(FrameCodec.ReadAsync(new MemoryStream(new byte[] { 0, 0 }), 100, CancellationToken.None)); }, "en-tête tronqué");
            Check.Throws<EndOfStreamException>(delegate { Wait(FrameCodec.ReadAsync(new MemoryStream(new byte[] { 0, 0, 0, 9, 1, 2 }), 100, CancellationToken.None)); }, "corps tronqué");
            FrameTooLargeException big = Check.Throws<FrameTooLargeException>(delegate { Wait(FrameCodec.ReadAsync(new MemoryStream(new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }), FrameCodec.MaxRequestBytes, CancellationToken.None)); }, "trame trop grande refusée sans allocation");
            Check.Eq(2147483647L, big.Declared, "longueur annoncée");
            Check.Eq(0, Wait(FrameCodec.ReadAsync(new MemoryStream(new byte[] { 0, 0, 0, 0 }), 100, CancellationToken.None)).Length, "trame vide");
            Check.Eq(1 << 20, FrameCodec.MaxRequestBytes, "plafond requête 1 Mio");
            Check.Eq(16 << 20, FrameCodec.MaxResponseBytes, "plafond réponse 16 Mio");
        }

        private static void JsonRpc_ParseRequest()
        {
            object id;
            RpcRequest r = JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"secret.get\",\"params\":{\"name\":\"k\"},\"id\":3}"), out id);
            Check.True(r.Method == "secret.get" && r.Params.String("name") == "k" && (long)r.Id == 3L && (long)id == 3L, "requête complète, id entier");
            r = JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"daemon.status\",\"id\":\"abc\"}"), out id);
            Check.True((string)r.Id == "abc" && r.Params == null, "id chaîne, sans params");
            r = JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"daemon.status\",\"id\":null}"), out id);
            Check.True(r.Id == null, "id null accepté");

            RpcException e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{nope"), out id); }, "JSON illisible");
            Check.Eq(RpcErrors.ParseError, e.Code, "-32700");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(new byte[] { 0x7B, 0xC3, 0x28, 0x7D }, out id); }, "UTF-8 invalide");
            Check.Eq(RpcErrors.ParseError, e.Code, "UTF-8 invalide → -32700");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("[1,2]"), out id); }, "racine tableau");
            Check.Eq(RpcErrors.InvalidRequest, e.Code, "-32600 pour une racine non objet");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"x\"}"), out id); }, "id manquant");
            Check.Eq(RpcErrors.InvalidRequest, e.Code, "id manquant → -32600");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"1.0\",\"method\":\"x\",\"id\":9}"), out id); }, "mauvaise version");
            Check.True(e.Code == RpcErrors.InvalidRequest && (long)id == 9L, "-32600 et id récupéré pour la réponse");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"id\":1}"), out id); }, "method manquante");
            Check.Eq(RpcErrors.InvalidRequest, e.Code, "method manquante → -32600");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseRequest(Bytes("{\"jsonrpc\":\"2.0\",\"method\":\"x\",\"params\":[1],\"id\":1}"), out id); }, "params tableau");
            Check.Eq(RpcErrors.InvalidParams, e.Code, "params non objet → -32602");
        }

        private static void JsonRpc_Envelopes()
        {
            OrderedDictionary result = new OrderedDictionary();
            result["a"] = 1L;
            Check.Eq("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"a\":1}}", Encoding.UTF8.GetString(JsonRpc.Success(1L, result)), "succès");
            OrderedDictionary data = new OrderedDictionary();
            data["retry_after_s"] = 4L;
            Check.Eq("{\"jsonrpc\":\"2.0\",\"id\":\"x\",\"error\":{\"code\":-32023,\"message\":\"attendre\",\"data\":{\"retry_after_s\":4}}}",
                Encoding.UTF8.GetString(JsonRpc.Failure("x", new RpcException(RpcErrors.RateLimited, "attendre", data))), "échec avec data");
            Check.Eq("{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}",
                Encoding.UTF8.GetString(JsonRpc.Failure(null, new RpcException(RpcErrors.ParseError, "Parse error"))), "échec sans data, id null");

            OrderedDictionary p = new OrderedDictionary();
            p["name"] = "k";
            string req = Encoding.UTF8.GetString(JsonRpc.Request(5, "secret.get", p));
            Check.Eq("{\"jsonrpc\":\"2.0\",\"method\":\"secret.get\",\"params\":{\"name\":\"k\"},\"id\":5}", req, "requête client");
            Check.Eq("{\"jsonrpc\":\"2.0\",\"method\":\"daemon.status\",\"id\":6}", Encoding.UTF8.GetString(JsonRpc.Request(6, "daemon.status", null)), "requête sans params");

            object got = JsonRpc.ParseResponse(JsonRpc.Success(5L, result), 5);
            Check.Eq(1L, (long)((IDictionary<string, object>)got)["a"], "ParseResponse rend result");
            RpcException e = Check.Throws<RpcException>(delegate { JsonRpc.ParseResponse(JsonRpc.Failure(5L, new RpcException(RpcErrors.RateLimited, "attendre", data)), 5); }, "erreur serveur");
            Check.True(e.Code == RpcErrors.RateLimited && e.Message == "attendre" && e.ErrorData != null, "code, message et data du serveur");
            e = Check.Throws<RpcException>(delegate { JsonRpc.ParseResponse(JsonRpc.Failure(null, new RpcException(RpcErrors.ParseError, "Parse error")), 5); }, "erreur avec id null");
            Check.Eq(RpcErrors.ParseError, e.Code, "l'erreur prime sur l'id");
            Check.Throws<RpcException>(delegate { JsonRpc.ParseResponse(JsonRpc.Success(4L, result), 5); }, "réponse pour un autre id");
            Check.Throws<RpcException>(delegate { JsonRpc.ParseResponse(Bytes("{\"jsonrpc\":\"2.0\",\"id\":5}"), 5); }, "ni result ni error");
        }
    }
}
