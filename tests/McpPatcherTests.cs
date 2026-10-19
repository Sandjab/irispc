using System;
using System.Collections.Generic;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Patcheur MCP (SPECS §16.1, spec phase 5 §6.1) ----------------------------------

        private const string McpBroker = "127.0.0.1:8080";
        private const string McpCa = "D:\\Dev\\irispc\\build\\Iris\\data\\ca.pem";

        private static McpPatchResult McpPatch(string json)
        {
            return McpPatcher.Patch(OrderedJsonParser.Parse(json, true).Root, McpBroker, McpCa);
        }

        private static IList<string> EnvKeys(OrderedJsonValue server)
        {
            List<string> keys = new List<string>();
            foreach (KeyValuePair<string, OrderedJsonValue> p in server.Get("env").Pairs) keys.Add(p.Key);
            return keys;
        }

        private static void McpPatcher_AddsSixVarsInOrder()
        {
            string json = "{\"mcpServers\":{\"foo\":{\"command\":\"node\",\"args\":[]}}}";
            OrderedJsonValue input = OrderedJsonParser.Parse(json, false).Root;
            string before = OrderedJsonWriter.Serialize(input);
            McpPatchResult r = McpPatcher.Patch(input, McpBroker, McpCa);
            Check.Eq(before, OrderedJsonWriter.Serialize(input), "l'entrée n'est pas modifiée");
            OrderedJsonValue foo = r.Root.Get("mcpServers").Get("foo");
            Check.Eq("command,args,env", string.Join(",", Keys(foo)), "env ajouté en fin d'entrée");
            Check.Eq("CURL_CA_BUNDLE,HTTPS_PROXY,HTTP_PROXY,NODE_EXTRA_CA_CERTS,REQUESTS_CA_BUNDLE,SSL_CERT_FILE", string.Join(",", EnvKeys(foo)), "six clés en ordre ordinal");
            Check.Eq("http://" + McpBroker, foo.Get("env").Get("HTTPS_PROXY").Text, "HTTPS_PROXY");
            Check.Eq("http://" + McpBroker, foo.Get("env").Get("HTTP_PROXY").Text, "HTTP_PROXY");
            Check.Eq(McpCa, foo.Get("env").Get("NODE_EXTRA_CA_CERTS").Text, "chemin Windows du CA");
            Check.True(r.Summary.Patched == 1 && r.Summary.AlreadyCompliant == 0 && r.Summary.Skipped == 0, "résumé");
            Check.Eq(6, r.Additions.Count, "six ajouts");
            Check.Eq("mcpServers.foo.env.CURL_CA_BUNDLE = " + OrderedJsonWriter.Quote(McpCa), r.Additions[0], "ligne de diff");
            string written = OrderedJsonWriter.Serialize(r.Root);
            Check.True(written.Contains("\"D:\\\\Dev\\\\irispc"), "antislashs échappés à l'écriture");
            Check.Eq(McpCa, OrderedJsonParser.Parse(written, false).Root.Get("mcpServers").Get("foo").Get("env").Get("SSL_CERT_FILE").Text, "chemin relu à l'identique");
        }

        private static IList<string> Keys(OrderedJsonValue obj)
        {
            List<string> keys = new List<string>();
            foreach (KeyValuePair<string, OrderedJsonValue> p in obj.Pairs) keys.Add(p.Key);
            return keys;
        }

        private static void McpPatcher_PreservesUserValues()
        {
            McpPatchResult r = McpPatch("{\"mcpServers\":{\"foo\":{\"command\":\"node\",\"env\":{\"HTTPS_PROXY\":\"http://existing.example:9999\",\"API_KEY\":\"{{kc:github_token}}\"}}}}");
            OrderedJsonValue env = r.Root.Get("mcpServers").Get("foo").Get("env");
            Check.Eq("http://existing.example:9999", env.Get("HTTPS_PROXY").Text, "valeur utilisateur conservée (règle 4)");
            Check.Eq("{{kc:github_token}}", env.Get("API_KEY").Text, "placeholder intact (règle 5)");
            Check.Eq("http://" + McpBroker, env.Get("HTTP_PROXY").Text, "SPECS prime sur le Swift : HTTP_PROXY ajouté malgré un HTTPS_PROXY utilisateur");
            Check.Eq("HTTPS_PROXY", env.Pairs[0].Key, "clés existantes en tête, dans leur ordre");
            Check.Eq(McpCa, env.Get("CURL_CA_BUNDLE").Text, "clés CA ajoutées");
            Check.Eq(1, r.Summary.Patched, "entrée patchée");
            Check.Eq(5, r.Additions.Count, "cinq ajouts (HTTPS_PROXY existait)");
        }

        private static void McpPatcher_HttpSseRules()
        {
            McpPatchResult r = McpPatch("{\"mcpServers\":{\"h\":{\"type\":\"http\",\"url\":\"https://x\"},\"s\":{\"type\":\"sse\",\"url\":\"https://y\"},\"e\":{\"type\":\"http\",\"url\":\"https://z\",\"env\":{}}}}");
            Check.True(r.Summary.Skipped == 2 && r.Summary.Patched == 1, "http/sse sans env ignorés, http avec env patché");
            Check.Eq("h,s", string.Join(",", r.SkippedServers), "serveurs ignorés nommés");
            Check.True(r.Root.Get("mcpServers").Get("h").Get("env") == null, "aucun env créé pour http (règle 3)");
            Check.Eq(6, r.Root.Get("mcpServers").Get("e").Get("env").Pairs.Count, "env existant d'un serveur http complété");
        }

        private static void McpPatcher_IdempotentAndLocations()
        {
            McpPatchResult first = McpPatch("{\"mcpServers\":{\"a\":{\"command\":\"x\"},\"b\":{\"command\":\"y\"}}}");
            McpPatchResult second = McpPatcher.Patch(first.Root, McpBroker, McpCa);
            Check.Eq(OrderedJsonWriter.Serialize(first.Root), OrderedJsonWriter.Serialize(second.Root), "second passage sans diff");
            Check.True(second.Summary.AlreadyCompliant == 2 && second.Summary.Patched == 0 && second.Additions.Count == 0, "second passage : déjà conformes");

            McpPatchResult nested = McpPatch("{\"projects\":1,\"cfg\":{\"mcpServers\":{\"n\":{\"command\":\"x\"}}}}");
            Check.True(nested.Summary.Patched == 1 && nested.Additions[0].StartsWith("cfg.mcpServers.n.env."), "mcpServers imbriqué d'un niveau : " + nested.Additions[0]);
            McpPatchResult both = McpPatch("{\"cfg\":{\"mcpServers\":{\"n\":{}}},\"mcpServers\":{\"r\":{}}}");
            Check.True(both.Root.Get("mcpServers").Get("r").Get("env") != null && both.Root.Get("cfg").Get("mcpServers").Get("n").Get("env") == null, "la racine prime sur l'imbriqué");

            string none = "{\"other\":{\"x\":1}}";
            McpPatchResult noop = McpPatch(none);
            Check.True(noop.Summary.Patched == 0 && noop.Summary.AlreadyCompliant == 0 && noop.Summary.Skipped == 0, "sans mcpServers : rien");
            Check.Eq(OrderedJsonWriter.Serialize(OrderedJsonParser.Parse(none, false).Root), OrderedJsonWriter.Serialize(noop.Root), "sans mcpServers : document intact");
            Check.Eq(0, McpPatch("{\"mcpServers\":[1,2]}").Summary.Patched, "mcpServers non objet : rien");
            McpPatchResult odd = McpPatch("{\"mcpServers\":{\"s\":\"texte\",\"n\":{\"env\":null}}}");
            Check.True(odd.Summary.Patched == 1 && odd.Summary.AlreadyCompliant == 0, "entrée non objet ignorée et non comptée");
            Check.Eq(6, odd.Root.Get("mcpServers").Get("n").Get("env").Pairs.Count, "env non objet remplacé par les six variables (comme IRIS)");
            Check.Eq(1, McpPatch("{\"mcpServers\":{\"j\":{\"command\":\"x\",},},}").Summary.Patched, "document JSONC à virgules finales");
        }

        private static void WrappedPaths_Registry()
        {
            string dir = TestDir.Create();
            try
            {
                WrappedPathsRegistry reg = WrappedPathsRegistry.ForDataDir(Path.Combine(dir, "data"));
                Check.Eq(Path.Combine(dir, "data", "wrapped-paths.json"), reg.ManifestPath, "emplacement dans data");
                Check.Eq(0, reg.List().Count, "absent : liste vide");
                reg.Add("C:\\p\\a.json");
                reg.Add("C:\\P\\A.JSON");
                reg.Add("C:\\p\\b.json");
                Check.Eq("C:\\p\\a.json|C:\\p\\b.json", string.Join("|", reg.List()), "sans doublon (casse ignorée), ordre d'insertion");
                Check.True(Json.Parse(File.ReadAllText(reg.ManifestPath)) is IList<object>, "manifeste : tableau JSON");
                reg.Remove("c:\\P\\a.json");
                Check.Eq("C:\\p\\b.json", string.Join("|", reg.List()), "retrait insensible à la casse");
                reg.Remove("C:\\absent.json");
                Check.Eq(1, reg.List().Count, "retrait d'un absent : sans effet");
                foreach (string corrupt in new[] { "{", "{\"a\":1}", "[1]", "" })
                {
                    File.WriteAllText(reg.ManifestPath, corrupt);
                    Check.Throws<WrappedPathsCorruptException>(delegate { reg.List(); }, "manifeste corrompu : " + corrupt);
                    Check.Throws<WrappedPathsCorruptException>(delegate { reg.Add("C:\\p\\c.json"); }, "Add sur corrompu : refus");
                    Check.Eq(corrupt, File.ReadAllText(reg.ManifestPath), "manifeste corrompu jamais réécrit");
                }
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
