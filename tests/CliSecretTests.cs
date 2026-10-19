using System;
using System.Collections.Generic;
using System.Text;
using IrisCli;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- iris secret / iris rule (SPECS §4.3, spec phase 5 §4, §5) ------------------------

        private static string Utf8(byte[] b) { return Encoding.UTF8.GetString(b); }

        /// <summary>Review Focus 3 : un seul saut de ligne final retiré, vide refusé, binaire conservé, tampon d'entrée effacé.</summary>
        private static void SecretValue_Normalize()
        {
            Check.Eq("abc", Utf8(SecretValue.Normalize(Encoding.UTF8.GetBytes("abc\r\n"))), "\\r\\n de PowerShell retiré");
            Check.Eq("abc", Utf8(SecretValue.Normalize(Encoding.UTF8.GetBytes("abc\n"))), "\\n retiré");
            Check.Eq("abc\n", Utf8(SecretValue.Normalize(Encoding.UTF8.GetBytes("abc\n\n"))), "un seul saut de ligne retiré");
            Check.Eq("abc\r", Utf8(SecretValue.Normalize(Encoding.UTF8.GetBytes("abc\r"))), "\\r seul conservé");
            Check.Eq("é ü", Utf8(SecretValue.Normalize(Encoding.UTF8.GetBytes("é ü\n"))), "non ASCII");
            foreach (string blank in new[] { "", "\n", "\r\n", " \t", "  \r\n" })
            {
                CliException ex = Check.Throws<CliException>(delegate { SecretValue.Normalize(Encoding.UTF8.GetBytes(blank)); }, "vide ou blanc refusé : [" + blank.Replace("\r", "\\r").Replace("\n", "\\n") + "]");
                Check.Eq(1, ex.Code, "code 1");
            }
            byte[] binary = { 0xFF, 0x20, 0x0A };
            byte[] kept = SecretValue.Normalize(binary);
            Check.True(kept.Length == 2 && kept[0] == 0xFF && kept[1] == 0x20, "valeur binaire non UTF-8 conservée");
            Check.True(binary[0] == 0 && binary[1] == 0 && binary[2] == 0, "tampon d'entrée effacé");
            Check.Eq("ligne", CliInput.ReadLine(Stdin("ligne\r\nsuite")), "ReadLine sans \\r\\n");
            Check.True(CliInput.ReadLine(Stdin("")) == null, "ReadLine en fin de flux : null");
        }

        private static void Cli_SecretLifecycle()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                List<string> outputs = new List<string>();
                CliContext c = CliCtx(d.Data);
                c.In = Stdin("sk-test-123\r\n");
                CliRun r = RunIris(c, "secret", "add", "demo", "--allowed-hosts", "api.example.com", "--value-from-stdin");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Out.Trim() == "secret ajouté : demo (hôtes : api.example.com)", "add depuis stdin : " + r.All);
                r = RunIris(d.Data, "secret", "list");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Out.Contains("NOM") && r.Out.Contains("demo") && r.Out.Contains("actif") && r.Out.Contains("api.example.com"), "list : " + r.Out);
                r = RunIris(d.Data, "secret", "list", "--json");
                outputs.Add(r.All);
                IList<object> items = (IList<object>)Json.Parse(r.Out);
                JsonObject first = new JsonObject((IDictionary<string, object>)items[0]);
                Check.True(items.Count == 1 && first.String("name") == "demo" && !first.Has("value"), "list --json sans valeur : " + r.Out);
                r = RunIris(d.Data, "secret", "show", "demo");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Out.Contains("nom : demo") && r.Out.Contains("quarantaine : non"), "show : " + r.Out);
                r = RunIris(d.Data, "secret", "edit", "demo", "--allowed-hosts", "a.example.com, b.example.com");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Out.Contains("hôtes : a.example.com,b.example.com"), "edit : " + r.All);
                Check.Eq(64, RunIris(d.Data, "secret", "edit", "demo").Code, "edit sans --allowed-hosts → 64");
                r = RunIris(d.Data, "secret", "quarantine", "demo");
                Check.True(r.Code == 0 && RunIris(d.Data, "secret", "list").Out.Contains("QUARANTAINE"), "quarantine");
                r = RunIris(d.Data, "secret", "unquarantine", "demo");
                Check.True(r.Code == 0 && RunIris(d.Data, "secret", "list").Out.Contains("actif"), "unquarantine");
                c = CliCtx(d.Data);
                c.In = Stdin("sk-new-456\n");
                r = RunIris(c, "secret", "rotate", "demo");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Out.Trim() == "secret renouvelé : demo", "rotate depuis stdin : " + r.All);
                c = CliCtx(d.Data);
                c.IsStdinRedirected = false;
                ScriptedConsoleInput typed = new ScriptedConsoleInput("sk-typed-789");
                c.Passwords = typed;
                r = RunIris(c, "secret", "rotate", "demo");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && typed.Prompts.Count == 1 && typed.Prompts[0] == "Nouvelle valeur pour demo : ", "rotate à la console, sans écho");

                c = CliCtx(d.Data);
                c.In = Stdin("x");
                r = RunIris(c, "secret", "add", "v", "--allowed-hosts", "api.example.com", "--value", "sk-inline-000");
                outputs.Add(r.All);
                Check.True(r.Code == 0 && r.Err.Contains("avertissement") && r.Err.Contains("historique"), "--value : avertissement : " + r.All);
                Check.Eq(64, RunIris(d.Data, "secret", "add", "w", "--allowed-hosts", "api.example.com").Code, "sans source de valeur → 64");
                Check.Eq(64, RunIris(d.Data, "secret", "add", "w", "--value", "a", "--value-from-stdin").Code, "deux sources → 64");
                c = CliCtx(d.Data);
                c.In = Stdin("\r\n");
                r = RunIris(c, "secret", "add", "w", "--allowed-hosts", "api.example.com", "--value-from-stdin");
                Check.True(r.Code == 1 && r.Err.Contains("vide"), "valeur vide → 1 : " + r.All);
                c = CliCtx(d.Data);
                c.In = Stdin("y");
                r = RunIris(c, "secret", "add", "demo", "--allowed-hosts", "api.example.com", "--value-from-stdin");
                Check.True(r.Code == 1 && r.Err.StartsWith("erreur : "), "doublon → 1 : " + r.All);
                c = CliCtx(d.Data);
                c.In = Stdin("y");
                Check.Eq(1, RunIris(c, "secret", "add", "z", "--value-from-stdin").Code, "sans --allowed-hosts : refus du daemon → 1");

                c = CliCtx(d.Data);
                c.In = Stdin("pas-le-bon\n");
                r = RunIris(c, "secret", "rm", "demo");
                Check.True(r.Code == 64 && r.Err.Contains("confirmation"), "rm : mauvaise confirmation → 64 : " + r.All);
                Check.True(RunIris(d.Data, "secret", "list").Out.Contains("demo"), "secret toujours là");
                c = CliCtx(d.Data);
                c.In = Stdin("demo\r\n");
                r = RunIris(c, "secret", "rm", "demo");
                Check.True(r.Code == 0 && r.Out.Trim() == "secret supprimé : demo", "rm confirmé : " + r.All);
                r = RunIris(d.Data, "secret", "rm", "demo", "--yes");
                Check.True(r.Code == 1 && r.Err.StartsWith("erreur : "), "rm d'un absent → 1 : " + r.All);

                foreach (string o in outputs)
                    foreach (string value in new[] { "sk-test-123", "sk-new-456", "sk-typed-789", "sk-inline-000" })
                        Check.True(!o.Contains(value), "aucune sortie ne contient " + value);
            }
        }

        private static void Cli_Rules()
        {
            using (CliDaemon d = StartCliDaemon())
            {
                CliRun r = RunIris(d.Data, "rule", "add", "api.example.com");
                Check.True(r.Code == 0 && r.Out.Trim() == "règle ajoutée : api.example.com (user)", "rule add : " + r.All);
                Check.Eq(0, RunIris(d.Data, "rule", "add", "api.example.com").Code, "rule add idempotent");
                r = RunIris(d.Data, "rule", "list");
                Check.True(r.Code == 0 && r.Out.Contains("HÔTE") && r.Out.Contains("api.anthropic.com") && r.Out.Contains("default") && r.Out.Contains("api.example.com") && r.Out.Contains("user"), "rule list : " + r.Out);
                r = RunIris(d.Data, "rule", "list", "--json");
                Check.Eq(2, ((IList<object>)Json.Parse(r.Out)).Count, "rule list --json");
                r = RunIris(d.Data, "rule", "rm", "api.anthropic.com");
                Check.True(r.Code == 64 && r.Err.Contains("non supprimable"), "hôte par défaut → 64 : " + r.All);
                r = RunIris(d.Data, "rule", "rm", "absent.example.com");
                Check.True(r.Code == 64 && r.Err.Contains("introuvable"), "hôte absent → 64 : " + r.All);
                r = RunIris(d.Data, "rule", "rm", "api.example.com");
                Check.True(r.Code == 0 && r.Out.Trim() == "règle supprimée : api.example.com", "rule rm : " + r.All);
                Check.Eq(1, RunIris(d.Data, "rule", "add", "pas un hôte").Code, "hôte invalide → 1");
            }
        }
    }
}
