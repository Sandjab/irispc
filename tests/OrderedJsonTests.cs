using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- JSON ordonné et JSONC (spec phase 5 §6.1, port de OrderedJSONDocument) ----------

        private static string RoundTrip(string text) { return OrderedJsonWriter.Serialize(OrderedJsonParser.Parse(text, false).Root); }

        private static void OrderedJson_RoundTripAndOrder()
        {
            Check.Eq("true\n", RoundTrip("true"), "booléen");
            Check.Eq("null\n", RoundTrip("null"), "null");
            Check.Eq("\"x\"\n", RoundTrip("\"x\""), "chaîne");
            Check.Eq("-7\n", RoundTrip("-7"), "entier négatif");
            Check.Eq("{}\n", RoundTrip("{}"), "objet vide");
            Check.Eq("[]\n", RoundTrip("[ ]"), "tableau vide");
            string ordered = "{\"z\":1,\"a\":2,\"m\":{\"y\":true,\"b\":null}}";
            Check.Eq("{\n  \"z\": 1,\n  \"a\": 2,\n  \"m\": {\n    \"y\": true,\n    \"b\": null\n  }\n}\n", RoundTrip(ordered), "ordre des clés conservé, 2 espaces, LF final");
            Check.Eq("[\n  {\n    \"b\": 1,\n    \"a\": 2\n  }\n]\n", RoundTrip("[{\"b\":1,\"a\":2}]"), "objet dans un tableau");
            Check.Eq("{\n  \"a\": 1\n}\n", RoundTrip(" \t\r\n {\"a\" : 1 } \n"), "espaces tolérés (y compris CR)");
            string once = RoundTrip(ordered);
            Check.Eq(once, RoundTrip(once), "sérialisation idempotente");
            OrderedJsonValue root = OrderedJsonParser.Parse(ordered, false).Root;
            Check.True(root.IsObject && root.Pairs.Count == 3 && root.Pairs[0].Key == "z", "Pairs dans l'ordre du fichier");
            Check.Eq(2L, root.Get("a").Integer, "Get");
            Check.True(root.Get("absent") == null, "Get d'une clé absente : null");
            Check.True(root.Get("m").Get("b").Kind == OrderedJsonKind.Null, "null JSON : valeur de genre Null, pas null C#");
        }

        private static void OrderedJson_StringsAndNumbers()
        {
            OrderedJsonValue s = OrderedJsonParser.Parse("\"a\\\"b\\\\c\\/d\\b\\f\\n\\r\\t\"", false).Root;
            Check.Eq("a\"b\\c/d\b\f\n\r\t", s.Text, "échappements décodés");
            Check.Eq("\"a\\\"b\\\\c/d\\b\\f\\n\\r\\t\"\n", OrderedJsonWriter.Serialize(s), "échappements réémis (slash non échappé)");
            Check.Eq("é", OrderedJsonParser.Parse("\"\\u00e9\"", false).Root.Text, "\\u00e9");
            Check.Eq("\"é\"\n", RoundTrip("\"\\u00e9\""), "non ASCII réémis tel quel");
            Check.Eq("\uD83D\uDE00", OrderedJsonParser.Parse("\"\\ud83d\\ude00\"", false).Root.Text, "paire de substitution");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("\"\\ud83d\"", false); }, "demi-paire haute isolée");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("\"\\ude00\"", false); }, "demi-paire basse isolée");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("\"\\uZZZZ\"", false); }, "\\u non hexadécimal");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("\"\\x\"", false); }, "échappement inconnu");
            Check.Eq("\"\\u0001\"\n", RoundTrip("\"\\u0001\""), "caractère de contrôle réémis en \\u0001");
            Check.Eq("\"\\u0000\"\n", RoundTrip("\"\\u0000\""), "\\u0000 accepté et réémis");

            OrderedJsonValue n = OrderedJsonParser.Parse("42", false).Root;
            Check.True(n.Kind == OrderedJsonKind.Integer && n.Integer == 42, "entier gardé entier");
            Check.Eq("1.0\n", RoundTrip("1.0"), "double entier : forme fractionnaire");
            Check.Eq("1.5\n", RoundTrip("1.5"), "double");
            Check.Eq("1000.0\n", RoundTrip("1e3"), "exposant : double");
            Check.Eq("9223372036854775807\n", RoundTrip("9223372036854775807"), "Int64.MaxValue");
            Check.True(OrderedJsonParser.Parse("9223372036854775808", false).Root.Kind == OrderedJsonKind.Double, "au-delà d'Int64 : double");
            Check.Eq("0\n", RoundTrip("-0"), "-0 : entier 0");
            foreach (string bad in new[] { "01", "-", "1.", "1e", ".5", "+1", "1e999", "-x" })
                Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse(bad, false); }, "nombre refusé : " + bad);
        }

        private static void OrderedJson_StrictRejections()
        {
            string[] bad = { "", "   ", "{\"a\":1,}", "[1,]", "// c\n{}", "{/* c */}", "{\"a\":1} x", "tru", "{\"a\" 1}", "{a:1}", "\"abc", "\"a\u0001b\"", "[1 2]" };
            foreach (string text in bad)
                Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse(text, false); }, "strict refuse : " + text.Replace("\n", "\\n"));
            OrderedJsonException dup = Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("{\n  \"a\": 1,\n  \"a\": 2\n}", false); }, "clé en double");
            Check.True(dup.Message.Contains("\"a\"") || dup.Message.Contains(" a"), "le message cite la clé : " + dup.Message);
            Check.True(dup.Line == 3 && dup.Column == 3, "position de la clé en double : L3:3 (" + dup.Line + ":" + dup.Column + ")");
            Check.True(dup.Message.StartsWith("L3:3 : "), "message préfixé par la position : " + dup.Message);
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("{\"a\":1,\"a\":2}", true); }, "clé en double refusée aussi en JSONC");
            Check.Eq(0, OrderedJsonParser.Parse("{\"a\":1}", false).Comments.Count, "strict : aucun commentaire relevé");
        }

        private static void OrderedJson_Jsonc()
        {
            OrderedJsonDocument d = OrderedJsonParser.Parse("{\n  // c\n  \"a\": 1\n}", true);
            Check.True(d.Comments.Count == 1 && d.Comments[0].Line == 2 && d.Comments[0].Column == 3 && d.Comments[0].Kind == CommentKind.Line, "commentaire de ligne en L2:3");
            Check.Eq(1L, d.Root.Get("a").Integer, "valeur après le commentaire");
            Check.Eq(1L, OrderedJsonParser.Parse("{\"a\" // x\n : 1}", true).Root.Get("a").Integer, "commentaire entre clé et deux-points");
            d = OrderedJsonParser.Parse("{ /* x */ \"a\": /* y */ 1 }", true);
            Check.True(d.Comments.Count == 2 && d.Comments[0].Column == 3 && d.Comments[1].Column == 16 && d.Comments[1].Kind == CommentKind.Block, "deux blocs : colonnes 3 et 16");
            d = OrderedJsonParser.Parse("/* a\nb */ // c\n{}", true);
            Check.True(d.Comments.Count == 2 && d.Comments[0].Line == 1 && d.Comments[0].Column == 1 && d.Comments[1].Line == 2 && d.Comments[1].Column == 6, "positions après un bloc multiligne");
            OrderedJsonException open = Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("{ /* x", true); }, "bloc non fermé");
            Check.True(open.Message.Contains("non fermé"), "message : " + open.Message);
            Check.Eq(2, OrderedJsonParser.Parse("[1,2,]", true).Root.Items.Count, "virgule finale de tableau");
            Check.Eq(1, OrderedJsonParser.Parse("{\"a\":1,}", true).Root.Pairs.Count, "virgule finale d'objet");
            d = OrderedJsonParser.Parse("{\"a\":1, // c\n}", true);
            Check.True(d.Root.Pairs.Count == 1 && d.Comments.Count == 1, "virgule finale suivie d'un commentaire");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("[1,]", false); }, "le mode strict refuse toujours la virgule finale");
            Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse("{} /", true); }, "barre oblique isolée");
        }

        private static void OrderedJson_SetAndClone()
        {
            OrderedJsonValue root = OrderedJsonParser.Parse("{\"a\":1,\"b\":2}", false).Root;
            root.Set("a", OrderedJsonValue.FromString("x"));
            root.Set("c", OrderedJsonValue.FromBool(false));
            Check.Eq("{\n  \"a\": \"x\",\n  \"b\": 2,\n  \"c\": false\n}\n", OrderedJsonWriter.Serialize(root), "Set remplace à sa place, ajoute en fin");
            OrderedJsonValue copy = root.Clone();
            copy.Set("b", OrderedJsonValue.Null());
            copy.Set("d", OrderedJsonValue.NewArray());
            Check.Eq(2L, root.Get("b").Integer, "Clone : l'original ne bouge pas");
            Check.True(root.Get("d") == null, "Clone : pas d'ajout dans l'original");
            Check.Throws<InvalidOperationException>(delegate { OrderedJsonValue.FromInteger(1).Set("k", OrderedJsonValue.Null()); }, "Set sur un scalaire");
            Check.Eq("\"D:\\\\a\\\"b\"", OrderedJsonWriter.Quote("D:\\a\"b"), "Quote");
        }

        private static void OrderedJson_DepthLimit()
        {
            string deep = new string('[', 600) + new string(']', 600);
            OrderedJsonException ex = Check.Throws<OrderedJsonException>(delegate { OrderedJsonParser.Parse(deep, false); }, "imbrication de 600 niveaux refusée sans débordement de pile");
            Check.True(ex.Message.Contains("imbrication"), "message : " + ex.Message);
            string ok = new string('[', 100) + new string(']', 100);
            Check.Eq(1, OrderedJsonParser.Parse(ok, false).Root.Items.Count, "100 niveaux acceptés");
        }

        /// <summary>Review Focus 1 : un .claude.json de plusieurs Mo, non ASCII et emoji non échappés, en temps linéaire.</summary>
        private static void OrderedJson_LargeUnicodeRoundTrip()
        {
            StringBuilder sb = new StringBuilder("{\n  \"mcpServers\": {");
            for (int i = 0; i < 24000; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("\n    \"srv-é-\uD83D\uDE00-" + i + "\": {\"command\": \"node\", \"args\": [\"日本語 ✓ " + i + "\", \"\\u00e9\"], \"n\": " + i + "}");
            }
            sb.Append("\n  }\n}\n");
            string text = sb.ToString();
            Check.True(text.Length > 2000000, "document de plus de 2 Mo (" + text.Length + ")");
            Stopwatch w = Stopwatch.StartNew();
            OrderedJsonDocument d = OrderedJsonParser.Parse(text, true);
            string once = OrderedJsonWriter.Serialize(d.Root);
            string twice = OrderedJsonWriter.Serialize(OrderedJsonParser.Parse(once, false).Root);
            w.Stop();
            Check.Eq(once, twice, "réécriture stable");
            Check.Eq(24000, d.Root.Get("mcpServers").Pairs.Count, "24 000 serveurs");
            Check.True(once.Contains("\"srv-é-\uD83D\uDE00-23999\"") && once.Contains("日本語 ✓ 23999"), "non ASCII et emoji conservés");
            Check.True(w.ElapsedMilliseconds < 20000, "temps linéaire (" + w.ElapsedMilliseconds + " ms)");
        }
    }
}
