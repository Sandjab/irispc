using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Json ------------------------------------------------------

        private static void Json_RoundTripOrdered()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["version"] = 1L;
            o["name"] = "irisé";
            o["enabled"] = true;
            o["nothing"] = null;
            o["ratio"] = 0.5;
            o["hosts"] = new List<object> { "a.example", "b.example" };
            OrderedDictionary inner = new OrderedDictionary();
            inner["max_count"] = 10L;
            o["backups"] = inner;
            string text = Json.Emit(o);
            Check.Eq("{\n  \"version\": 1,\n  \"name\": \"irisé\",\n  \"enabled\": true,\n  \"nothing\": null,\n  \"ratio\": 0.5,\n  \"hosts\": [\n    \"a.example\",\n    \"b.example\"\n  ],\n  \"backups\": {\n    \"max_count\": 10\n  }\n}", text, "indentation 2, ordre d'insertion, LF");
            JsonObject back = Json.ParseObject(text);
            Check.Eq(1L, back.Int("version"), "entier relu en long");
            Check.Eq("irisé", back.String("name"), "chaîne non ASCII intacte");
            Check.True(back.Bool("enabled", false), "booléen");
            Check.True(back.Has("nothing") && back.Raw("nothing") == null, "null conservé");
            Check.Eq(0.5, (double)back.Raw("ratio"), "double");
            Check.Eq("a.example,b.example", string.Join(",", back.StringArray("hosts")), "tableau de chaînes");
            Check.Eq(10L, back.Object("backups").Int("max_count"), "objet imbriqué");
            Check.Eq("version,name,enabled,nothing,ratio,hosts,backups", string.Join(",", back.Keys), "ordre des clés conservé en lecture");
        }

        private static void Json_CompactAndEscapes()
        {
            OrderedDictionary o = new OrderedDictionary();
            o["s"] = "a\"b\\c\n\t\u0001é";
            o["empty"] = new OrderedDictionary();
            o["list"] = new object[0];
            Check.Eq("{\"s\":\"a\\\"b\\\\c\\n\\t\\u0001é\",\"empty\":{},\"list\":[]}", Json.EmitCompact(o), "échappements, objets et tableaux vides");
            Check.Eq("a\"b\\c\n\t\u0001é", Json.ParseObject(Json.EmitCompact(o)).String("s"), "aller-retour des échappements");
        }

        private static void Json_Dates()
        {
            DateTime d = new DateTime(2026, 10, 17, 7, 49, 47, DateTimeKind.Utc);
            Check.Eq("2026-10-17T07:49:47Z", Json.FormatDate(d), "format ISO UTC sans fraction");
            Check.Eq("2026-10-17T07:49:47Z", Json.FormatDate(d.ToLocalTime()), "une date locale est convertie en UTC");
            Check.Eq(d, Json.ParseDate("2026-10-17T07:49:47Z"), "lecture sans fraction");
            Check.Eq(d.AddMilliseconds(123), Json.ParseDate("2026-10-17T07:49:47.123Z"), "lecture avec fraction");
            Check.Eq(d, Json.ParseDate("2026-10-17T09:49:47+02:00"), "décalage horaire ramené en UTC");
            Check.Eq(DateTimeKind.Utc, Json.ParseDate("2026-10-17T07:49:47Z").Kind, "Kind UTC");
            Check.Throws<JsonException>(delegate { Json.ParseDate("hier"); }, "date invalide");
            OrderedDictionary o = new OrderedDictionary();
            o["at"] = d;
            Check.Eq("{\"at\":\"2026-10-17T07:49:47Z\"}", Json.EmitCompact(o), "DateTime émis en ISO");
        }

        private static void Json_Errors()
        {
            Check.Throws<JsonException>(delegate { Json.Parse("{"); }, "JSON tronqué");
            Check.Throws<JsonException>(delegate { Json.Parse(""); }, "vide");
            Check.Throws<JsonException>(delegate { Json.ParseObject("[1]"); }, "ParseObject sur un tableau");
            JsonObject o = Json.ParseObject("{\"n\":\"x\",\"i\":3,\"l\":[1]}");
            JsonException ex = Check.Throws<JsonException>(delegate { o.String("absent"); }, "champ requis absent");
            Check.True(ex.Message.Contains("absent"), "le message cite la clé");
            Check.Throws<JsonException>(delegate { o.Int("n"); }, "type inattendu");
            Check.Throws<JsonException>(delegate { o.StringArray("i"); }, "tableau attendu");
            Check.Eq(null, o.OptionalString("absent"), "optionnel absent → null");
            Check.Eq(7L, o.OptionalInt("absent") ?? 7L, "optionnel entier absent");
            Check.Throws<JsonException>(delegate { Json.Emit(new object()); }, "type non sérialisable");
            Check.Throws<JsonException>(delegate { Json.Emit(double.NaN); }, "NaN refusé");
        }

        private static void Json_Numbers()
        {
            object parsed = Json.Parse("{\"a\":1,\"b\":12345678901,\"c\":1.25,\"d\":-3,\"e\":1e3}");
            JsonObject o = new JsonObject((IDictionary<string, object>)parsed);
            Check.Eq(1L, o.Int("a"), "petit entier");
            Check.Eq(12345678901L, o.Int("b"), "grand entier");
            Check.Eq(1.25, (double)o.Raw("c"), "décimal → double");
            Check.Eq(-3L, o.Int("d"), "négatif");
            Check.Eq(1000.0, Convert.ToDouble(o.Raw("e")), "notation exponentielle (long ou double selon le parseur, valeur 1000)");
            Check.Eq("[1,12345678901,1.25,-3]", Json.EmitCompact(new object[] { 1, 12345678901L, 1.25, -3 }), "émission des nombres en invariant");
        }
    }
}
