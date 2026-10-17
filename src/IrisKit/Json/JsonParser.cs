using System;
using System.Collections.Generic;
using System.Globalization;
using System.Web.Script.Serialization;

namespace IrisKit
{
    /// <summary>JSON invalide, type inattendu ou champ manquant. Message en français.</summary>
    public sealed class JsonException : Exception
    {
        public JsonException(string message) : base(message) { }
        public JsonException(string message, Exception inner) : base(message, inner) { }
    }

    /// <summary>
    /// Façade JSON (spec §5.2) : lecture via JavaScriptSerializer, écriture maison ordonnée (JsonWriter.cs),
    /// dates ISO 8601 UTC. Les modèles ont des ToJson()/FromJson() explicites, jamais de réflexion.
    /// </summary>
    public static partial class Json
    {
        private const string DateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'";

        /// <summary>Objets → IDictionary&lt;string, object&gt; (ordre d'insertion), tableaux → IList&lt;object&gt;, nombres → long ou double.</summary>
        public static object Parse(string text)
        {
            if (string.IsNullOrEmpty(text)) throw new JsonException("JSON vide");
            JavaScriptSerializer serializer = new JavaScriptSerializer();
            serializer.MaxJsonLength = int.MaxValue;
            serializer.RecursionLimit = 64;
            object raw;
            try
            {
                raw = serializer.DeserializeObject(text);
            }
            catch (ArgumentException ex)
            {
                throw new JsonException("JSON invalide : " + ex.Message, ex);
            }
            catch (InvalidOperationException ex)
            {
                throw new JsonException("JSON invalide : " + ex.Message, ex);
            }
            return Normalize(raw);
        }

        public static JsonObject ParseObject(string text)
        {
            IDictionary<string, object> dict = Parse(text) as IDictionary<string, object>;
            if (dict == null) throw new JsonException("objet JSON attendu à la racine");
            return new JsonObject(dict);
        }

        /// <summary>Ramène les types de JavaScriptSerializer à long / double / string / bool / null / dict / liste.</summary>
        private static object Normalize(object value)
        {
            if (value == null || value is string || value is bool) return value;
            if (value is int) return (long)(int)value;
            if (value is long) return value;
            if (value is decimal)
            {
                decimal d = (decimal)value;
                if (d == decimal.Truncate(d) && d >= long.MinValue && d <= long.MaxValue) return (long)d;
                return (double)d;
            }
            if (value is double || value is float) return Convert.ToDouble(value, CultureInfo.InvariantCulture);
            IDictionary<string, object> dict = value as IDictionary<string, object>;
            if (dict != null)
            {
                Dictionary<string, object> result = new Dictionary<string, object>();
                foreach (KeyValuePair<string, object> kv in dict) result[kv.Key] = Normalize(kv.Value);
                return result;
            }
            object[] array = value as object[];
            if (array != null)
            {
                List<object> list = new List<object>(array.Length);
                foreach (object item in array) list.Add(Normalize(item));
                return list;
            }
            throw new JsonException("valeur JSON inattendue : " + value.GetType().Name);
        }

        // ---- Dates -----------------------------------------------------

        public static string FormatDate(DateTime value)
        {
            return value.ToUniversalTime().ToString(DateFormat, CultureInfo.InvariantCulture);
        }

        /// <summary>ISO 8601 avec ou sans fraction, Z ou décalage ; résultat en Kind UTC.</summary>
        public static DateTime ParseDate(string text)
        {
            DateTime parsed;
            if (text == null || !DateTime.TryParse(text, CultureInfo.InvariantCulture,
                DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed)
                || text.IndexOf('T') < 0)
                throw new JsonException("date ISO 8601 attendue, reçu : " + (text ?? "null"));
            return DateTime.SpecifyKind(parsed, DateTimeKind.Utc);
        }
    }
}
