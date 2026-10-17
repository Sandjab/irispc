using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Lecture typée d'un objet JSON parsé. Les champs requis absents ou d'un autre type lèvent JsonException.</summary>
    public sealed class JsonObject
    {
        private readonly IDictionary<string, object> raw;

        public JsonObject(IDictionary<string, object> raw)
        {
            if (raw == null) throw new ArgumentNullException("raw");
            this.raw = raw;
        }

        public IEnumerable<string> Keys { get { return raw.Keys; } }

        public bool Has(string key) { return raw.ContainsKey(key); }

        public object Raw(string key)
        {
            object value;
            return raw.TryGetValue(key, out value) ? value : null;
        }

        public string String(string key) { return Require<string>(key, "chaîne"); }

        public string OptionalString(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            string s = value as string;
            if (s == null) throw new JsonException("champ " + key + " : chaîne attendue");
            return s;
        }

        public long Int(string key)
        {
            object value = Require<object>(key, "entier");
            if (value is long) return (long)value;
            throw new JsonException("champ " + key + " : entier attendu");
        }

        public long? OptionalInt(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            if (value is long) return (long)value;
            throw new JsonException("champ " + key + " : entier attendu");
        }

        public bool Bool(string key, bool defaultValue)
        {
            object value = Raw(key);
            if (value == null) return defaultValue;
            if (value is bool) return (bool)value;
            throw new JsonException("champ " + key + " : booléen attendu");
        }

        public JsonObject Object(string key)
        {
            return new JsonObject(Require<IDictionary<string, object>>(key, "objet"));
        }

        public JsonObject OptionalObject(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            IDictionary<string, object> dict = value as IDictionary<string, object>;
            if (dict == null) throw new JsonException("champ " + key + " : objet attendu");
            return new JsonObject(dict);
        }

        public IList<object> Array(string key) { return Require<IList<object>>(key, "tableau"); }

        public IList<object> OptionalArray(string key)
        {
            object value = Raw(key);
            if (value == null) return null;
            IList<object> list = value as IList<object>;
            if (list == null) throw new JsonException("champ " + key + " : tableau attendu");
            return list;
        }

        public IList<string> StringArray(string key)
        {
            IList<object> items = Array(key);
            List<string> result = new List<string>(items.Count);
            foreach (object item in items)
            {
                string s = item as string;
                if (s == null) throw new JsonException("champ " + key + " : tableau de chaînes attendu");
                result.Add(s);
            }
            return result;
        }

        private T Require<T>(string key, string expected) where T : class
        {
            object value;
            if (!raw.TryGetValue(key, out value) || value == null)
                throw new JsonException("champ manquant : " + key);
            T typed = value as T;
            if (typed == null) throw new JsonException("champ " + key + " : " + expected + " attendu");
            return typed;
        }
    }
}
