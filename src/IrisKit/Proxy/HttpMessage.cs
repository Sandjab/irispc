using System;
using System.Collections;
using System.Collections.Generic;

namespace IrisKit
{
    public sealed class HttpHeader
    {
        public string Name { get; private set; }
        public string Value { get; private set; }

        public HttpHeader(string name, string value)
        {
            if (name == null) throw new ArgumentNullException("name");
            Name = name;
            Value = value ?? "";
        }
    }

    /// <summary>En-têtes dans l'ordre du fil, noms insensibles à la casse (RFC 7230 §3.2), occurrences multiples conservées.</summary>
    public sealed class HttpHeaders : IEnumerable<HttpHeader>
    {
        private readonly List<HttpHeader> list = new List<HttpHeader>();

        public int Count { get { return list.Count; } }

        public void Add(string name, string value) { list.Add(new HttpHeader(name, value)); }

        public bool Contains(string name) { return IndexOf(name) >= 0; }

        /// <summary>Première valeur, ou null si absent.</summary>
        public string First(string name)
        {
            int i = IndexOf(name);
            return i < 0 ? null : list[i].Value;
        }

        public IList<string> All(string name)
        {
            List<string> values = new List<string>();
            foreach (HttpHeader h in list) if (Is(h, name)) values.Add(h.Value);
            return values;
        }

        /// <summary>Retire toutes les occurrences ; rend leur nombre.</summary>
        public int Remove(string name)
        {
            return list.RemoveAll(delegate(HttpHeader h) { return Is(h, name); });
        }

        /// <summary>Remplace la première occurrence (en gardant la casse de son nom), retire les autres, ou ajoute.</summary>
        public void Set(string name, string value)
        {
            int i = IndexOf(name);
            if (i < 0) { Add(name, value); return; }
            list[i] = new HttpHeader(list[i].Name, value);
            for (int j = list.Count - 1; j > i; j--) if (Is(list[j], name)) list.RemoveAt(j);
        }

        public HttpHeaders Clone()
        {
            HttpHeaders copy = new HttpHeaders();
            copy.list.AddRange(list);
            return copy;
        }

        private int IndexOf(string name)
        {
            for (int i = 0; i < list.Count; i++) if (Is(list[i], name)) return i;
            return -1;
        }

        private static bool Is(HttpHeader h, string name)
        {
            return string.Equals(h.Name, name, StringComparison.OrdinalIgnoreCase);
        }

        public IEnumerator<HttpHeader> GetEnumerator() { return list.GetEnumerator(); }
        IEnumerator IEnumerable.GetEnumerator() { return list.GetEnumerator(); }
    }

    public sealed class HttpRequestHead
    {
        public string Method { get; private set; }
        /// <summary>Cible telle que reçue : chemin+query (origin-form) ou `host:port` (CONNECT).</summary>
        public string Target { get; private set; }
        public string Version { get; private set; }
        public HttpHeaders Headers { get; private set; }

        public HttpRequestHead(string method, string target, string version, HttpHeaders headers)
        {
            Method = method; Target = target; Version = version; Headers = headers ?? new HttpHeaders();
        }
    }

    public sealed class HttpResponseHead
    {
        public string Version { get; private set; }
        public int Status { get; private set; }
        public string Reason { get; private set; }
        public HttpHeaders Headers { get; private set; }

        public HttpResponseHead(string version, int status, string reason, HttpHeaders headers)
        {
            Version = version; Status = status; Reason = reason ?? ""; Headers = headers ?? new HttpHeaders();
        }
    }
}
