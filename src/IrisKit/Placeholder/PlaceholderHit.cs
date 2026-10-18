using System;

namespace IrisKit
{
    public enum HitLocationKind { Header, UrlPath, QueryString, Body }

    /// <summary>Emplacement d'un placeholder dans la requête. Pour un en-tête, le nom est en minuscules (RFC 7230 §3.2).</summary>
    public sealed class HitLocation : IEquatable<HitLocation>
    {
        public HitLocationKind Kind { get; private set; }
        public string HeaderName { get; private set; }

        private HitLocation(HitLocationKind kind, string headerName) { Kind = kind; HeaderName = headerName; }

        public static HitLocation Header(string name) { return new HitLocation(HitLocationKind.Header, (name ?? "").ToLowerInvariant()); }
        public static readonly HitLocation UrlPath = new HitLocation(HitLocationKind.UrlPath, null);
        public static readonly HitLocation QueryString = new HitLocation(HitLocationKind.QueryString, null);
        public static readonly HitLocation Body = new HitLocation(HitLocationKind.Body, null);

        public AlertLocation ToAlertLocation()
        {
            switch (Kind)
            {
                case HitLocationKind.Header: return AlertLocation.Header;
                case HitLocationKind.UrlPath: return AlertLocation.UrlPath;
                case HitLocationKind.QueryString: return AlertLocation.QueryString;
                default: return AlertLocation.Body;
            }
        }

        /// <summary>Libellé sans valeur pour le journal de diagnostic (le nom d'en-tête est une métadonnée, jamais un secret).</summary>
        public string Describe()
        {
            switch (Kind)
            {
                case HitLocationKind.Header: return "header(" + HeaderName + ")";
                case HitLocationKind.UrlPath: return "path";
                case HitLocationKind.QueryString: return "query";
                default: return "body";
            }
        }

        public bool Equals(HitLocation other)
        {
            return other != null && other.Kind == Kind && string.Equals(other.HeaderName, HeaderName, StringComparison.Ordinal);
        }

        public override bool Equals(object obj) { return Equals(obj as HitLocation); }
        public override int GetHashCode() { return ((int)Kind * 397) ^ (HeaderName == null ? 0 : HeaderName.GetHashCode()); }
        public override string ToString() { return Describe(); }
    }

    /// <summary>Un placeholder trouvé : nom, emplacement, extrait de contexte (avant substitution, jamais une valeur).</summary>
    public sealed class PlaceholderHit
    {
        public string Name { get; private set; }
        public HitLocation Location { get; private set; }
        public string Snippet { get; private set; }

        public PlaceholderHit(string name, HitLocation location, string snippet)
        {
            Name = name; Location = location; Snippet = snippet ?? "";
        }
    }
}
