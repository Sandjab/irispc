using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Parseur JSON ordonné (port d'OrderedJSONDocument.parse d'IRIS) : RFC 8259 strict, ou JSONC (`//`, `/* */`, virgules finales)
    /// avec relevé des positions de commentaires. Clés en double refusées dans les deux modes. Positions en caractères UTF-16.
    /// </summary>
    public static class OrderedJsonParser
    {
        /// <summary>Profondeur maximale : un fichier hostile `[[[[…` ne fait jamais déborder la pile.</summary>
        public const int MaxDepth = 512;

        public static OrderedJsonDocument Parse(string text, bool jsonc)
        {
            if (text == null) throw new ArgumentNullException("text");
            Cursor c = new Cursor(text, jsonc);
            c.SkipWhitespaceAndComments();
            if (c.AtEnd) throw c.Error("document vide", c.Pos);
            OrderedJsonValue root = c.ParseValue(0);
            c.SkipWhitespaceAndComments();
            if (!c.AtEnd) throw c.Error("caractère inattendu après la valeur : " + Show(text[c.Pos]), c.Pos);
            return new OrderedJsonDocument(root, c.Comments.AsReadOnly());
        }

        private static string Show(char c)
        {
            if (c < 0x20) return "U+" + ((int)c).ToString("X4", CultureInfo.InvariantCulture);
            return "'" + c + "'";
        }

        private static bool IsDigit(char c) { return c >= '0' && c <= '9'; }

        private sealed class Cursor
        {
            private readonly string s;
            private readonly bool jsonc;
            public int Pos;
            public readonly List<CommentPosition> Comments = new List<CommentPosition>();
            // Cache de LineCol : le curseur avance, les appels successifs sont O(1) amorti (pas de O(n²) sur un gros fichier commenté).
            private int cachePos;
            private int cacheLine = 1;
            private int cacheColumn = 1;

            public Cursor(string s, bool jsonc)
            {
                this.s = s;
                this.jsonc = jsonc;
            }

            public bool AtEnd { get { return Pos >= s.Length; } }

            public OrderedJsonException Error(string reason, int at)
            {
                int line, column;
                LineCol(at, out line, out column);
                return new OrderedJsonException(reason, at, line, column);
            }

            private void LineCol(int at, out int line, out int column)
            {
                if (at < cachePos)
                {
                    cachePos = 0;
                    cacheLine = 1;
                    cacheColumn = 1;
                }
                for (int i = cachePos; i < at && i < s.Length; i++)
                {
                    if (s[i] == '\n') { cacheLine++; cacheColumn = 1; }
                    else cacheColumn++;
                }
                cachePos = at;
                line = cacheLine;
                column = cacheColumn;
            }

            private CommentPosition CommentAt(int at, CommentKind kind)
            {
                int line, column;
                LineCol(at, out line, out column);
                return new CommentPosition(line, column, kind);
            }

            public void SkipWhitespaceAndComments()
            {
                while (true)
                {
                    while (Pos < s.Length && (s[Pos] == ' ' || s[Pos] == '\t' || s[Pos] == '\n' || s[Pos] == '\r')) Pos++;
                    if (Pos >= s.Length || s[Pos] != '/') return;
                    if (!jsonc) throw Error("commentaire interdit en JSON strict", Pos);
                    if (Pos + 1 >= s.Length) return; // '/' isolé : refusé par l'appelant
                    char next = s[Pos + 1];
                    if (next == '/')
                    {
                        Comments.Add(CommentAt(Pos, CommentKind.Line));
                        Pos += 2;
                        while (Pos < s.Length && s[Pos] != '\n') Pos++;
                        continue;
                    }
                    if (next == '*')
                    {
                        int start = Pos;
                        Comments.Add(CommentAt(start, CommentKind.Block));
                        Pos += 2;
                        bool closed = false;
                        while (Pos + 1 < s.Length)
                        {
                            if (s[Pos] == '*' && s[Pos + 1] == '/')
                            {
                                Pos += 2;
                                closed = true;
                                break;
                            }
                            Pos++;
                        }
                        if (!closed) throw Error("commentaire /* non fermé", start);
                        continue;
                    }
                    return;
                }
            }

            public OrderedJsonValue ParseValue(int depth)
            {
                SkipWhitespaceAndComments();
                if (AtEnd) throw Error("fin de document inattendue", Pos);
                char c = s[Pos];
                switch (c)
                {
                    case '{': return ParseObject(depth + 1);
                    case '[': return ParseArray(depth + 1);
                    case '"': return OrderedJsonValue.FromString(ParseString());
                    case 't': Literal("true"); return OrderedJsonValue.FromBool(true);
                    case 'f': Literal("false"); return OrderedJsonValue.FromBool(false);
                    case 'n': Literal("null"); return OrderedJsonValue.Null();
                    default:
                        if (c == '-' || IsDigit(c)) return ParseNumber();
                        throw Error("caractère inattendu : " + Show(c), Pos);
                }
            }

            private void CheckDepth(int depth)
            {
                if (depth > MaxDepth) throw Error("imbrication trop profonde (plus de " + MaxDepth + " niveaux)", Pos);
            }

            private OrderedJsonValue ParseObject(int depth)
            {
                CheckDepth(depth);
                Pos++; // {
                OrderedJsonValue obj = OrderedJsonValue.NewObject();
                HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);
                SkipWhitespaceAndComments();
                if (AtEnd) throw Error("fin de document inattendue dans un objet", Pos);
                if (s[Pos] == '}') { Pos++; return obj; }
                while (true)
                {
                    SkipWhitespaceAndComments();
                    if (AtEnd) throw Error("fin de document inattendue dans un objet", Pos);
                    if (s[Pos] != '"') throw Error("clé entre guillemets attendue, trouvé " + Show(s[Pos]), Pos);
                    int keyPos = Pos;
                    string key = ParseString();
                    if (!seen.Add(key)) throw Error("clé en double : \"" + key + "\"", keyPos);
                    SkipWhitespaceAndComments();
                    if (AtEnd || s[Pos] != ':') throw Error("':' attendu après la clé \"" + key + "\"", Pos);
                    Pos++;
                    obj.Pairs.Add(new KeyValuePair<string, OrderedJsonValue>(key, ParseValue(depth)));
                    SkipWhitespaceAndComments();
                    if (AtEnd) throw Error("fin de document inattendue dans un objet", Pos);
                    char next = s[Pos];
                    if (next == '}') { Pos++; return obj; }
                    if (next != ',') throw Error("',' ou '}' attendu, trouvé " + Show(next), Pos);
                    Pos++;
                    SkipWhitespaceAndComments();
                    if (!AtEnd && s[Pos] == '}')
                    {
                        if (!jsonc) throw Error("virgule finale interdite en JSON strict", Pos);
                        Pos++;
                        return obj;
                    }
                }
            }

            private OrderedJsonValue ParseArray(int depth)
            {
                CheckDepth(depth);
                Pos++; // [
                OrderedJsonValue array = OrderedJsonValue.NewArray();
                SkipWhitespaceAndComments();
                if (AtEnd) throw Error("fin de document inattendue dans un tableau", Pos);
                if (s[Pos] == ']') { Pos++; return array; }
                while (true)
                {
                    array.Items.Add(ParseValue(depth));
                    SkipWhitespaceAndComments();
                    if (AtEnd) throw Error("fin de document inattendue dans un tableau", Pos);
                    char next = s[Pos];
                    if (next == ']') { Pos++; return array; }
                    if (next != ',') throw Error("',' ou ']' attendu, trouvé " + Show(next), Pos);
                    Pos++;
                    SkipWhitespaceAndComments();
                    if (!AtEnd && s[Pos] == ']')
                    {
                        if (!jsonc) throw Error("virgule finale interdite en JSON strict", Pos);
                        Pos++;
                        return array;
                    }
                }
            }

            private string ParseString()
            {
                Pos++; // "
                StringBuilder sb = new StringBuilder();
                while (Pos < s.Length)
                {
                    char c = s[Pos];
                    if (c == '"') { Pos++; return sb.ToString(); }
                    if (c == '\\')
                    {
                        int esc = Pos;
                        Pos++;
                        if (AtEnd) throw Error("chaîne non fermée", esc);
                        char e = s[Pos++];
                        switch (e)
                        {
                            case '"': sb.Append('"'); break;
                            case '\\': sb.Append('\\'); break;
                            case '/': sb.Append('/'); break;
                            case 'b': sb.Append('\b'); break;
                            case 'f': sb.Append('\f'); break;
                            case 'n': sb.Append('\n'); break;
                            case 'r': sb.Append('\r'); break;
                            case 't': sb.Append('\t'); break;
                            case 'u': AppendUnicodeEscape(sb, esc); break;
                            default: throw Error("échappement invalide : \\" + e, esc);
                        }
                        continue;
                    }
                    if (c < 0x20) throw Error("caractère de contrôle non échappé dans une chaîne : " + Show(c), Pos);
                    sb.Append(c);
                    Pos++;
                }
                throw Error("chaîne non fermée", Pos);
            }

            private void AppendUnicodeEscape(StringBuilder sb, int esc)
            {
                int high = Hex4(esc);
                if (high >= 0xD800 && high <= 0xDBFF)
                {
                    if (Pos + 1 >= s.Length || s[Pos] != '\\' || s[Pos + 1] != 'u') throw Error("demi-paire de substitution isolée", esc);
                    Pos += 2;
                    int low = Hex4(esc);
                    if (low < 0xDC00 || low > 0xDFFF) throw Error("paire de substitution invalide", esc);
                    sb.Append((char)high);
                    sb.Append((char)low);
                    return;
                }
                if (high >= 0xDC00 && high <= 0xDFFF) throw Error("demi-paire de substitution isolée", esc);
                sb.Append((char)high);
            }

            private int Hex4(int esc)
            {
                if (Pos + 4 > s.Length) throw Error("échappement \\u incomplet", esc);
                int value = 0;
                for (int i = 0; i < 4; i++)
                {
                    char h = s[Pos++];
                    int digit;
                    if (h >= '0' && h <= '9') digit = h - '0';
                    else if (h >= 'a' && h <= 'f') digit = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') digit = h - 'A' + 10;
                    else throw Error("échappement \\u invalide", esc);
                    value = value * 16 + digit;
                }
                return value;
            }

            private void Literal(string word)
            {
                if (Pos + word.Length > s.Length || string.CompareOrdinal(s, Pos, word, 0, word.Length) != 0)
                    throw Error("caractère inattendu : " + Show(s[Pos]), Pos);
                Pos += word.Length;
            }

            private OrderedJsonValue ParseNumber()
            {
                int start = Pos;
                bool isFloat = false;
                if (s[Pos] == '-') Pos++;
                if (AtEnd) throw Error("nombre invalide", start);
                if (s[Pos] == '0')
                {
                    Pos++;
                    if (!AtEnd && IsDigit(s[Pos])) throw Error("nombre invalide (zéro en tête)", start);
                }
                else if (s[Pos] >= '1' && s[Pos] <= '9')
                {
                    while (!AtEnd && IsDigit(s[Pos])) Pos++;
                }
                else throw Error("nombre invalide", start);
                if (!AtEnd && s[Pos] == '.')
                {
                    isFloat = true;
                    Pos++;
                    if (AtEnd || !IsDigit(s[Pos])) throw Error("nombre invalide (chiffre attendu après le point)", start);
                    while (!AtEnd && IsDigit(s[Pos])) Pos++;
                }
                if (!AtEnd && (s[Pos] == 'e' || s[Pos] == 'E'))
                {
                    isFloat = true;
                    Pos++;
                    if (!AtEnd && (s[Pos] == '+' || s[Pos] == '-')) Pos++;
                    if (AtEnd || !IsDigit(s[Pos])) throw Error("nombre invalide (exposant)", start);
                    while (!AtEnd && IsDigit(s[Pos])) Pos++;
                }
                string text = s.Substring(start, Pos - start);
                long n;
                if (!isFloat && long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out n))
                    return OrderedJsonValue.FromInteger(n);
                double d;
                if (double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out d) && !double.IsInfinity(d) && !double.IsNaN(d))
                    return OrderedJsonValue.FromDouble(d);
                throw Error("nombre hors limites : " + text, start);
            }
        }
    }
}
