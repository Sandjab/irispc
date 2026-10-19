using System;
using System.Globalization;
using System.Text;

namespace IrisKit
{
    /// <summary>Sérialiseur d'OrderedJsonValue (OrderedJSONDocument.serialize d'IRIS) : 2 espaces, `": "`, LF, saut de ligne final.</summary>
    public static class OrderedJsonWriter
    {
        public static string Serialize(OrderedJsonValue root)
        {
            StringBuilder sb = new StringBuilder();
            Emit(sb, root, 0);
            sb.Append('\n');
            return sb.ToString();
        }

        /// <summary>Chaîne JSON entre guillemets (mêmes échappements que la sérialisation) ; sert aussi au diff de --dry-run.</summary>
        public static string Quote(string text)
        {
            StringBuilder sb = new StringBuilder();
            AppendString(sb, text);
            return sb.ToString();
        }

        private static void Emit(StringBuilder sb, OrderedJsonValue v, int indent)
        {
            switch (v.Kind)
            {
                case OrderedJsonKind.Null: sb.Append("null"); return;
                case OrderedJsonKind.Bool: sb.Append(v.Boolean ? "true" : "false"); return;
                case OrderedJsonKind.Integer: sb.Append(v.Integer.ToString(CultureInfo.InvariantCulture)); return;
                case OrderedJsonKind.Double: sb.Append(FormatDouble(v.Number)); return;
                case OrderedJsonKind.String: AppendString(sb, v.Text); return;
                case OrderedJsonKind.Array:
                    if (v.Items.Count == 0) { sb.Append("[]"); return; }
                    sb.Append("[\n");
                    for (int i = 0; i < v.Items.Count; i++)
                    {
                        Pad(sb, indent + 1);
                        Emit(sb, v.Items[i], indent + 1);
                        if (i < v.Items.Count - 1) sb.Append(',');
                        sb.Append('\n');
                    }
                    Pad(sb, indent);
                    sb.Append(']');
                    return;
                default:
                    if (v.Pairs.Count == 0) { sb.Append("{}"); return; }
                    sb.Append("{\n");
                    for (int i = 0; i < v.Pairs.Count; i++)
                    {
                        Pad(sb, indent + 1);
                        AppendString(sb, v.Pairs[i].Key);
                        sb.Append(": ");
                        Emit(sb, v.Pairs[i].Value, indent + 1);
                        if (i < v.Pairs.Count - 1) sb.Append(',');
                        sb.Append('\n');
                    }
                    Pad(sb, indent);
                    sb.Append('}');
                    return;
            }
        }

        private static void Pad(StringBuilder sb, int indent) { sb.Append(' ', indent * 2); }

        /// <summary>Double entier (|d| &lt; 1e15) : forme fractionnaire `1.0` comme IRIS ; sinon forme aller-retour (« R »).</summary>
        private static string FormatDouble(double d)
        {
            if (d == Math.Floor(d) && Math.Abs(d) < 1e15) return d.ToString("0.0", CultureInfo.InvariantCulture);
            return d.ToString("R", CultureInfo.InvariantCulture);
        }

        private static void AppendString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
