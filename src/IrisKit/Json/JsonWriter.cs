using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace IrisKit
{
    public static partial class Json
    {
        /// <summary>Émission indentée (2 espaces, LF), ordre d'insertion des dictionnaires respecté.</summary>
        public static string Emit(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0, true);
            return sb.ToString();
        }

        /// <summary>Émission sur une ligne (JSONL).</summary>
        public static string EmitCompact(object value)
        {
            StringBuilder sb = new StringBuilder();
            Write(sb, value, 0, false);
            return sb.ToString();
        }

        private static void Write(StringBuilder sb, object value, int depth, bool pretty)
        {
            if (value == null) { sb.Append("null"); return; }
            string s = value as string;
            if (s != null) { WriteString(sb, s); return; }
            if (value is bool) { sb.Append((bool)value ? "true" : "false"); return; }
            if (value is DateTime) { WriteString(sb, FormatDate((DateTime)value)); return; }
            if (value is int || value is long || value is short || value is byte || value is uint || value is ulong)
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }
            if (value is double || value is float || value is decimal)
            {
                double d = Convert.ToDouble(value, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) throw new JsonException("nombre non représentable en JSON");
                sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            if (value is Enum) throw new JsonException("énumération non sérialisable directement : " + value.GetType().Name);
            IDictionary dict = value as IDictionary;
            if (dict != null) { WriteObject(sb, dict, depth, pretty); return; }
            IEnumerable list = value as IEnumerable;
            if (list != null) { WriteArray(sb, list, depth, pretty); return; }
            throw new JsonException("type non sérialisable : " + value.GetType().Name);
        }

        private static void WriteObject(StringBuilder sb, IDictionary dict, int depth, bool pretty)
        {
            if (dict.Count == 0) { sb.Append("{}"); return; }
            sb.Append('{');
            bool first = true;
            foreach (DictionaryEntry entry in dict)
            {
                string key = entry.Key as string;
                if (key == null) throw new JsonException("clé JSON non textuelle");
                if (!first) sb.Append(',');
                first = false;
                NewLine(sb, depth + 1, pretty);
                WriteString(sb, key);
                sb.Append(pretty ? ": " : ":");
                Write(sb, entry.Value, depth + 1, pretty);
            }
            NewLine(sb, depth, pretty);
            sb.Append('}');
        }

        private static void WriteArray(StringBuilder sb, IEnumerable list, int depth, bool pretty)
        {
            sb.Append('[');
            bool first = true;
            foreach (object item in list)
            {
                if (!first) sb.Append(',');
                first = false;
                NewLine(sb, depth + 1, pretty);
                Write(sb, item, depth + 1, pretty);
            }
            if (!first) NewLine(sb, depth, pretty);
            sb.Append(']');
        }

        private static void NewLine(StringBuilder sb, int depth, bool pretty)
        {
            if (!pretty) return;
            sb.Append('\n');
            sb.Append(' ', depth * 2);
        }

        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
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
