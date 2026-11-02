using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Hd2Qd.License
{
    /// <summary>A small JSON reader and writer: objects as Dictionary&lt;string, object&gt;
    /// (in their order), arrays as List&lt;object&gt;, whole numbers as long (the deploy
    /// record's nanosecond times do not fit a double), others as double.</summary>
    public static class Json
    {
        public static object Parse(string s)
        {
            int i = 0;
            var v = Value(s, ref i);
            Space(s, ref i);
            if (i != s.Length) throw new FormatException("JSON: text after the value at " + i);
            return v;
        }

        static void Space(string s, ref int i)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
        }

        static object Value(string s, ref int i)
        {
            Space(s, ref i);
            if (i >= s.Length) throw new FormatException("JSON: unexpected end");
            char c = s[i];
            if (c == '{')
            {
                var d = new Dictionary<string, object>();
                i++;
                Space(s, ref i);
                if (i < s.Length && s[i] == '}') { i++; return d; }
                while (true)
                {
                    Space(s, ref i);
                    var key = Str(s, ref i);
                    Space(s, ref i);
                    Expect(s, ref i, ':');
                    d[key] = Value(s, ref i);
                    Space(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    Expect(s, ref i, '}');
                    return d;
                }
            }
            if (c == '[')
            {
                var l = new List<object>();
                i++;
                Space(s, ref i);
                if (i < s.Length && s[i] == ']') { i++; return l; }
                while (true)
                {
                    l.Add(Value(s, ref i));
                    Space(s, ref i);
                    if (i < s.Length && s[i] == ',') { i++; continue; }
                    Expect(s, ref i, ']');
                    return l;
                }
            }
            if (c == '"') return Str(s, ref i);
            if (Word(s, ref i, "true")) return true;
            if (Word(s, ref i, "false")) return false;
            if (Word(s, ref i, "null")) return null;
            int start = i;
            while (i < s.Length && "+-0123456789.eE".IndexOf(s[i]) >= 0) i++;
            if (start == i) throw new FormatException("JSON: unexpected '" + c + "' at " + i);
            var text = s.Substring(start, i - start);
            if (text.IndexOfAny(new[] { '.', 'e', 'E' }) < 0 && long.TryParse(text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var whole))
                return whole;
            return double.Parse(text, NumberStyles.Float, CultureInfo.InvariantCulture);
        }

        static bool Word(string s, ref int i, string w)
        {
            if (string.CompareOrdinal(s, i, w, 0, w.Length) != 0) return false;
            i += w.Length;
            return true;
        }

        static void Expect(string s, ref int i, char c)
        {
            if (i >= s.Length || s[i] != c) throw new FormatException("JSON: '" + c + "' expected at " + i);
            i++;
        }

        static string Str(string s, ref int i)
        {
            Expect(s, ref i, '"');
            var sb = new StringBuilder();
            while (i < s.Length)
            {
                char c = s[i++];
                if (c == '"') return sb.ToString();
                if (c != '\\') { sb.Append(c); continue; }
                if (i >= s.Length) break;
                char e = s[i++];
                switch (e)
                {
                    case 'n': sb.Append('\n'); break;
                    case 't': sb.Append('\t'); break;
                    case 'r': sb.Append('\r'); break;
                    case 'b': sb.Append('\b'); break;
                    case 'f': sb.Append('\f'); break;
                    case 'u':
                        sb.Append((char)int.Parse(s.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: sb.Append(e); break;
                }
            }
            throw new FormatException("JSON: unfinished string");
        }

        /// <summary>The text of a value; with indent, two spaces a level (as the Python
        /// version wrote its files).</summary>
        public static string Write(object v, bool indent = false)
        {
            var sb = new StringBuilder();
            Write(sb, v, indent ? 0 : -1);
            return sb.ToString();
        }

        static void Line(StringBuilder sb, int level)
        {
            if (level < 0) return;
            sb.Append('\n').Append(' ', level * 2);
        }

        static void Write(StringBuilder sb, object v, int level)
        {
            int inner = level < 0 ? -1 : level + 1;
            switch (v)
            {
                case null: sb.Append("null"); break;
                case bool b: sb.Append(b ? "true" : "false"); break;
                case string s:
                    sb.Append('"');
                    foreach (var c in s)
                    {
                        if (c == '"' || c == '\\') sb.Append('\\').Append(c);
                        else if (c == '\n') sb.Append("\\n");
                        else if (c < ' ') sb.AppendFormat(CultureInfo.InvariantCulture, "\\u{0:x4}", (int)c);
                        else sb.Append(c);
                    }
                    sb.Append('"');
                    break;
                case IDictionary<string, object> d:
                    if (d.Count == 0) { sb.Append("{}"); break; }
                    sb.Append('{');
                    bool first = true;
                    foreach (var kv in d)
                    {
                        if (!first) sb.Append(',');
                        first = false;
                        Line(sb, inner);
                        Write(sb, kv.Key, inner);
                        sb.Append(level < 0 ? ":" : ": ");
                        Write(sb, kv.Value, inner);
                    }
                    Line(sb, level);
                    sb.Append('}');
                    break;
                case System.Collections.IEnumerable e:
                    var items = new List<object>();
                    foreach (var x in e) items.Add(x);
                    if (items.Count == 0) { sb.Append("[]"); break; }
                    sb.Append('[');
                    for (int k = 0; k < items.Count; k++)
                    {
                        if (k > 0) sb.Append(',');
                        Line(sb, inner);
                        Write(sb, items[k], inner);
                    }
                    Line(sb, level);
                    sb.Append(']');
                    break;
                case int n: sb.Append(n.ToString(CultureInfo.InvariantCulture)); break;
                case long n: sb.Append(n.ToString(CultureInfo.InvariantCulture)); break;
                default:
                    sb.Append(Convert.ToDouble(v, CultureInfo.InvariantCulture).ToString("R", CultureInfo.InvariantCulture));
                    break;
            }
        }

        // reading helpers for the files' loose objects
        public static string Str(IDictionary<string, object> d, string k) => d != null && d.TryGetValue(k, out var v) ? v as string : null;
        public static bool Bool(IDictionary<string, object> d, string k, bool fallback = false) =>
            d != null && d.TryGetValue(k, out var v) && v is bool b ? b : fallback;
        public static long Long(IDictionary<string, object> d, string k) =>
            d != null && d.TryGetValue(k, out var v) && v != null && !(v is string) && !(v is bool) && !(v is IDictionary<string, object>) && !(v is List<object>)
                ? Convert.ToInt64(v, CultureInfo.InvariantCulture) : 0;
        public static Dictionary<string, object> Obj(IDictionary<string, object> d, string k) =>
            d != null && d.TryGetValue(k, out var v) ? v as Dictionary<string, object> : null;
        public static List<object> List(IDictionary<string, object> d, string k) =>
            d != null && d.TryGetValue(k, out var v) && v is List<object> l ? l : new List<object>();
    }
}
