using System;
using System.Collections.Generic;

namespace IrisKit
{
    public enum OrderedJsonKind { Object, Array, String, Integer, Double, Bool, Null }

    /// <summary>
    /// Valeur JSON qui garde l'ordre des clés (port d'OrderedJSONValue d'IRIS) : objet = liste de paires, tableau, chaîne,
    /// entier 64 bits, double, booléen, null. Objets et tableaux sont mutables ; le patcheur travaille sur une copie (Clone).
    /// </summary>
    public sealed class OrderedJsonValue
    {
        public OrderedJsonKind Kind { get; private set; }
        public List<KeyValuePair<string, OrderedJsonValue>> Pairs { get; private set; }
        public List<OrderedJsonValue> Items { get; private set; }
        public string Text { get; private set; }
        public long Integer { get; private set; }
        public double Number { get; private set; }
        public bool Boolean { get; private set; }

        private OrderedJsonValue(OrderedJsonKind kind) { Kind = kind; }

        public bool IsObject { get { return Kind == OrderedJsonKind.Object; } }

        public static OrderedJsonValue NewObject()
        {
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.Object);
            v.Pairs = new List<KeyValuePair<string, OrderedJsonValue>>();
            return v;
        }

        public static OrderedJsonValue NewArray()
        {
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.Array);
            v.Items = new List<OrderedJsonValue>();
            return v;
        }

        public static OrderedJsonValue FromString(string text)
        {
            if (text == null) throw new ArgumentNullException("text");
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.String);
            v.Text = text;
            return v;
        }

        public static OrderedJsonValue FromInteger(long n)
        {
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.Integer);
            v.Integer = n;
            return v;
        }

        public static OrderedJsonValue FromDouble(double d)
        {
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.Double);
            v.Number = d;
            return v;
        }

        public static OrderedJsonValue FromBool(bool b)
        {
            OrderedJsonValue v = new OrderedJsonValue(OrderedJsonKind.Bool);
            v.Boolean = b;
            return v;
        }

        public static OrderedJsonValue Null() { return new OrderedJsonValue(OrderedJsonKind.Null); }

        /// <summary>Valeur de `key` dans un objet ; null (C#) si la clé est absente ou si la valeur n'est pas un objet.</summary>
        public OrderedJsonValue Get(string key)
        {
            if (Kind != OrderedJsonKind.Object) return null;
            foreach (KeyValuePair<string, OrderedJsonValue> p in Pairs)
                if (p.Key == key) return p.Value;
            return null;
        }

        /// <summary>Remplace la valeur de `key` à sa place, ou l'ajoute en fin d'objet.</summary>
        public void Set(string key, OrderedJsonValue value)
        {
            if (Kind != OrderedJsonKind.Object) throw new InvalidOperationException("Set sur une valeur JSON qui n'est pas un objet");
            if (value == null) throw new ArgumentNullException("value");
            for (int i = 0; i < Pairs.Count; i++)
            {
                if (Pairs[i].Key != key) continue;
                Pairs[i] = new KeyValuePair<string, OrderedJsonValue>(key, value);
                return;
            }
            Pairs.Add(new KeyValuePair<string, OrderedJsonValue>(key, value));
        }

        /// <summary>Copie profonde des objets et tableaux ; les scalaires sont immuables et partagés.</summary>
        public OrderedJsonValue Clone()
        {
            if (Kind == OrderedJsonKind.Object)
            {
                OrderedJsonValue o = NewObject();
                foreach (KeyValuePair<string, OrderedJsonValue> p in Pairs)
                    o.Pairs.Add(new KeyValuePair<string, OrderedJsonValue>(p.Key, p.Value.Clone()));
                return o;
            }
            if (Kind == OrderedJsonKind.Array)
            {
                OrderedJsonValue a = NewArray();
                foreach (OrderedJsonValue item in Items) a.Items.Add(item.Clone());
                return a;
            }
            return this;
        }
    }

    public enum CommentKind { Line, Block }

    /// <summary>Position (1-indexée) d'un commentaire JSONC : `mcp wrap` refuse d'écrire un fichier qui en contient.</summary>
    public sealed class CommentPosition
    {
        public int Line { get; private set; }
        public int Column { get; private set; }
        public CommentKind Kind { get; private set; }

        public CommentPosition(int line, int column, CommentKind kind)
        {
            Line = line;
            Column = column;
            Kind = kind;
        }
    }

    /// <summary>JSON refusé : message `L<ligne>:<col> : <raison>` en français.</summary>
    public sealed class OrderedJsonException : Exception
    {
        public int Position { get; private set; }
        public int Line { get; private set; }
        public int Column { get; private set; }

        public OrderedJsonException(string reason, int position, int line, int column)
            : base("L" + line + ":" + column + " : " + reason)
        {
            Position = position;
            Line = line;
            Column = column;
        }
    }

    public sealed class OrderedJsonDocument
    {
        public OrderedJsonValue Root { get; private set; }
        public IList<CommentPosition> Comments { get; private set; }

        public OrderedJsonDocument(OrderedJsonValue root, IList<CommentPosition> comments)
        {
            Root = root;
            Comments = comments;
        }
    }
}
