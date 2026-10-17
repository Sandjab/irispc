using System;
using System.Collections.Generic;

namespace IrisKit
{
    /// <summary>Abonnés synchrones in-process (spec §5.5). Un abonné qui lève n'empêche pas les autres ; l'erreur est journalisée.</summary>
    public sealed class EventsBus
    {
        private readonly object gate = new object();
        private readonly Dictionary<int, Action<Event>> subscribers = new Dictionary<int, Action<Event>>();
        private int nextId;

        private sealed class Subscription : IDisposable
        {
            private EventsBus bus;
            private readonly int id;
            public Subscription(EventsBus bus, int id) { this.bus = bus; this.id = id; }
            public void Dispose()
            {
                EventsBus b = bus;
                bus = null;
                if (b != null) b.Unsubscribe(id);
            }
        }

        public IDisposable Subscribe(Action<Event> handler)
        {
            if (handler == null) throw new ArgumentNullException("handler");
            lock (gate)
            {
                int id = ++nextId;
                subscribers[id] = handler;
                return new Subscription(this, id);
            }
        }

        private void Unsubscribe(int id)
        {
            lock (gate) { subscribers.Remove(id); }
        }

        public int SubscriberCount
        {
            get { lock (gate) { return subscribers.Count; } }
        }

        public void Publish(Event e)
        {
            List<Action<Event>> snapshot;
            lock (gate) { snapshot = new List<Action<Event>>(subscribers.Values); }
            foreach (Action<Event> handler in snapshot)
            {
                try { handler(e); }
                catch (Exception ex) { Log.Warn("events", "abonné en échec : " + ex.GetType().Name + " : " + ex.Message); }
            }
        }
    }
}
