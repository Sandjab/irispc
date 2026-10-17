using System;
using System.IO;

namespace IrisKit
{
    /// <summary>Point d'émission unique : ring (mémoire) → journal JSONL (optionnel) → bus (abonnés).</summary>
    public sealed class EventPipeline
    {
        public EventRing Ring { get; private set; }
        public JsonlEventStore Store { get; private set; }
        public EventsBus Bus { get; private set; }

        public EventPipeline(EventRing ring, JsonlEventStore store, EventsBus bus)
        {
            if (ring == null) throw new ArgumentNullException("ring");
            if (bus == null) throw new ArgumentNullException("bus");
            Ring = ring;
            Store = store;
            Bus = bus;
        }

        public void Emit(Event e)
        {
            Ring.Append(e);
            if (Store != null)
            {
                try { Store.Append(e); }
                catch (IOException ex) { Log.Error("events", "journal inaccessible : " + ex.Message); }
                catch (UnauthorizedAccessException ex) { Log.Error("events", "journal inaccessible : " + ex.Message); }
            }
            Bus.Publish(e);
        }
    }
}
