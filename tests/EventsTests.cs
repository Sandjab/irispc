using System;
using System.Collections.Generic;
using System.IO;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Events ----------------------------------------------------

        private static Event Ev(EventKind kind, DateTime at, string host)
        {
            return new Event(Guid.NewGuid(), at, kind, host, "GET", "/", 200, 1, new string[0], null, null, EventFlags.None);
        }

        private static void Events_Ring()
        {
            Check.Throws<ArgumentOutOfRangeException>(delegate { new EventRing(0); }, "capacité nulle refusée");
            EventRing ring = new EventRing(3);
            for (int i = 0; i < 5; i++) ring.Append(Ev(i % 2 == 0 ? EventKind.NoMatch : EventKind.Substituted, T0.AddSeconds(i), "h" + i));
            Check.Eq(3, ring.All.Count, "borné à la capacité");
            Check.Eq("h2,h3,h4", string.Join(",", new List<Event>(ring.All).ConvertAll(delegate(Event e) { return e.Host; })), "les plus anciens évincés");
            Check.Eq(2, ring.Recent(2).Count, "Recent(2)");
            Check.Eq("h4", ring.Recent(1)[0].Host, "Recent rend les derniers en ordre");
            Check.Eq(0, ring.Recent(0).Count, "Recent(0) vide");
            Check.Eq(0, ring.Recent(-1).Count, "Recent(-1) vide");
            Check.Eq(2, ring.Since(T0.AddSeconds(3)).Count, "Since inclusif");
            Check.Eq(3L, ring.Count(EventKind.NoMatch), "totaux par kind sur la vie du ring (évincés compris)");
            Check.Eq(2L, ring.Count(EventKind.Substituted), "totaux");
            Check.Eq(3, ring.Clear(), "Clear rend le nombre retiré");
            Check.Eq(3L, ring.Count(EventKind.NoMatch), "Clear ne remet pas les totaux à zéro");
        }

        private static void Events_Bus()
        {
            EventsBus bus = new EventsBus();
            List<string> seen = new List<string>();
            IDisposable a = bus.Subscribe(delegate(Event e) { seen.Add("a:" + e.Host); });
            IDisposable b = bus.Subscribe(delegate(Event e) { throw new InvalidOperationException("abonné défaillant"); });
            IDisposable c = bus.Subscribe(delegate(Event e) { seen.Add("c:" + e.Host); });
            Check.Eq(3, bus.SubscriberCount, "trois abonnés");
            bus.Publish(Ev(EventKind.NoMatch, T0, "x"));
            Check.Eq("a:x,c:x", string.Join(",", seen), "un abonné en échec n'empêche pas les autres");
            a.Dispose(); b.Dispose();
            bus.Publish(Ev(EventKind.NoMatch, T0, "y"));
            Check.Eq("a:x,c:x,c:y", string.Join(",", seen), "désabonnement");
            Check.Eq(1, bus.SubscriberCount, "un abonné restant");
            c.Dispose(); c.Dispose();
            Check.Eq(0, bus.SubscriberCount, "Dispose idempotent");
        }

        private static void Events_JsonlStore()
        {
            string dir = TestDir.Create();
            try
            {
                DateTime now = new DateTime(2026, 10, 17, 23, 59, 0, DateTimeKind.Utc);
                Check.Eq("events-2026-10-17.jsonl", JsonlEventStore.FileNameFor(now), "nom de fichier par jour UTC");
                DateTime parsed;
                Check.True(JsonlEventStore.TryParseFileDate("events-2026-10-17.jsonl", out parsed) && parsed == now.Date, "date relue depuis le nom");
                Check.True(!JsonlEventStore.TryParseFileDate("notes.txt", out parsed), "autre fichier ignoré");
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return now; }))
                {
                    Event e1 = Ev(EventKind.Substituted, now, "api.anthropic.com");
                    store.Append(e1);
                    store.Append(Ev(EventKind.NoMatch, now.AddSeconds(30), "h2"));
                    store.Append(Ev(EventKind.PassThrough, now.AddMinutes(2), "h3")); // lendemain UTC
                    string[] lines = File.ReadAllLines(Path.Combine(dir, "events-2026-10-17.jsonl"));
                    Check.Eq(2, lines.Length, "deux lignes le 17 (flush à chaque écriture)");
                    Check.Eq(Json.EmitCompact(e1.ToJson()), lines[0], "une ligne = EmitCompact de l'event");
                    Check.True(File.Exists(Path.Combine(dir, "events-2026-10-18.jsonl")), "changement de jour → nouveau fichier");
                    IList<Event> back = store.Read(now);
                    Check.True(back.Count == 2 && back[0].Id == e1.Id && back[1].Host == "h2", "relecture d'un jour");
                }
                File.WriteAllText(Path.Combine(dir, "events-2026-10-09.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "events-2026-10-10.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "events-2026-10-11.jsonl"), "");
                File.WriteAllText(Path.Combine(dir, "garde-moi.txt"), "");
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return now; }))
                {
                    Check.Eq(2, store.Purge(), "fichiers plus vieux que 7 jours supprimés (09 et 10)");
                    Check.True(!File.Exists(Path.Combine(dir, "events-2026-10-09.jsonl")) && File.Exists(Path.Combine(dir, "events-2026-10-11.jsonl")) && File.Exists(Path.Combine(dir, "garde-moi.txt")), "limite inclusive à retention_days, autres fichiers intacts");
                }
            }
            finally { TestDir.Delete(dir); }
        }

        private static void Events_Pipeline()
        {
            string dir = TestDir.Create();
            try
            {
                EventRing ring = new EventRing(10);
                EventsBus bus = new EventsBus();
                int published = 0;
                bus.Subscribe(delegate(Event e) { published++; });
                using (JsonlEventStore store = new JsonlEventStore(dir, 7, delegate { return T0; }))
                {
                    EventPipeline p = new EventPipeline(ring, store, bus);
                    p.Emit(Ev(EventKind.Error, T0, "h"));
                    Check.True(ring.All.Count == 1 && published == 1 && File.Exists(Path.Combine(dir, "events-2023-11-14.jsonl")), "ring, bus et journal alimentés");
                }
                EventPipeline noStore = new EventPipeline(ring, null, bus);
                noStore.Emit(Ev(EventKind.Error, T0, "h"));
                Check.Eq(2, ring.All.Count, "journal optionnel");
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
