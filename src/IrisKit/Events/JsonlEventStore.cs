using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace IrisKit
{
    /// <summary>
    /// Journal persistant : un fichier `events-AAAA-MM-JJ.jsonl` par jour UTC (jour du timestamp de l'event),
    /// une ligne par event, flush à chaque écriture. Purge des fichiers plus vieux que retentionDays
    /// au démarrage (appel explicite) et à chaque changement de jour.
    /// </summary>
    public sealed class JsonlEventStore : IDisposable
    {
        private const string Prefix = "events-";
        private const string Extension = ".jsonl";
        private static readonly UTF8Encoding Utf8NoBom = new UTF8Encoding(false);

        private readonly object gate = new object();
        private readonly string dir;
        private readonly int retentionDays;
        private readonly Func<DateTime> clock;
        private StreamWriter writer;
        private DateTime openDay;

        public string Directory { get { return dir; } }
        public int RetentionDays { get { return retentionDays; } }

        public JsonlEventStore(string eventsDir, int retentionDays, Func<DateTime> clock)
        {
            if (retentionDays <= 0) throw new ArgumentOutOfRangeException("retentionDays");
            dir = eventsDir;
            this.retentionDays = retentionDays;
            this.clock = clock;
            System.IO.Directory.CreateDirectory(dir);
        }

        public static string FileNameFor(DateTime utc)
        {
            return Prefix + utc.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + Extension;
        }

        public static bool TryParseFileDate(string fileName, out DateTime day)
        {
            day = DateTime.MinValue;
            if (fileName == null || !fileName.StartsWith(Prefix, StringComparison.Ordinal) || !fileName.EndsWith(Extension, StringComparison.Ordinal)) return false;
            string middle = fileName.Substring(Prefix.Length, fileName.Length - Prefix.Length - Extension.Length);
            if (!DateTime.TryParseExact(middle, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out day)) return false;
            day = DateTime.SpecifyKind(day.Date, DateTimeKind.Utc);
            return true;
        }

        public void Append(Event e)
        {
            lock (gate)
            {
                DateTime day = e.Timestamp.ToUniversalTime().Date;
                if (writer == null || day != openDay)
                {
                    CloseWriter();
                    writer = new StreamWriter(Path.Combine(dir, FileNameFor(day)), true, Utf8NoBom);
                    writer.AutoFlush = true;
                    writer.NewLine = "\n";
                    bool dayChanged = openDay != DateTime.MinValue;
                    openDay = day;
                    if (dayChanged) Purge();
                }
                writer.WriteLine(Json.EmitCompact(e.ToJson()));
            }
        }

        /// <summary>Conserve les retentionDays derniers jours (aujourd'hui compris) : supprime les fichiers dont le jour ≤ aujourd'hui − retentionDays. Rend le nombre supprimé.</summary>
        public int Purge()
        {
            DateTime limit = clock().ToUniversalTime().Date.AddDays(-retentionDays);
            int removed = 0;
            foreach (string path in System.IO.Directory.GetFiles(dir, Prefix + "*" + Extension))
            {
                DateTime day;
                if (!TryParseFileDate(Path.GetFileName(path), out day) || day > limit) continue;
                try { File.Delete(path); removed++; }
                catch (IOException ex) { Log.Warn("events", "purge impossible : " + path + " : " + ex.Message); }
                catch (UnauthorizedAccessException ex) { Log.Warn("events", "purge impossible : " + path + " : " + ex.Message); }
            }
            if (removed > 0) Log.Info("events", removed + " fichier(s) d'events purgé(s), rétention " + retentionDays + " jour(s)");
            return removed;
        }

        public IList<Event> Read(DateTime day)
        {
            string path = Path.Combine(dir, FileNameFor(day));
            List<Event> result = new List<Event>();
            if (!File.Exists(path)) return result;
            lock (gate)
            {
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
                using (StreamReader reader = new StreamReader(fs, Encoding.UTF8))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Trim().Length == 0) continue;
                        try { result.Add(Event.FromJson(Json.ParseObject(line))); }
                        catch (JsonException ex) { Log.Warn("events", "ligne illisible dans " + path + " : " + ex.Message); }
                    }
                }
            }
            return result;
        }

        /// <summary>`events.clear` : ferme le fichier du jour et supprime tous les fichiers d'events ; rend le nombre d'events (lignes non vides) supprimés.</summary>
        public int ClearAll()
        {
            lock (gate)
            {
                CloseWriter();
                openDay = DateTime.MinValue;
                int count = 0;
                foreach (string path in System.IO.Directory.GetFiles(dir, Prefix + "*" + Extension))
                {
                    try
                    {
                        foreach (string line in File.ReadAllLines(path, Encoding.UTF8)) if (line.Trim().Length > 0) count++;
                        File.Delete(path);
                    }
                    catch (IOException ex) { Log.Warn("events", "suppression impossible : " + path + " : " + ex.Message); }
                    catch (UnauthorizedAccessException ex) { Log.Warn("events", "suppression impossible : " + path + " : " + ex.Message); }
                }
                Log.Info("events", "journal vidé : " + count + " event(s) supprimé(s)");
                return count;
            }
        }

        private void CloseWriter()
        {
            if (writer == null) return;
            writer.Flush();
            writer.Dispose();
            writer = null;
        }

        public void Dispose()
        {
            lock (gate) { CloseWriter(); }
        }
    }
}
