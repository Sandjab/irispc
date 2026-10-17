using System;
using System.IO;

namespace IrisKit
{
    /// <summary>Niveaux de log, valeurs de fil IRIS : trace, debug, info, warn, error.</summary>
    public enum LogLevel { Trace = 0, Debug = 1, Info = 2, Warn = 3, Error = 4 }

    public static class LogLevelWire
    {
        public static readonly string[] Names = { "trace", "debug", "info", "warn", "error" };

        public static string ToWire(LogLevel level) { return Names[(int)level]; }

        public static bool TryParse(string wire, out LogLevel level)
        {
            int i = Array.IndexOf(Names, wire);
            level = i < 0 ? LogLevel.Info : (LogLevel)i;
            return i >= 0;
        }
    }

    /// <summary>
    /// Journal console horodaté (spec §5.5). Jamais de valeur de secret : passer par Redaction.Redact.
    /// Statique et verrouillé : un seul flux de sortie par processus.
    /// </summary>
    public static class Log
    {
        private static readonly object Gate = new object();
        private static readonly string[] Labels = { "TRACE", "DEBUG", "INFO ", "WARN ", "ERROR" };

        public static LogLevel Minimum = LogLevel.Info;
        public static TextWriter Writer = Console.Out;
        public static Func<DateTime> Clock = delegate { return DateTime.UtcNow; };

        public static void Reset()
        {
            Minimum = LogLevel.Info;
            Writer = Console.Out;
            Clock = delegate { return DateTime.UtcNow; };
        }

        public static void Trace(string category, string message) { Write(LogLevel.Trace, category, message); }
        public static void Debug(string category, string message) { Write(LogLevel.Debug, category, message); }
        public static void Info(string category, string message) { Write(LogLevel.Info, category, message); }
        public static void Warn(string category, string message) { Write(LogLevel.Warn, category, message); }
        public static void Error(string category, string message) { Write(LogLevel.Error, category, message); }

        private static void Write(LogLevel level, string category, string message)
        {
            if (level < Minimum) return;
            string line = Json.FormatDate(Clock()) + " " + Labels[(int)level] + " [" + category + "] " + message;
            lock (Gate)
            {
                Writer.WriteLine(line);
                Writer.Flush();
            }
        }
    }
}
