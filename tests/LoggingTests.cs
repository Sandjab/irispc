using System;
using System.IO;
using System.Text;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- Logging ---------------------------------------------------

        private static void Logging_LevelsAndFormat()
        {
            StringWriter w = new StringWriter();
            Log.Reset();
            Log.Writer = w;
            Log.Clock = delegate { return new DateTime(2026, 10, 17, 7, 49, 47, DateTimeKind.Utc); };
            Log.Minimum = LogLevel.Info;
            Log.Debug("vault", "caché");
            Log.Info("vault", "coffre ouvert");
            Log.Warn("ca", "attention");
            Log.Error("config", "échec");
            string[] lines = w.ToString().Split(new[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            Check.Eq(3, lines.Length, "debug filtré sous info");
            Check.Eq("2026-10-17T07:49:47Z INFO  [vault] coffre ouvert", lines[0], "format horodaté, niveau aligné, catégorie");
            Check.Eq("2026-10-17T07:49:47Z WARN  [ca] attention", lines[1], "warn");
            Check.Eq("2026-10-17T07:49:47Z ERROR [config] échec", lines[2], "error");
            Log.Minimum = LogLevel.Trace;
            Log.Trace("x", "t");
            Check.True(w.ToString().Contains("TRACE [x] t"), "trace visible au niveau trace");
            Log.Reset();
        }

        private static void Logging_LevelWire()
        {
            Check.Eq("trace,debug,info,warn,error", string.Join(",", LogLevelWire.Names), "valeurs IRIS");
            LogLevel level;
            Check.True(LogLevelWire.TryParse("warn", out level) && level == LogLevel.Warn, "warn");
            Check.True(!LogLevelWire.TryParse("warning", out level), "warning refusé (valeur IRIS = warn)");
            Check.True(!LogLevelWire.TryParse("INFO", out level), "sensible à la casse");
            Check.Eq("error", LogLevelWire.ToWire(LogLevel.Error), "ToWire");
        }

        private static void Logging_Redaction()
        {
            string r = Redaction.Redact("sk-ant-secret-123");
            Check.True(r.StartsWith("[REDACTED:") && r.EndsWith("]") && r.Length == "[REDACTED:".Length + 8 + 1, "format [REDACTED:8hex]");
            Check.Eq(r, Redaction.Redact(Encoding.UTF8.GetBytes("sk-ant-secret-123")), "même empreinte pour string et bytes UTF-8");
            Check.True(r != Redaction.Redact("sk-ant-secret-124"), "empreintes distinctes");
            Check.True(!r.Contains("sk-ant"), "la valeur n'apparaît pas");
            Check.Eq("[REDACTED:e3b0c442]", Redaction.Redact(new byte[0]), "SHA-256 de vide = e3b0c442…");
        }
    }
}
