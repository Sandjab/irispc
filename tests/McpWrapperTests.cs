using System;
using System.IO;
using System.Text;
using System.Threading;
using IrisKit;

namespace Iris.Tests
{
    public static partial class TestMain
    {
        // ---- McpWrapper et McpFileWatcher (spec phase 5 §6) -----------------------------------

        private const string McpSample = "{\n  \"mcpServers\": {\n    \"gh\": {\n      \"command\": \"npx\"\n    }\n  }\n}\n";

        private static McpWrapOptions WrapOptions(string path, WrappedPathsRegistry registry)
        {
            McpWrapOptions o = new McpWrapOptions();
            o.Path = path;
            o.BrokerListen = McpBroker;
            o.CaPemPath = McpCa;
            o.Registry = registry;
            return o;
        }

        private static void McpWrapper_WrapAndUnwrap()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, ".mcp.json");
                File.WriteAllText(path, McpSample, new UTF8Encoding(false));
                byte[] original = File.ReadAllBytes(path);
                WrappedPathsRegistry reg = WrappedPathsRegistry.ForDataDir(Path.Combine(dir, "data"));
                McpWrapResult r = McpWrapper.Wrap(WrapOptions(path, reg));
                Check.True(r.Outcome == McpWrapOutcome.Patched && r.Patch.Summary.Patched == 1, "patché");
                Check.True(McpWrapper.SameBytes(original, File.ReadAllBytes(path + ".iris.bak")), "backup = octets d'origine");
                Check.True(File.ReadAllText(path).Contains("\"HTTPS_PROXY\": \"http://" + McpBroker + "\""), "variables écrites");
                Check.True(McpWrapper.SameBytes(McpWrapper.Sha256(File.ReadAllBytes(path)), r.ContentHash), "empreinte du contenu écrit");
                Check.Eq(path, string.Join("|", reg.List()), "chemin enregistré");
                byte[] patched = File.ReadAllBytes(path);
                r = McpWrapper.Wrap(WrapOptions(path, reg));
                Check.True(r.Outcome == McpWrapOutcome.AlreadyCompliant && McpWrapper.SameBytes(patched, File.ReadAllBytes(path)), "second wrap : déjà conforme, aucune écriture");
                Check.True(McpWrapper.Unwrap(path, reg) == null, "unwrap sans avertissement");
                Check.True(McpWrapper.SameBytes(original, File.ReadAllBytes(path)) && !File.Exists(path + ".iris.bak"), "restauré, backup consommé");
                Check.Eq(0, reg.List().Count, "retiré du registre");
                McpFileException none = Check.Throws<McpFileException>(delegate { McpWrapper.Unwrap(path, reg); }, "unwrap sans backup");
                Check.True(!none.IsIo && none.Message.Contains("aucun backup"), "code 1 : " + none.Message);
            }
            finally { TestDir.Delete(dir); }
        }

        private static void McpWrapper_BomCrlfPreserved()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, "claude_desktop_config.json");
                File.WriteAllText(path, McpSample.Replace("\n", "\r\n"), new UTF8Encoding(true));
                Check.True(McpWrapper.Wrap(WrapOptions(path, null)).Outcome == McpWrapOutcome.Patched, "patché");
                byte[] bytes = File.ReadAllBytes(path);
                Check.True(bytes[0] == 0xEF && bytes[1] == 0xBB && bytes[2] == 0xBF, "BOM conservé");
                string text = new UTF8Encoding(false).GetString(bytes, 3, bytes.Length - 3);
                Check.True(text.Contains("\r\n") && text.Replace("\r\n", "").IndexOf('\n') < 0, "fins de ligne CRLF partout");
                Check.True(McpWrapper.Wrap(WrapOptions(path, null)).Outcome == McpWrapOutcome.AlreadyCompliant, "CRLF + BOM : second wrap conforme");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void McpWrapper_CommentsDryRunAndRace()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, ".mcp.json");
                string commented = "{\n  // serveurs\n  \"mcpServers\": {\"gh\": {\"command\": \"npx\"}}\n}\n";
                File.WriteAllText(path, commented);
                McpWrapResult r = McpWrapper.Wrap(WrapOptions(path, null));
                Check.True(r.Outcome == McpWrapOutcome.CommentsFound && r.FirstComment.Line == 2 && r.FirstComment.Column == 3, "commentaires : refus, position L2:3");
                Check.True(File.ReadAllText(path) == commented && !File.Exists(path + ".iris.bak"), "fichier commenté intact, pas de backup");
                McpWrapOptions dry = WrapOptions(path, null);
                dry.DryRun = true;
                r = McpWrapper.Wrap(dry);
                Check.True(r.Outcome == McpWrapOutcome.DryRun && r.Patch.Additions.Count == 6, "--dry-run permis malgré les commentaires");
                Check.True(File.ReadAllText(path) == commented && !File.Exists(path + ".iris.bak"), "--dry-run : rien d'écrit");

                File.WriteAllText(path, McpSample);
                McpWrapOptions race = WrapOptions(path, null);
                race.BeforeReplace = delegate { File.WriteAllText(path, "{\"mcpServers\": {}}\n"); };
                r = McpWrapper.Wrap(race);
                Check.True(r.Outcome == McpWrapOutcome.ChangedDuringPatch, "modifié pendant le patch : abandon");
                Check.Eq("{\"mcpServers\": {}}\n", File.ReadAllText(path), "écriture concurrente préservée, jamais remplacée");
                Check.Eq(McpSample, File.ReadAllText(path + ".iris.bak"), "backup écrit avant le remplacement");

                File.WriteAllText(path, McpSample);
                McpWrapOptions skip = WrapOptions(path, null);
                skip.SkipIfHash = McpWrapper.Sha256(File.ReadAllBytes(path));
                Check.True(McpWrapper.Wrap(skip).Outcome == McpWrapOutcome.SkippedOwnWrite && File.ReadAllText(path) == McpSample, "contenu déjà vu : ignoré");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void McpWrapper_Errors()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, ".mcp.json");
                McpFileException ex = Check.Throws<McpFileException>(delegate { McpWrapper.Wrap(WrapOptions(path, null)); }, "fichier absent");
                Check.True(!ex.IsIo && ex.Message.Contains("introuvable"), ex.Message);
                File.WriteAllText(path, "{ cassé");
                ex = Check.Throws<McpFileException>(delegate { McpWrapper.Wrap(WrapOptions(path, null)); }, "JSON invalide");
                Check.True(!ex.IsIo && ex.Message.Contains("JSON invalide"), ex.Message);
                File.WriteAllBytes(path, new byte[] { 0x7B, 0xC3, 0x28, 0x7D });
                ex = Check.Throws<McpFileException>(delegate { McpWrapper.Wrap(WrapOptions(path, null)); }, "pas UTF-8");
                Check.True(!ex.IsIo && ex.Message.Contains("UTF-8"), ex.Message);
                File.WriteAllText(path, McpSample);
                File.WriteAllText(path + ".iris.bak", "{ cassé");
                ex = Check.Throws<McpFileException>(delegate { McpWrapper.Unwrap(path, null); }, "backup invalide");
                Check.True(!ex.IsIo && File.ReadAllText(path) == McpSample, "backup invalide : rien n'est touché");
            }
            finally { TestDir.Delete(dir); }
        }

        private static void McpFileWatcher_Debounces()
        {
            string dir = TestDir.Create();
            try
            {
                string path = Path.Combine(dir, ".mcp.json");
                File.WriteAllText(path, "{}");
                using (McpFileWatcher w = new McpFileWatcher(path, TimeSpan.FromMilliseconds(300)))
                {
                    for (int i = 0; i < 5; i++) File.WriteAllText(path, "{\"n\": " + i + "}");
                    CancellationTokenSource limit = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    w.WaitForChange(limit.Token);
                    Check.True(!limit.IsCancellationRequested, "changement signalé après le debounce");
                    CancellationTokenSource quiet = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
                    Check.Throws<OperationCanceledException>(delegate { w.WaitForChange(quiet.Token); }, "rafale regroupée : un seul signal, puis attente annulable");
                    File.WriteAllText(Path.Combine(dir, "autre.json"), "{}");
                    CancellationTokenSource other = new CancellationTokenSource(TimeSpan.FromMilliseconds(800));
                    Check.Throws<OperationCanceledException>(delegate { w.WaitForChange(other.Token); }, "un autre fichier du dossier n'est pas signalé");
                }
            }
            finally { TestDir.Delete(dir); }
        }
    }
}
