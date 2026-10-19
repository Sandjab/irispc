using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace IrisKit
{
    public enum McpWrapOutcome { Patched, AlreadyCompliant, DryRun, CommentsFound, ChangedDuringPatch, SkippedOwnWrite }

    /// <summary>Fichier MCP inutilisable : `IsIo` = échec d'écriture (code 3), sinon absent, illisible ou invalide (code 1).</summary>
    public sealed class McpFileException : Exception
    {
        public bool IsIo { get; private set; }

        public McpFileException(bool isIo, string message) : base(message) { IsIo = isIo; }
    }

    public sealed class McpWrapOptions
    {
        /// <summary>Chemin absolu du fichier MCP.</summary>
        public string Path;
        public string BrokerListen;
        public string CaPemPath;
        public bool DryRun;
        /// <summary>null : pas d'enregistrement.</summary>
        public WrappedPathsRegistry Registry;
        /// <summary>--watch : contenu déjà traité (écriture d'iris) → SkippedOwnWrite sans rien faire.</summary>
        public byte[] SkipIfHash;
        /// <summary>Tests : simule une écriture concurrente juste avant le remplacement.</summary>
        public Action BeforeReplace;
    }

    public sealed class McpWrapResult
    {
        public McpWrapOutcome Outcome;
        public McpPatchResult Patch;
        public CommentPosition FirstComment;
        public string BackupPath;
        /// <summary>SHA-256 du contenu laissé sur disque (écrit, ou lu s'il était déjà conforme).</summary>
        public byte[] ContentHash;
        public string RegistryWarning;
    }

    /// <summary>
    /// Un cycle de `iris mcp wrap` (spec phase 5 §6.2) : lecture, empreinte, parse JSONC, refus des commentaires, patch, backup des
    /// octets d'origine, revalidation stricte, contrôle d'écriture concurrente, remplacement atomique, registre. BOM et CRLF conservés.
    /// </summary>
    public static class McpWrapper
    {
        private static readonly UTF8Encoding StrictUtf8 = new UTF8Encoding(false, true);
        private static readonly byte[] Bom = { 0xEF, 0xBB, 0xBF };

        public static string BackupPathFor(string path) { return path + ".iris.bak"; }

        public static McpWrapResult Wrap(McpWrapOptions o)
        {
            McpWrapResult r = new McpWrapResult();
            r.BackupPath = BackupPathFor(o.Path);
            byte[] original = ReadFile(o.Path);
            byte[] readHash = Sha256(original);
            r.ContentHash = readHash;
            if (o.SkipIfHash != null && SameBytes(readHash, o.SkipIfHash))
            {
                r.Outcome = McpWrapOutcome.SkippedOwnWrite;
                return r;
            }
            bool bom, crlf;
            OrderedJsonDocument doc = ParseFile(o.Path, original, out bom, out crlf);
            if (doc.Comments.Count > 0 && !o.DryRun)
            {
                r.Outcome = McpWrapOutcome.CommentsFound;
                r.FirstComment = doc.Comments[0];
                return r;
            }
            r.Patch = McpPatcher.Patch(doc.Root, o.BrokerListen, o.CaPemPath);
            string after = OrderedJsonWriter.Serialize(r.Patch.Root);
            if (after == OrderedJsonWriter.Serialize(doc.Root))
            {
                r.Outcome = McpWrapOutcome.AlreadyCompliant;
                return r;
            }
            if (o.DryRun)
            {
                r.Outcome = McpWrapOutcome.DryRun;
                return r;
            }
            try { File.WriteAllBytes(r.BackupPath, original); }
            catch (Exception ex)
            {
                if (IsIo(ex)) throw new McpFileException(true, "écriture du backup " + r.BackupPath + " impossible : " + ex.Message);
                throw;
            }
            try { OrderedJsonParser.Parse(after, false); }
            catch (OrderedJsonException ex) { throw new McpFileException(false, "le résultat du patch ne se relit pas en JSON strict (" + ex.Message + ") : rien n'a été écrit"); }
            byte[] output = Encode(crlf ? after.Replace("\n", "\r\n") : after, bom);
            if (o.BeforeReplace != null) o.BeforeReplace();
            if (!Unchanged(o.Path, readHash))
            {
                r.Outcome = McpWrapOutcome.ChangedDuringPatch;
                r.ContentHash = null;
                return r;
            }
            ReplaceAtomically(o.Path, output);
            r.ContentHash = Sha256(output);
            r.Outcome = McpWrapOutcome.Patched;
            if (o.Registry != null) r.RegistryWarning = Register(o.Registry, o.Path, true);
            return r;
        }

        /// <summary>Restaure `path` depuis `path.iris.bak` (le backup est consommé) ; rend un avertissement de registre ou null.</summary>
        public static string Unwrap(string path, WrappedPathsRegistry registry)
        {
            string backup = BackupPathFor(path);
            if (!File.Exists(backup)) throw new McpFileException(false, "aucun backup : " + backup);
            byte[] bytes = ReadFile(backup);
            bool bom, crlf;
            ParseFile(backup, bytes, out bom, out crlf); // invalide → McpFileException, rien n'est touché
            try
            {
                if (File.Exists(path)) File.Replace(backup, path, null);
                else File.Move(backup, path);
            }
            catch (Exception ex)
            {
                if (IsIo(ex)) throw new McpFileException(true, "restauration de " + path + " impossible : " + ex.Message);
                throw;
            }
            return registry == null ? null : Register(registry, path, false);
        }

        public static byte[] Sha256(byte[] data)
        {
            using (SHA256 sha = SHA256.Create()) return sha.ComputeHash(data);
        }

        public static bool SameBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != b[i]) return false;
            return true;
        }

        private static bool IsIo(Exception ex) { return ex is IOException || ex is UnauthorizedAccessException; }

        private static byte[] ReadFile(string path)
        {
            try { return File.ReadAllBytes(path); }
            catch (FileNotFoundException) { throw new McpFileException(false, "fichier introuvable : " + path); }
            catch (DirectoryNotFoundException) { throw new McpFileException(false, "fichier introuvable : " + path); }
            catch (Exception ex)
            {
                if (IsIo(ex)) throw new McpFileException(false, "lecture de " + path + " impossible : " + ex.Message);
                throw;
            }
        }

        private static OrderedJsonDocument ParseFile(string path, byte[] bytes, out bool bom, out bool crlf)
        {
            bom = bytes.Length >= 3 && bytes[0] == Bom[0] && bytes[1] == Bom[1] && bytes[2] == Bom[2];
            int skip = bom ? 3 : 0;
            string text;
            try { text = StrictUtf8.GetString(bytes, skip, bytes.Length - skip); }
            catch (DecoderFallbackException) { throw new McpFileException(false, path + " n'est pas encodé en UTF-8"); }
            crlf = text.Contains("\r\n");
            try { return OrderedJsonParser.Parse(text, true); }
            catch (OrderedJsonException ex) { throw new McpFileException(false, path + " : JSON invalide, " + ex.Message); }
        }

        private static byte[] Encode(string text, bool bom)
        {
            byte[] body = new UTF8Encoding(false).GetBytes(text);
            if (!bom) return body;
            byte[] all = new byte[body.Length + 3];
            Buffer.BlockCopy(Bom, 0, all, 0, 3);
            Buffer.BlockCopy(body, 0, all, 3, body.Length);
            return all;
        }

        /// <summary>Le fichier a-t-il toujours le contenu lu au début du cycle ? Disparu ou illisible = changé.</summary>
        private static bool Unchanged(string path, byte[] readHash)
        {
            try { return SameBytes(Sha256(File.ReadAllBytes(path)), readHash); }
            catch (Exception ex)
            {
                if (IsIo(ex)) return false;
                throw;
            }
        }

        private static void ReplaceAtomically(string path, byte[] bytes)
        {
            string tmp = path + ".iris.tmp";
            try
            {
                File.WriteAllBytes(tmp, bytes);
                if (File.Exists(path)) File.Replace(tmp, path, null);
                else File.Move(tmp, path);
            }
            catch (Exception ex)
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); }
                catch (IOException) { }
                if (IsIo(ex)) throw new McpFileException(true, "écriture de " + path + " impossible : " + ex.Message);
                throw;
            }
        }

        private static string Register(WrappedPathsRegistry registry, string path, bool add)
        {
            try
            {
                if (add) registry.Add(path);
                else registry.Remove(path);
                return null;
            }
            catch (WrappedPathsCorruptException ex) { return ex.Message; }
            catch (Exception ex)
            {
                if (IsIo(ex)) return "registre des fichiers enrobés non mis à jour : " + ex.Message;
                throw;
            }
        }
    }
}
