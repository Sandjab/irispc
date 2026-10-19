using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using IrisKit;

namespace IrisCli
{
    /// <summary>Daemon injoignable (pipe absent, délai dépassé, accès refusé, connexion perdue) : code 2.</summary>
    public sealed class DaemonUnreachableException : Exception
    {
        public DaemonUnreachableException(string message) : base(message) { }

        /// <summary>Message canonique : comment lancer irisd, puis le pipe visé (spec phase 5 §3).</summary>
        public static DaemonUnreachableException For(string pipeName, CliContext ctx, string detail)
        {
            string message = "irisd ne tourne pas. Lancez : \"" + ctx.ExpectedServerPath + "\" --foreground"
                + System.Environment.NewLine + "  pipe : \\\\.\\pipe\\" + pipeName;
            if (detail != null) message += System.Environment.NewLine + "  détail : " + detail;
            return new DaemonUnreachableException(message);
        }
    }

    public static class Paths
    {
        /// <summary>`~` ou `~\…` en tête → profil utilisateur, puis chemin absolu (ArgumentException / NotSupportedException si invalide).</summary>
        public static string ExpandHome(string path, string userProfile)
        {
            if (path == "~") path = userProfile;
            else if (path.StartsWith("~\\", StringComparison.Ordinal) || path.StartsWith("~/", StringComparison.Ordinal))
                path = Path.Combine(userProfile, path.Substring(2));
            return Path.GetFullPath(path);
        }
    }

    public static class PipeNames
    {
        public const string Default = "iris-admin";

        /// <summary>--pipe-name > --config-path > data\config.json voisin de iris.exe > iris-admin (spec phase 5 §3).</summary>
        public static string Resolve(string pipeOption, string configPathOption, string dataDirectory, string userProfile)
        {
            if (pipeOption != null) return pipeOption;
            if (configPathOption != null)
            {
                string path = configPathOption;
                try
                {
                    path = Paths.ExpandHome(configPathOption, userProfile);
                    return FromConfig(path);
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException || ex is JsonException || ex is ArgumentException || ex is NotSupportedException)
                        throw new CliException(CliExit.Logic, "config illisible : " + path + " (" + ex.Message + ")");
                    throw;
                }
            }
            string local = Path.Combine(dataDirectory, "config.json");
            try
            {
                if (File.Exists(local)) return FromConfig(local);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch (JsonException) { }
            return Default;
        }

        private static string FromConfig(string path)
        {
            JsonObject o = Json.ParseObject(File.ReadAllText(path, Encoding.UTF8));
            string name = o.Object("broker").String("admin_pipe");
            if (name.Trim().Length == 0) throw new JsonException("broker.admin_pipe vide");
            return name;
        }
    }

    /// <summary>Connexion au pipe admin pour une commande : identité du serveur vérifiée, erreurs de transport → code 2.</summary>
    public sealed class CliConnection : IDisposable
    {
        private readonly AdminClient client;

        public string PipeName { get; private set; }

        private CliConnection(AdminClient client, string pipeName)
        {
            this.client = client;
            PipeName = pipeName;
        }

        public static string ResolvePipe(ParsedArgs args, CliContext ctx)
        {
            return PipeNames.Resolve(args.Option("--pipe-name"), args.Option("--config-path"), ctx.DataDirectory, ctx.UserProfile);
        }

        public static CliConnection Open(ParsedArgs args, CliContext ctx) { return Open(ResolvePipe(args, ctx), ctx); }

        /// <summary>AdminServerIdentityException traverse (code 2, message dédié) ; pipe absent, délai, accès refusé → DaemonUnreachableException.</summary>
        public static CliConnection Open(string pipeName, CliContext ctx)
        {
            try { return new CliConnection(AdminClient.Connect(pipeName, ctx.ExpectedServerPath, ctx.ConnectTimeout), pipeName); }
            catch (TimeoutException) { throw DaemonUnreachableException.For(pipeName, ctx, null); }
            catch (IOException ex) { throw DaemonUnreachableException.For(pipeName, ctx, ex.Message); }
            catch (UnauthorizedAccessException ex) { throw DaemonUnreachableException.For(pipeName, ctx, ex.Message); }
        }

        /// <summary>Résultat brut (dictionnaire, liste ou scalaire) ; pipe fermé en cours d'appel → DaemonUnreachableException.</summary>
        public object Call(string method, IDictionary parameters)
        {
            try { return client.Call(method, parameters); }
            catch (IOException ex) { throw new DaemonUnreachableException("connexion au daemon perdue (\\\\.\\pipe\\" + PipeName + ") : " + ex.Message); }
        }

        public static JsonObject AsObject(object raw)
        {
            IDictionary<string, object> d = raw as IDictionary<string, object>;
            if (d == null) throw new CliException(CliExit.Logic, "réponse inattendue du daemon (objet attendu)");
            return new JsonObject(d);
        }

        public static IList<object> AsList(object raw)
        {
            IList<object> list = raw as IList<object>;
            if (list == null) throw new CliException(CliExit.Logic, "réponse inattendue du daemon (tableau attendu)");
            return list;
        }

        public void Dispose() { client.Dispose(); }
    }
}
