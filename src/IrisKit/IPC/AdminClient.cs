using System;
using System.Collections;
using System.IO;
using System.IO.Pipes;
using System.Reflection;
using System.Threading;

namespace IrisKit
{
    /// <summary>Le serveur du pipe n'est pas l'exécutable attendu : rien n'est envoyé (spec phase 3 §4, invariant 4).</summary>
    public sealed class AdminServerIdentityException : Exception
    {
        public string Expected { get; private set; }
        public string Actual { get; private set; }

        public AdminServerIdentityException(string expected, string actual)
            : base("le serveur du pipe n'est pas " + expected + " (exécutable : " + actual + ") : connexion refusée, rien n'a été envoyé")
        {
            Expected = expected;
            Actual = actual;
        }
    }

    /// <summary>
    /// Client du pipe admin (tests, CLI, app) : connexion, vérification de l'identité du serveur avant toute requête,
    /// appels JSON-RPC synchrones, une requête à la fois. Les trames envoyées sont effacées après écriture.
    /// </summary>
    public sealed class AdminClient : IDisposable
    {
        private readonly NamedPipeClientStream pipe;
        private readonly object gate = new object();
        private long nextId;

        private AdminClient(NamedPipeClientStream pipe) { this.pipe = pipe; }

        /// <summary>irisd.exe du dossier de l'exécutable appelant (dossier portable).</summary>
        public static string DefaultServerPath()
        {
            Assembly entry = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();
            return Path.Combine(Path.GetDirectoryName(entry.Location), "irisd.exe");
        }

        public static AdminClient Connect(string pipeName, string expectedServerPath, TimeSpan timeout)
        {
            NamedPipeClientStream p = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            try
            {
                p.Connect((int)timeout.TotalMilliseconds);
                string actual = PipeNative.ServerImagePath(p);
                // Identité de fichier, pas de chemin : subst, jonction ou nom 8.3 ne provoquent pas de faux refus (spec phase 5 §8).
                if (!FileIdentity.Same(actual, expectedServerPath))
                    throw new AdminServerIdentityException(expectedServerPath, actual);
                return new AdminClient(p);
            }
            catch
            {
                p.Dispose();
                throw;
            }
        }

        /// <summary>Appel JSON-RPC : rend `result` (dictionnaire, liste ou scalaire) ou lève RpcException ; IOException si le daemon ferme.</summary>
        public object Call(string method, IDictionary parameters)
        {
            lock (gate)
            {
                long id = ++nextId;
                byte[] request = JsonRpc.Request(id, method, parameters);
                try { FrameCodec.WriteAsync(pipe, request, CancellationToken.None).GetAwaiter().GetResult(); }
                finally { Array.Clear(request, 0, request.Length); }
                byte[] response = FrameCodec.ReadAsync(pipe, FrameCodec.MaxResponseBytes, CancellationToken.None).GetAwaiter().GetResult();
                if (response == null) throw new IOException("le daemon a fermé le pipe sans répondre");
                return JsonRpc.ParseResponse(response, id);
            }
        }

        public void Dispose() { pipe.Dispose(); }
    }
}
